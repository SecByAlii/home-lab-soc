# 4. Windows victim host (win01)

How the second victim was built: a Windows 11 host feeding the same Splunk indexer as the
Linux VM, so the lab covers both of the platforms a SOC analyst actually sees. Everything
here was built to be reproducible — the install is unattended and the forwarder config is
checked in.

## The VM

- **UTM (QEMU), aarch64 `virt`**, 8 GB RAM, 4 cores, 64 GB NVMe, on the same Apple Silicon
  Mac and the same shared network as the Linux victim (`victim01`).
- **Windows 11 Pro, ARM64** — the only Windows edition that virtualizes natively on Apple
  Silicon. Installed from Microsoft's official multi-edition Arm64 ISO.
- **Unattended install.** An `autounattend.xml` answers every setup prompt — disk
  partitioning, edition, a local `analyst` admin account, skip the Microsoft-account screens
  — so the build is hands-off and repeatable rather than a pile of manual clicks. The UTM
  guest-tools drivers (VirtIO storage/network) are slipstreamed in the same answer file.

### Post-install hardening note

The unattended install leaves the account password in two places that a real build must
clean up: `C:\Windows\Panther\unattend-original.xml` (plaintext) and the `DefaultPassword`
LSA secret from the one-time auto-logon. Both were removed and auto-logon disabled after
first boot.

## Logging pipeline

A **Splunk Universal Forwarder** on win01 ships to the same indexer as the Linux side
(`<indexer>:9997`, index `main`, host `win01`). Three sources:

| Source | Why |
|--------|-----|
| `WinEventLog:Security` | logons (4625), account creation (4720), scheduled tasks (4698), log clear (1102) |
| `WinEventLog:System` | service and system-level events |
| `WinEventLog:Microsoft-Windows-Sysmon/Operational` | process creation (1), registry (13), process access (10) |

`inputs.conf` sets **`renderXml = false`** on all three. On a bare indexer with no Splunk
Add-on for Windows, classic key-value rendering is what makes `EventCode`, `CommandLine`,
`TargetObject`, and `GrantedAccess` auto-extract — keeping the SPL consistent across every
Windows detection.

## Audit policy

Two subcategories are off by default and were enabled so the Security-log detections have
events to find:

```
auditpol /set /subcategory:"User Account Management"   /success:enable /failure:enable   # 4720 (det 10)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable   # 4698 (det 11)
```

Failed-logon auditing (4625) and the log-cleared event (1102) are on by default.

## Sysmon

Installed from the ARM64 build with the SwiftOnSecurity baseline config, plus one tuning
change to enable ProcessAccess for the LSASS detection — see
[`../detections/sysmon-config.md`](../detections/sysmon-config.md).

## Two things worth knowing (banked so the next person skips the discovery tax)

- **The Splunk forwarder has no Windows-Arm64 build.** The x64 forwarder runs on Windows 11
  Arm under the OS's x64 emulation. Splunk documents this as best-effort and says Windows
  Event Log collection is "unsupported or not yet validated" there — but tested here, it
  works: Security, System, and Sysmon all forward. (Honest caveat: it's not a Splunk-certified
  configuration.)
- **The forwarder runs as a virtual service account, not SYSTEM.** Out of the box it can read
  the Security log but **not** the Sysmon channel, so Sysmon events silently failed to
  forward (`errorCode=5`) until the `NT SERVICE\SplunkForwarder` account was added to the
  local **Event Log Readers** group. Least-privilege fix, not "run it as SYSTEM."
