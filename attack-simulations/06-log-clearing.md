# Attack 6 — Clear Linux Logs (T1070.002)

**MITRE ATT&CK:** [T1070.002 — Indicator Removal: Clear Linux or Mac System Logs](https://attack.mitre.org/techniques/T1070/002/)

Follows Atomic Red Team's T1070.002 tests — truncate or delete the system logs so the
earlier activity (attacks 1–5) leaves no local trace. This is the anti-forensics step
that usually comes last, and it's the reason a SOC ships logs off the host instead of
trusting what's on disk.

## Instrumentation first

`auditd` has no default rules, so nothing watches the log files. Detection 6 needs
`60-logclear.rules` loaded — see `setup/03-auditd-instrumentation.md`. The rule set puts
`-w … -p wa` watches on `auth.log`, `syslog`, and `audit/audit.log`, plus a broad
`-F dir=/var/log` syscall rule for anything the named watches miss.

## Execution

```
sudo truncate -s 0 /var/log/auth.log      # wipe the auth/sudo/SSH trail
sudo rm -f /var/log/syslog                # delete the general log outright
sudo bash -c ': > /var/log/audit/audit.log'   # blank the audit log itself
```

Three different verbs on purpose — a size-zero truncate that keeps the inode, an
`unlink` that removes the file, and a shell redirect that opens with `O_TRUNC`. Each
produces a different syscall, and the detection has to catch all three.

`rsyslog` is restarted afterward so `syslog` and `auth.log` start filling again — an
attacker would want logging back on so the box looks normal.

## Result

Against the loaded rules, with `AUID` pinned to `analyst` on every one:

| Target | `comm` | syscall | Record detail |
|---|---|---|---|
| `/var/log/auth.log` | `truncate` | `openat` | `nametype=NORMAL` |
| `/var/log/syslog` | `rm` | `unlinkat` | `nametype=DELETE` |
| `/var/log/audit/audit.log` | `bash` | `openat` (`O_TRUNC`) | `nametype=NORMAL` |

## Detection

See `detections/06-log-clearing.md`.

## Honest gap — and the real finding

- **Truncating the audit log destroyed evidence of the other two clears.** In the first
  run all three commands ran back to back; the `: > audit.log` zeroed the file while
  auditd's async buffer still held the `auth.log`-truncate and `syslog`-`rm` records, so
  those never made it to disk and never reached Splunk. The auth.log and syslog events
  in the detection are from a second run that left `audit.log` alone. This isn't a lab
  artifact to apologise for — it's the technique working. On-disk logs are not evidence
  you can rely on; the forwarder shipping each line to a separate indexer in real time
  is what makes the wipe too late.
- **No "log went silent" detection here.** The obvious complement — alert when a log
  source stops producing events — needs a normal baseline to measure against, and this
  lab has no steady background auth/syslog traffic to baseline. Noted as the right
  second signal on a real deployment, not built.
- **The forwarder's own truncation notice** (`Will begin reading at offset=0 …
  audit.log`) lands in the UF's `splunkd.log` / `index=_internal`, which isn't forwarded
  from this box. On a full deployment that line, seen on the indexer, is itself a
  high-value detection.
