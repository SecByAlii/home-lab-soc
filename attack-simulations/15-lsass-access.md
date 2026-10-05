# Attack 15 — LSASS Credential-Dump Access (T1003.001)

**MITRE ATT&CK:** [T1003.001 — OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)

Credential theft from LSASS (the Windows process holding logged-on credentials) is one of
the most important things a SOC watches for. Tools like Mimikatz open a handle to
`lsass.exe` with memory-read rights and scrape secrets out of it. The detection doesn't
need the tool — it watches for the **handle** itself: **Sysmon event 10 (process access)**
to `lsass.exe` with a dump-grade access mask.

**No real credential-dumping tool was used.** The access was simulated by opening a handle
to the target with the same access mask a dumper requests (`0x1410` =
`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`), then closing it — no memory was read and
nothing was written to disk.

## What actually happened: the OS blocked it (and that's the finding)

```powershell
$lsass = (Get-Process lsass).Id
$h = OpenProcess(0x1410, $false, $lsass)   # returns 0, GetLastError = 5 (ACCESS_DENIED)
```

The handle request was **denied**. This Windows 11 build runs LSASS as a protected
process (`RunAsPPL = 2`, enabled by default), so even a SYSTEM-level caller can't open it
for memory read. The credential-dump technique is stopped at the OS layer — **no Sysmon
10 fires because the access never happens.** That is defense-in-depth working: a control
pre-empts the need for the detection.

## Two prerequisites this surfaced

1. **Sysmon ProcessAccess must be turned on.** The SwiftOnSecurity config ships it
   *disabled* (an empty `include` block) because it's noisy. Detecting LSASS access
   requires enabling and scoping it — see [`detections/sysmon-config.md`](../detections/sysmon-config.md).
2. **LSA protection masks the technique here.** With it on, the realistic attack can't
   produce the event, so the detection was validated a different way (below).

## Validating the detection logic

With ProcessAccess enabled, the detection SPL was proven against a **stand-in target**: a
throwaway process opened with the identical `0x1410` dump mask, which produced a clean
Sysmon 10 the detection fired on. The benign baseline on this host is `svchost.exe`
opening `lsass.exe` with `0x1000` (`PROCESS_QUERY_LIMITED_INFORMATION`) — exactly the
noise the detection's mask filter is designed to exclude.

## Detection

See `detections/15-lsass-access.md`.
