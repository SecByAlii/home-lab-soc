# Attack 12 — Registry Run Key Persistence (T1547.001)

**MITRE ATT&CK:** [T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/)

Another Windows persistence staple: drop a value under a `Run` key so a program launches
automatically at logon. No Security-log equivalent exists for this by default — it's
caught by **Sysmon event 13 (registry value set)**, which is why the
[Sysmon tuning](../detections/sysmon-config.md) matters.

## Execution

```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SecurityUpdater /t REG_SZ /d "C:\Windows\Temp\su.exe" /f
```

The value name `SecurityUpdater` is the same hide-in-plain-sight trick as the other
attacks.

## Result

**Sysmon event 13**, `Image=reg.exe`,
`TargetObject=HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdater`,
`Details=C:\Windows\Temp\su.exe`.

**Note on the hive:** the simulation was driven as `SYSTEM`, so `HKCU` resolved to
`HKU\.DEFAULT` (the SYSTEM profile) rather than an interactive user's hive. The detection
matches the `...\CurrentVersion\Run\` path across **all** hives (`HKU\*`, `HKLM`), so it
catches the event regardless — which is the right design, since an attacker may write the
Run key under whatever account they land on.

## Detection

See `detections/12-run-key-persistence.md`.
