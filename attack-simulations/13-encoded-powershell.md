# Attack 13 — Encoded PowerShell Execution (T1059.001)

**MITRE ATT&CK:** [T1059.001 — Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

Running PowerShell with a Base64-`-EncodedCommand` payload is one of the most common
things real attackers and commodity malware do on Windows — it hides the actual command
from shoulder-level inspection and from naive string matching. The detection works on the
**command line itself**, captured by **Sysmon event 1 (process creation)**.

## Execution

```powershell
$enc=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("whoami; hostname; Get-Date"))
Start-Process powershell -ArgumentList "-NoProfile","-EncodedCommand",$enc -WindowStyle Hidden -Wait
```

The payload here is harmless (`whoami; hostname; Get-Date`) — the point is the *shape* of
the invocation (`-EncodedCommand` + a Base64 blob + a hidden window), which is what gives
the technique away no matter what the decoded command is.

## Result

**Sysmon event 1** for `powershell.exe` with the `-EncodedCommand` argument and the Base64
string on the command line.

## Detection

See `detections/13-encoded-powershell.md`.
