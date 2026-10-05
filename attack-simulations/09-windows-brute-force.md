# Attack 9 — Windows Password Brute Force (T1110.001)

**MITRE ATT&CK:** [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

The Windows counterpart of [attack 1](01-ssh-brute-force.md). Same technique, different
log: instead of `sshd` failures in `auth.log`, Windows writes a **Security event 4625**
for every failed logon. This is the first technique replayed against the new
[Windows victim host](../setup/04-windows-victim.md), to prove the detection logic
carries across platforms while the evidence source changes completely.

## Execution

Eight failed logon attempts for a non-existent user, driven through the Windows
`LogonUser` API (logon type 2, interactive) so each one produces a real 4625:

```powershell
Add-Type -Namespace W -Name A -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("advapi32.dll",SetLastError=true)]
public static extern bool LogonUser(string u,string d,string p,int lt,int lp,out System.IntPtr t);
"@
$tok=[IntPtr]::Zero
1..8 | % { [W.A]::LogonUser("jsmith",$env:COMPUTERNAME,"WrongPass$_!",2,0,[ref]$tok) | Out-Null }
```

`jsmith` doesn't exist on the box — a password-guessing run against a likely username is
exactly the behaviour this detects.

## Result

Eight `EventCode=4625` events in the Security log, all for `jsmith`, inside one minute.
Failed-logon auditing is on by default in Windows, so no audit policy change was needed
for this one (unlike attacks 10 and 11).

## Detection

See `detections/09-windows-brute-force.md`.
