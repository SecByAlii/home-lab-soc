# Attack 11 — Scheduled Task Persistence (T1053.005)

**MITRE ATT&CK:** [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

The Windows sibling of the Linux [cron persistence](05-cron-persistence.md) attack. A
scheduled task is the classic Windows persistence mechanism: register a task that runs on
a schedule (or at logon) so the attacker's payload keeps coming back.

## Setup: audit policy

Scheduled-task creation (Security event **4698**) is audited under a subcategory that is
off by default:

```
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

## Execution

```
schtasks /create /tn "UpdateHealthCheck" /tr "cmd.exe /c echo hb > C:\Windows\Temp\hb.txt" /sc minute /mo 10 /ru SYSTEM /f
```

Named `UpdateHealthCheck` and set to run as `SYSTEM` every 10 minutes — an innocuous,
maintenance-sounding name doing something an attacker would actually want: recurring
execution at the highest privilege.

## Result

- **Security event 4698** — "A scheduled task was created", Task Name `\UpdateHealthCheck`.
- **Sysmon event 1** — the `schtasks.exe` process that created it, with its full command
  line. Two independent witnesses to the same action, which detection 11 can corroborate.

## Detection

See `detections/11-scheduled-task.md`.
