# Attack 10 — Create Local Account, Windows (T1136.001)

**MITRE ATT&CK:** [T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)

The Windows counterpart of [attack 2](02-create-local-account.md). Same persistence move
— plant a second account that blends in — logged on Windows as **Security event 4720**.

## Setup: audit policy

Unlike failed logons, account-management auditing is **not guaranteed on**. It was
enabled first:

```
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
```

That this is a required prerequisite is itself worth knowing: on a box where it was never
turned on, account creation leaves no 4720 at all.

## Execution

```
net user svc_helpdesk <password> /add
```

`svc_helpdesk` is named to look like routine IT infrastructure, the same blend-in logic
as the Linux `svc_backup`.

## Result

One `EventCode=4720` for `svc_helpdesk`.

**A real-world note from this run:** the first attempt used a weaker password and
`net user` failed *silently* (non-zero exit, piped to null), so no account and no 4720 —
a good reminder to check command results, not assume success. The retry with a
complexity-compliant password succeeded and logged cleanly.

## Detection

See `detections/10-windows-new-account.md`.
