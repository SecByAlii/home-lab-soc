# Attack 2 — Create Local Account (T1136.001)

**MITRE ATT&CK:** [T1136.001 — Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/)

Matches Atomic Red Team's documented test for this technique: use `useradd` to create a
new local account. This is a common persistence move — an attacker with root access
plants a second account so they can get back in even if the account they used to break
in gets noticed and locked.

## Execution

```
sudo useradd -m -s /bin/bash svc_backup
```

`svc_backup` is deliberately named to blend in with legitimate service accounts —
that's the actual attacker behavior this detection has to catch: not a name that
announces itself, but one that just looks like normal infrastructure.

## Result

`useradd` logs directly to `/var/log/auth.log` (no auditd dependency for this one):

```
useradd[15092]: new group: name=svc_backup, GID=1002
useradd[15092]: new user: name=svc_backup, UID=1002, GID=1002, home=/home/svc_backup, shell=/bin/bash, from=none
```

## Detection

See `detections/02-new-local-account.md`.
