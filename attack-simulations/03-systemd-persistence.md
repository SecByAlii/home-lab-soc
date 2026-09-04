# Attack 3 — Persistence via systemd Service (T1543.002)

**MITRE ATT&CK:** [T1543.002 — Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/)

Matches Atomic Red Team's documented test for this technique: create a new systemd
unit and enable it, so it runs automatically on every boot without further attacker
interaction. This is a step up from the local-account technique (attack 2) — instead
of a second login path, this plants code that runs itself.

## Execution

```
sudo tee /etc/systemd/system/sysupdate-check.service > /dev/null <<'UNIT'
[Unit]
Description=System Update Checker

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'echo persistence-check-ok'

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable sysupdate-check.service
sudo systemctl start sysupdate-check.service
```

The unit name and description are deliberately boring — `sysupdate-check.service`
reads like routine infrastructure, which is the actual attacker move: persistence that
doesn't announce itself in a service list. `WantedBy=multi-user.target` is what makes
it survive a reboot.

## Result

Logged to `/var/log/syslog` the moment it started:

```
systemd[1]: Starting sysupdate-check.service - System Update Checker...
systemd[1]: Finished sysupdate-check.service - System Update Checker.
```

## Detection

See `detections/03-new-systemd-service.md`.

## Honest gap

`systemctl enable` writing the actual unit file to `/etc/systemd/system/` doesn't
generate a log line on its own — only starting the service does. A more complete
detection would add an `auditd` watch rule on `/etc/systemd/system/` to catch the file
write itself, which would flag the persistence mechanism even if it were installed
but never started. Not implemented yet — noted here rather than glossed over.
