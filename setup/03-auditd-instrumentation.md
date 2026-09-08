# 03 — auditd Instrumentation

The forwarder ships `/var/log/audit/audit.log` from the start (see setup 02), but a
default Ubuntu `auditd` runs with **no rules loaded** — so out of the box that log only
carries login/sudo/PAM records. File-write and command-execution visibility has to be
turned on with rules, per technique, as the detection library grows.

This file tracks what's been added and why. Each rule set lives in `detections/audit-rules/`.

## How to load a rule set on `victim01`

```
scp detections/audit-rules/50-cron.rules analyst@192.168.64.2:/tmp/
ssh victim01 'sudo cp /tmp/50-cron.rules /etc/audit/rules.d/ && sudo augenrules --load'
ssh victim01 'sudo auditctl -l'   # confirm the rules are active
```

`augenrules --load` merges every file in `/etc/audit/rules.d/` and applies it without a
reboot. `auditctl -s` shows `enabled 1` and the current backlog.

## Rule sets

| File | Key(s) | For | Added |
|---|---|---|---|
| `50-cron.rules` | `cron_persist`, `cron_exec` | Detection 5 — T1053.003 Cron | 2026-09-08 |

## Notes / gotchas

- **`augenrules` warns "Old style watch rules are slower"** for every `-w` line. That's
  advisory — path watches (`-w`) work fine; the note is nudging toward explicit syscall
  rules (`-a always,exit -F path=...`), which matter only on a busy host. Left as `-w`
  here for readability.
- **Loading a rule set is itself audited.** Each `-w` produces a `type=CONFIG_CHANGE` /
  `op=add_rule` event carrying the same key as the rule. Detections filter these out
  (`type=SYSCALL` only, or `NOT op=add_rule`) so instrumenting the box doesn't read as
  an attack.
- **auditd records index as one Splunk event each**, not merged — a `SYSCALL` record and
  its sibling `PATH` record are separate events sharing an `audit()` timestamp+ID.
  Detection logic that needs both the syscall and the filename either searches each
  record type separately or stitches them on that ID.
- Rules are **not** set immutable (`-e 2`) on this lab box, so `augenrules --load` can
  reload freely. A hardened host would lock them and require a reboot to change.
