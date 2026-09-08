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
| `60-logclear.rules` | `log_tamper` | Detection 6 — T1070.002 Clear Logs | 2026-09-08 |
| `70-discovery.rules` | `proc_exec` | Detection 7 — T1018 Remote Discovery (all interactive execve) | 2026-09-08 |

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
  its sibling `PATH` / `EXECVE` record are separate events sharing an `audit()`
  timestamp+ID. Detection logic that needs fields from more than one record type either
  searches each separately or stitches them on that ID (`rex "audit\((?<aevent>[0-9.]+:[0-9]+)\)"`
  then `stats … by aevent`).
- **`EXECVE` carries the argv as `a0`, `a1`, `a2`… — one field per token, no combined
  command string, and no `auid`/`comm`** (those are on the sibling `SYSCALL`). Rebuild
  the command with `mvjoin(mvappend(a0,a1,…)," ")`, and guard it with
  `if(type=="EXECVE", …)` so the `SYSCALL` record's hex `a0`–`a3` registers don't get
  mixed in.
- Rules are **not** set immutable (`-e 2`) on this lab box, so `augenrules --load` can
  reload freely. A hardened host would lock them and require a reboot to change.
- **Truncating `/var/log/audit/audit.log` while auditd runs doesn't stop auditd** — it
  holds the file descriptor and keeps writing at its stored offset, so the file goes
  sparse and then refills. But any records still in auditd's async write buffer at the
  moment of truncation are lost, and the Splunk forwarder re-reads the file from offset
  0 on the size change. Detection 6 hit this directly: the first attack run also
  truncated audit.log and that wiped the on-disk record of the same run's other two log
  clears. The lesson the repo keeps: the audit log has to be shipped off-box in real
  time, because whatever is still on disk can be erased.
