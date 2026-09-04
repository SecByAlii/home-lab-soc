# Detection 1 — SSH Brute Force

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
**Attack simulated:** `attack-simulations/01-ssh-brute-force.md`
**Log source:** `linux_secure` (`/var/log/auth.log` via the Splunk forwarder)

## The search

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "Failed password for (invalid user )?(?<attempted_user>\S+) from (?<src_ip>\S+)"
| bin _time span=5m
| stats count as failed_attempts, values(attempted_user) as attempted_users, earliest(_time) as first_attempt, latest(_time) as last_attempt by src_ip, _time
| where failed_attempts >= 5
| convert ctime(first_attempt) ctime(last_attempt)
```

## What it catches

Five or more failed SSH password attempts from the same source IP inside a 5-minute
window. Bucketing by `_time` (5-minute bins) instead of a single running count means a
slow, spread-out brute force doesn't get averaged away, and a source hammering the box
in a tight burst — the actual `hydra` behavior — trips it immediately.

Against the simulated attack: 7 failed attempts from `127.0.0.1` inside about 30
seconds, all in one 5-minute bin → `failed_attempts=7`, over the threshold of 5.

## Follow-up: did it succeed?

A brute force that lands is worse than one that doesn't. Second search, run against any
source IP the first search flags:

```spl
index=main sourcetype=linux_secure src_ip="<flagged IP>"
| rex field=_raw "Accepted password for (?<user>\S+) from"
| where isnotnull(user)
```

Any hit here after a flagged brute-force window means a login actually succeeded —
that's the difference between "someone's knocking" and "someone's in."

## False positives to expect

- **A real user who forgot their password.** 5+ fat-fingered attempts in 5 minutes from
  a legitimate source IP is rare but not impossible. Cross-check `attempted_users` — a
  brute force tries many usernames or hammers one from an unfamiliar IP; a real user
  fat-fingering their own password stays on their own account.
- **Automated health checks or monitoring tools** that retry SSH connections on
  misconfiguration can produce a similar burst. Worth an allowlist of known
  monitoring-source IPs in a real deployment; not an issue in this single-host lab.

## Threshold notes

`failed_attempts >= 5` in 5 minutes is a starting point, not a tuned value — a real
deployment would baseline against actual traffic first. Set low here deliberately,
since the lab has no legitimate SSH traffic to generate noise against.
