# Planned attack techniques

Target list for the first pass — Atomic Red Team tests that (a) run cleanly on Linux,
(b) generate log evidence in the sources we're actually collecting (auth.log, auditd),
and (c) map to techniques a real SOC analyst gets tested on.

Each gets its own detection in `detections/` once it's been run and caught.

| # | MITRE ATT&CK ID | Technique | Atomic Red Team test | Log source |
|---|---|---|---|---|
| 1 | T1110.001 | Brute Force: Password Guessing | Atomic T1110.001-1 (SSH brute force) | auth.log |
| 2 | T1078 | Valid Accounts | Manual: successful login after failed attempts | auth.log |
| 3 | T1136.001 | Create Account: Local Account | Atomic T1136.001 (useradd) | auditd |
| 4 | T1543.002 | Create/Modify System Process: systemd | Atomic T1543.002 | auditd |
| 5 | T1053.003 | Scheduled Task/Job: Cron | Atomic T1053.003 | auditd |
| 6 | T1070.002 | Indicator Removal: Clear Linux/Mac Logs | Atomic T1070.002 | auth.log + auditd |
| 7 | T1018 | Remote System Discovery | Atomic T1018 (nmap/arp scan) | auditd (process exec) |
| 8 | T1548.001 | Abuse Elevation Control: setuid/setgid | Atomic T1548.001 | auditd |

This list will grow as the lab does — starting with brute force and privilege
escalation since those map cleanest to the auth.log/auditd sources already in scope,
then expanding into discovery and defense evasion once the pipeline's proven stable.

## Why Atomic Red Team

It runs individual, documented attacker techniques (not a full exploit chain), so each
test produces one clean, attributable set of log events — good for building detections
one technique at a time instead of untangling a whole simulated breach at once.
