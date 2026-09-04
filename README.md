# Home Lab SOC

A self-built detection lab: a Splunk SIEM watching a simulated victim host, with realistic
attacker techniques run against it and detection logic written and tested against the real
resulting logs. Every detection here is mapped to a MITRE ATT&CK technique.

**Status: in progress.** This README tracks real state, not the finished pitch — sections
below are marked as they're completed.

## Why this exists

Most "I did a CTF" portfolio pieces show you can follow a walkthrough. This one shows the
other half of the job: watching logs, writing detections, and telling true positives from
noise — the actual day-to-day of a SOC analyst.

## Architecture

```
┌─────────────────────┐         Splunk Universal Forwarder        ┌──────────────────────┐
│   Ubuntu 26.04 VM    │ ──────────────────────────────────────►  │   macOS host          │
│   (UTM, ARM-native)  │         auth.log, auditd, syslog          │   Splunk Enterprise    │
│                      │                                            │   Free (500MB/day)     │
│  Atomic Red Team     │                                            │                        │
│  attack techniques   │                                            │  SPL detection         │
│  executed here       │                                            │  searches + dashboards │
└─────────────────────┘                                            └──────────────────────┘
```

## Build log

- [x] Host machine confirmed (Apple Silicon, 24GB RAM, 650GB free)
- [x] UTM installed (ARM-native hypervisor for the victim VM)
- [x] Ubuntu Server 26.04 LTS VM (`victim01`) created in UTM
- [x] SSH key-based access from macOS host to `victim01` configured
- [x] Splunk Enterprise (free tier) installed on macOS host
- [x] Splunk Universal Forwarder installed on `victim01`, shipping auth.log/auditd/syslog
      to Splunk on the macOS host (port 9997) — confirmed live, 1,781+ events indexed
- [x] First attack technique run + detected — T1110.001 SSH brute force via `hydra`
      (Atomic Red Team's documented test, run natively rather than through the
      PowerShell wrapper), 7 failed logins generated and caught by a 5-minute
      threshold detection
- [ ] Detection library (10+ techniques, MITRE-mapped) — 3 of 8 planned done
      (T1110.001 SSH brute force, T1136.001 new local account, T1543.002 systemd
      persistence)
- [ ] Dashboards + screenshots
- [ ] Full writeup

## Repo layout

- `setup/` — exact steps to reproduce this lab, in build order
- `attack-simulations/` — which Atomic Red Team techniques were run, and why each was picked
- `detections/` — one file per detection, each with the SPL query, the MITRE ATT&CK technique
  it maps to, and notes on false positives
- `screenshots/` — Splunk catching each simulated attack
- `WRITEUP.md` — the polished portfolio piece once the lab is complete

## Skills demonstrated

SIEM configuration and log ingestion · SPL query writing · MITRE ATT&CK mapping ·
Linux log sources (auth.log, auditd) · attack simulation · detection engineering ·
distinguishing true positives from noise
