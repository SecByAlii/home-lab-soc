# Home Lab SOC — Detection Engineering Writeup

A single-analyst detection lab: a Splunk SIEM watching a purpose-built Linux victim
host, eight attacker techniques run against it, and a detection written and tuned for
each one against the **real logs the attack produced** — not against documentation, not
against synthetic data. Every detection is mapped to MITRE ATT&CK and ships with the
false positives it will produce and an honest note on what it doesn't cover.

Repo: [github.com/SecByAlii/home-lab-soc](https://github.com/SecByAlii/home-lab-soc)

---

## The premise

Most entry-level security portfolios are CTF writeups. A CTF writeup shows you can
follow an attack path someone else designed. It says nothing about the other side of
the console — the part where alerts fire, most of them are noise, and someone has to
decide which one is real.

This project is that side. For each technique the loop was:

1. **Run the attack** on the victim host, using the documented Atomic Red Team procedure
   where one exists.
2. **Read the logs it actually generated** — not what the technique's wiki page says it
   should generate, what this host on this OS actually wrote.
3. **Write a detection** against those real events.
4. **Run it against the full log history** and see what else it catches — the tuning
   pass.
5. **Write down the false positives** it will produce in a real environment, and the
   part of the technique it still misses.

Step 5 is the one that matters. A detection without a documented failure mode is a
liability — it tells whoever's on call that it's trustworthy when it isn't.

---

## Architecture

```
┌─────────────────────┐        Splunk Universal Forwarder         ┌──────────────────────┐
│   Ubuntu 26.04 VM    │ ──────────────────────────────────────►  │   macOS host          │
│   victim01 (UTM)     │        auth.log · auditd · syslog         │   Splunk Enterprise    │
│                      │        shipped in real time (:9997)       │   (free tier)          │
│  attacks run here    │                                            │   SPL detections       │
│  auditd rule sets    │                                            │   + dashboards         │
│  loaded per technique│                                            │                        │
└─────────────────────┘                                            └──────────────────────┘
```

- **victim01** — Ubuntu Server 26.04 on UTM (ARM-native). Three log sources:
  `/var/log/auth.log` (`linux_secure`), the kernel audit log (`linux_audit`), and
  `/var/log/syslog`.
- **Forwarding is the point, not a detail.** Logs leave the host the moment they're
  written. Detection 6 (log clearing) demonstrates why: anything still only on disk can
  be erased by an attacker with root, and in one test run it was — the forwarded copy is
  the one that survived.
- **auditd starts with no rules.** File-write and process-execution visibility is turned
  on rule set by rule set as the detection library grows — four sets so far, one per
  technique that needs them, all versioned in `detections/audit-rules/` and documented
  in `setup/03-auditd-instrumentation.md`.

---

## The detection library

| # | MITRE ATT&CK | Technique | Detection shape | Log source |
|---|---|---|---|---|
| 1 | T1110.001 | SSH brute force | rate — N failures per window | `auth.log` |
| 2 | T1136.001 | New local account | rare-event — alert on any occurrence | `auth.log` |
| 3 | T1543.002 | systemd persistence | allowlist — unseen service name | `syslog` |
| 4 | T1078 | Valid accounts | correlation — success after a failure burst | `auth.log` |
| 5 | T1053.003 | Cron persistence | file-write + exec watch | `auditd` |
| 6 | T1070.002 | Log truncation / deletion | destructive op on a protected file | `auditd` |
| 7 | T1018 | Remote system discovery | scanner binary + argument shape | `auditd` |
| 8 | T1548.001 | Setuid/setgid abuse | mode-bit change + elevated execution | `auditd` |

Four detection *shapes* across eight techniques — rate, rare-event, allowlist,
correlation. Recognising which shape a technique needs is most of the job; the SPL is
the easy part once that's decided.

Three worth walking through, because they show the range.

### Detection 1 — SSH brute force (T1110.001): the rate shape

`hydra` against the `analyst` account produced 7 `Failed password` lines in ~30 seconds.
The detection buckets failures into 5-minute bins by source IP and alerts on 5 or more:

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<attempted_user>\S+) from (?<src_ip>\S+)"
| bin _time span=5m
| stats count as failed_attempts, values(attempted_user) as attempted_users by src_ip, _time
| where failed_attempts >= 5
```

Binning instead of a single running count matters: a slow brute force spread over hours
doesn't get averaged below the threshold, and a tight burst — the actual `hydra`
behaviour — trips it immediately. The companion question ("did any attempt then
*succeed*?") became detection 4.

**Documented false positive:** a real user fat-fingering their own password 5+ times.
Distinguished by whether `attempted_users` is one account from a known IP (a person) or
many accounts / an unfamiliar IP (an attack).

### Detection 3 — systemd persistence (T1543.002): the allowlist shape

The attack planted a new systemd service (`sysupdate-check.service`, deliberately
boring name) that runs on every boot. There's no rate here and no rare-event framing
that works — a minimal Ubuntu box starts ~90 legitimate services, so "a service
started" is not a signal. The question is **identity**: *have I seen this specific
service before?*

The detection answers it with a lookup table of every service name that had legitimately
started on the box, captured before the attack ran:

```
grep -oP 'Starting \K\S+(?= - )' /var/log/syslog | sort -u > known_services.csv
```

```spl
index=main sourcetype=syslog "systemd[1]: Starting"
| rex "Starting (?<service_name>\S+) - "
| lookup known_services.csv service_name OUTPUT is_known
| where isnull(is_known)
```

One row against the attack: `sysupdate-check.service`. The honest gap is written into
the detection file — a snapshot allowlist only works for one hand-built host with a
known install history; a fleet needs this per golden image, or a first-seen search over
a long rolling window instead.

### Detection 6 — log clearing (T1070.002): auditd, and a real finding

The attack cleared logs three ways — `truncate` on `auth.log`, `rm` on `syslog`, and an
`O_TRUNC` open on the audit log itself. auditd writes one indexed event per *record*
(`SYSCALL`, `PATH`, `EXECVE` are separate events sharing one `audit(epoch:serial)` id),
so the detection stitches them back together in SPL:

```spl
index=main sourcetype=linux_audit (key=log_tamper OR type=PATH)
| rex "audit\((?<aevent>[0-9.]+:[0-9]+)\)"
| rex "\bname=\"(?<target>[^\"]+)\""
| stats values(comm) as comm, values(AUID) as auid, values(target) as targets by aevent
| eval logfile=mvfilter(match(targets,"^/var/log/(auth\.log|syslog|audit/audit\.log|...)$"))
| where isnotnull(logfile) AND auid!="unset"
```

Two things this technique taught that weren't in the plan:

- **`AUID` is the attribution field.** Every command ran through `sudo`, so `uid` and
  `euid` are `root` and useless. `AUID` — the login UID the kernel stamps at session
  start — stays `analyst` through the privilege change. Filtering on it also removes the
  legitimate noise (rsyslogd recreating the files after a service restart runs with
  `AUID=unset`, because a daemon started by init has no login UID).

- **Truncating the audit log destroyed the evidence of the other two clears.** On the
  first run all three commands ran back-to-back; zeroing `audit.log` while auditd's
  async write buffer still held the `auth.log` and `syslog` records meant those never
  reached disk or Splunk. The detection's `auth.log`/`syslog` rows come from a second,
  cleaner run. This isn't a lab artifact to apologise for — it's the technique working,
  and it's the argument for real-time off-box forwarding stated as plainly as it can be.

---

## What this demonstrates

- **SIEM operation** — installing and configuring Splunk + Universal Forwarder,
  managing indexes and inputs, monitoring ingest health (and recovering it after an
  attack disrupted it).
- **Log-source knowledge** — `auth.log` vs `auditd` vs `syslog`: what each captures,
  where each falls short, and when a technique needs auditd rules that aren't on by
  default.
- **SPL** — field extraction with `rex`, `stats` aggregation, `bin` for time-bucketing,
  `lookup` for allowlists, multi-record correlation by shared event id, bitwise mode
  decoding.
- **Detection engineering as a discipline** — matching a detection shape to a technique,
  tuning against real history, and writing the failure mode down every time.
- **MITRE ATT&CK fluency** — every detection mapped, and the boundary cases reasoned
  through (where T1110 becomes T1078; T1053.003 as the schedule-based sibling of
  T1543.002).
- **Adversary tradecraft** — enough to run each technique the way an operator would
  (boring names, `nosuid`-aware payload placement, `AUID`-preserving `sudo` chains) and
  to know what the *stealthier* version would look like.

---

## Known limitations

Carried up from the per-detection honest-gap sections, because a reviewer should see
them without digging:

- **Single host, no baseline traffic.** The rate thresholds (detection 1) and the
  absence of a log-silence detection (detection 6) both come down to there being no
  steady legitimate activity to baseline against. Real tuning needs real traffic.
- **Record stitching happens in SPL, not at index time.** The auditd detections
  reassemble multi-record events with `rex` + `stats` on every search. A production
  deployment would do this once with `props`/`transforms` on the indexer.
- **Allowlists are snapshots.** `known_services.csv` (detection 3) and the implicit
  known-good sets elsewhere are point-in-time captures of one hand-built box. They work
  here because nothing else changed between snapshot and attack.
- **Correlation inherits every per-detection false positive.** The session layer (below)
  is a triage aid, not a verdict — a busy admin session scores `HIGH` on it. And its
  90-minute session window is a guess that a patient attacker defeats by spacing actions
  out; a rolling risk score with decay is the real answer.

---

## Correlation — from detections to incidents

The eight detections are single-signal: each fires on one observation, independently.
Three brute-force alerts and a new-account alert from one login session aren't four
things to triage — they're one intrusion. A correlation layer rolls them up.

Everything runs through two macros (`dashboards/macros.conf`):

- **`` `soc_detections` ``** normalises all eight detections to one row each — `_time`,
  `sig`, `mitre`, `tactic`, `actor`, `detail`. The dashboard's every panel is built on
  this.
- **`` `soc_incidents` ``** collapses that into per-actor sessions
  (`transaction actor maxpause=90m`) and scores each `5·detections + 20·distinct
  tactics`, with severity from the tactic count.

Two design decisions did the real work:

- **Normalising the actor across log sources.** `auth.log` names a brute force by source
  IP; `auditd` names everything else by login user (`AUID`). Left alone, "`127.0.0.1`
  guessed the password" and "`analyst` then created an account" never join. Re-keying the
  brute-force detection on the *targeted account* puts the guessing and the
  post-compromise activity in the same incident.
- **Scoring on ATT&CK breadth, not volume.** A session that touches Persistence *and*
  Defense Evasion *and* Privilege Escalation is worse than one that fired the same rule
  five times. Distinct tactics is the multiplier.

Against the lab data the eight raw detections collapse into two incidents:

| Session | Actor | Severity | Risk | Detections | Tactics |
|---|---|---|---|---|---|
| 2026-09-08 11:04 (+42m) | analyst | **CRITICAL** | 105 | 5 | 4 |
| 2026-09-04 15:10 (+86m) | analyst | **HIGH** | 55 | 3 | 2 |

Full design notes and false positives: `detections/session-correlation.md`.

## Dashboard

One Splunk view (`dashboards/soc_overview.xml`, screenshot in the README): **sessions of
concern** at the top from `` `soc_incidents` ``, then the simulated intrusion as a
chronological ATT&CK-mapped timeline, coverage counters, and a by-tactic breakdown.
Every panel runs the real macros — the dashboard *is* the detection library and its
correlation layer, not a separate reporting build.

## What's next

- Replace the `transaction` session window with a rolling per-actor risk score with
  decay — defeats the "space actions out" evasion a fixed `maxpause` can't.
- Follow cross-actor pivots (brute-force `analyst` → `su` to another account) with a
  login-chain graph rather than treating them as separate incidents.
- Add discovery / defense-evasion breadth toward a 10+ technique library.
- Replace snapshot allowlists with first-seen searches over a rolling window.
