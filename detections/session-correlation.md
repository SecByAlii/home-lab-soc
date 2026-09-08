# Correlation layer — detections → session-level incidents

**What it does:** rolls the eight single-signal detections up into per-actor sessions and
scores each session by how much of the ATT&CK matrix it touches. Three brute-force
alerts and a new-account alert from one login session aren't four things to triage —
they're one intrusion.

**Depends on:** the eight detections in this folder, exposed through the
`` `soc_detections` `` macro (`dashboards/macros.conf`), which normalises every
detection to one row: `_time`, `sig` (`"Name [Txxxx]"`), `detection`, `mitre`,
`tactic`, `actor`, `detail`.

## The macros

```
`soc_detections`   → one row per detection hit across all 8 techniques
`soc_incidents`    → `soc_detections` collapsed into scored per-actor sessions
```

`soc_incidents` in full:

```spl
`soc_detections`
| transaction actor maxpause=90m mvlist=sig
| eval detections=eventcount,
       tactics=mvcount(mvdedup(tactic)),
       techniques=mvcount(mvdedup(mitre))
| eval risk_score=(detections*5)+(tactics*20)
| eval severity=case(tactics>=4 OR risk_score>=90,"CRITICAL",
                     detections>=2,"HIGH",
                     true(),"LOW")
| eval first_seen=_time, span_min=round(duration/60)
| table first_seen span_min actor severity risk_score detections tactics techniques sig
| sort - risk_score
```

## Design decisions

- **Group by `actor`, not audit `ses`.** The attack ran across a dozen SSH sessions
  (`ses=14,15,16,24,36,40,…`). Session id fragments the intrusion; the actor doesn't.
  `transaction … maxpause=90m` then stitches an actor's activity into one incident as
  long as gaps stay under 90 minutes, and splits genuinely separate intrusions (the
  Sept 4 and Sept 8 runs land as two incidents, days apart).

- **Normalise the actor across log sources.** `auth.log` identifies a brute force by
  *source IP*; `auditd` identifies everything else by *login user* (`AUID`). Left alone,
  "`127.0.0.1` guessed the password" and "`analyst` then created an account" never join.
  The brute-force branch is rewritten to key on the **targeted account** instead of the
  source IP, so the guessing and the post-compromise activity land in the same incident
  — which is the correlation that matters.

- **Score on ATT&CK breadth, not volume.** `risk = 5·detections + 20·tactics`. A session
  that touches Persistence *and* Defense Evasion *and* Privilege Escalation is worse than
  one that fired the same detection five times. Distinct tactics is the multiplier.

- **Severity from tactic count.** `CRITICAL` at 4+ tactics (or risk ≥ 90), `HIGH` at 2+
  detections, `LOW` for a lone signal. A single brute-force alert with no follow-on is
  `LOW` — watch it, don't page on it.

## Result against the lab data

| Session | Actor | Severity | Risk | Detections | Tactics |
|---|---|---|---|---|---|
| 2026-09-08 11:04 (+42m) | analyst | **CRITICAL** | 105 | 5 | 4 |
| 2026-09-04 15:10 (+86m) | analyst | **HIGH** | 55 | 3 | 2 |

The Sept 8 session — valid-account login → cron persistence → log clearing → network
scan → setuid abuse — reads as a full intrusion chain in one row. The Sept 4 session —
brute force → new account → systemd persistence — is the earlier, narrower one.

Rendered as the **Sessions of concern** panel at the top of the dashboard
(`dashboards/soc_overview.xml`), severity-coloured.

## False positives to expect

- **A busy admin session.** A sysadmin who legitimately adds a user, edits cron, and
  restarts a service in one sitting will score `HIGH` here. The per-detection false
  positives all still apply — this layer inherits them and can amplify them. It's a
  triage aid, not a verdict.
- **`maxpause` is a guess.** 90 minutes fits this lab. A real environment tunes it to
  how its analysts actually work, and a patient attacker who spaces actions hours apart
  defeats a fixed pause entirely — `transaction` is the wrong tool at that point;
  a rolling per-actor risk score with decay is the real answer.

## Honest gap

- **No cross-actor pivot.** If the attacker brute-forces `analyst`, then `su`s to a
  second account and continues, this treats it as two incidents. Following the pivot
  needs a process-lineage / login-chain graph, not `transaction`.
- **Risk weights are hand-set.** `5` and `20` produce a sane ordering on this data set
  but aren't calibrated against anything. A real deployment would derive them from how
  often each tactic combination turns out to be a true positive.
