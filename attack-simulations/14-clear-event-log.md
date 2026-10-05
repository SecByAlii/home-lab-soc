# Attack 14 — Clear the Windows Security Log (T1070.001)

**MITRE ATT&CK:** [T1070.001 — Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

The Windows version of the Linux [log-clearing](06-log-clearing.md) attack, and it makes
the same point even more sharply. An attacker covering their tracks wipes the Security
log — but Windows records the wipe itself as **event 1102**, and everything already
forwarded off-box is beyond their reach.

## Execution

```
wevtutil cl Security
```

Run **last** in the sequence, after attacks 9–13 and 15, so it had real evidence to try
to destroy.

## Result

Two things, and the second is the whole lesson:

1. **Event 1102** — "The audit log was cleared" — written to the freshly-cleared Security
   log and immediately forwarded.
2. **The earlier events survived.** `4625` (brute force), `4720` (new account), and `4698`
   (scheduled task) were all still queryable in Splunk *after* the local Security log was
   wiped, because the forwarder had already shipped them. The attacker cleared the local
   copy; the one that mattered was already gone from their reach.

This mirrors exactly what the Linux side showed when `truncate` destroyed the on-disk
`audit.log`: real-time forwarding is the control that beats log-clearing.

## Detection

See `detections/14-clear-event-log.md`.
