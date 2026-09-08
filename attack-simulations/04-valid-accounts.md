# Attack 4 — Valid Accounts (T1078)

**MITRE ATT&CK:** [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)

Atomic Red Team's tests for T1078 are Windows- and cloud-focused (local `net user`
logons, Azure AD sign-ins) with nothing that runs on a headless Linux box, so this one
is run manually — as the planned-techniques list already called for. The scenario is the
direct continuation of attack 1: a password-guessing run against `analyst` that this
time **lands**, and the attacker logs straight in on the credential they just recovered.

This is the technique boundary worth being precise about. Attack 1 (T1110.001) is the
guessing. The moment one guess is correct and gets used to authenticate, the activity is
T1078 — the attacker is now operating as a legitimate account, and every following action
is indistinguishable from that real user unless something flags the login itself.

## Setup

A weak password is set on `analyst` so the guessing run has something to find (a lab
stand-in for a real cracked or phished credential — see "Honest gap" below):

```
echo 'analyst:<lab password>' | sudo chpasswd
```

The actual value is kept out of this repo; on the build host it is stored in the macOS
login keychain as item `home-lab-soc victim01 analyst`.

## Execution

```
cat > /tmp/t1078_wordlist.txt <<'WORDS'
Password1
Welcome2026
Spring2026!
<lab password>
WORDS

hydra -l analyst -P /tmp/t1078_wordlist.txt -t 1 ssh://127.0.0.1
```

Same tool and target as attack 1, with one deliberate change: the correct password is
the last entry in the list, so the run produces a short burst of failures immediately
followed by a success — the log signature of a guessing attack that worked.

```
[22][ssh] host: 127.0.0.1   login: analyst   password: <lab password>
1 of 1 target successfully completed, 1 valid password found
```

## Result

Four events in `/var/log/auth.log` (forwarded as `sourcetype=linux_secure`), same
source IP and source port throughout — one `sshd-session` process working the
connection:

```
sshd-session[2053]: Failed password for analyst from 127.0.0.1 port 55962 ssh2
sshd-session[2053]: Failed password for analyst from 127.0.0.1 port 55962 ssh2
sshd-session[2053]: Failed password for analyst from 127.0.0.1 port 55962 ssh2
sshd-session[2053]: Accepted password for analyst from 127.0.0.1 port 55962 ssh2
```

Three failures over about six seconds, then `Accepted password` for the same account
from the same address. That `Failed`-then-`Accepted` sequence from one source is the
thing the detection keys on.

## Detection

See `detections/04-valid-accounts.md`.

## Honest gap

- **The credential was made guessable on purpose.** A real T1078 login uses a password
  obtained out of band — phished, reused from a breach dump, pulled from a config file —
  and the guessing burst that this detection correlates against wouldn't exist. Caught
  that way, T1078 needs a different signal: a valid login from an unfamiliar source IP,
  at an unusual hour, or for an account that normally only uses SSH keys. Noted as the
  next iteration, not built here.
- **`analyst` is also the box's real admin account.** In this lab it doubles as the
  attacker's target; a cleaner separation would give the simulated victim its own
  low-value account so admin activity and attacker activity never share a username.
