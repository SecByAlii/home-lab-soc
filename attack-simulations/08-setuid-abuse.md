# Attack 8 — Setuid/Setgid Abuse (T1548.001)

**MITRE ATT&CK:** [T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid](https://attack.mitre.org/techniques/T1548/001/)

Follows Atomic Red Team's T1548.001 tests — copy a shell, set the setuid bit on it so
it runs with the file owner's privileges, then execute it to get a root shell without a
password. This is a persistence-flavoured privilege-escalation move: once the setuid
binary exists, the operator can come back to root any time, no `sudo` and no credential.

## Instrumentation first

`80-privesc.rules` logs `fchmod` / `fchmodat` by interactive users, key `perm_mod` —
see `setup/03-auditd-instrumentation.md`. The second half of the detection (a process
running with `euid=0` it wasn't launched with) rides the `proc_exec` feed already in
place from `70-discovery.rules`.

## Execution

```
sudo cp /bin/bash /var/tmp/.cache-helper   # root-owned copy of the shell
sudo chmod 4755 /var/tmp/.cache-helper     # setuid bit + world-executable
/var/tmp/.cache-helper -p -c 'id'          # run it; -p stops bash dropping privileges
```

`id` from inside that shell:

```
uid=1000(analyst) gid=1000(analyst) euid=0(root) ...
```

`euid=0` while the real `uid` is still `analyst` — the setuid bit worked.

Two details that matter for reproducing it:

- **The binary must be root-owned.** A first attempt copied bash as `analyst`; the
  setuid bit then just meant "run as analyst," no gain. `sudo cp` fixes it.
- **It can't live in `/tmp`.** `/tmp` and `/dev/shm` are mounted `nosuid` on this image,
  so the kernel ignores the setuid bit on exec there. `/var/tmp` is on `/` and honours
  it. (That `nosuid` mount is itself a real, cheap hardening control worth noting.)

## Result

- **The `chmod`:** `type=SYSCALL syscall=fchmodat`, `comm="chmod"`, `key="perm_mod"`,
  `AUID="analyst"`, mode argument `a2=9ed` → octal `04755` → setuid bit set.
- **The execution:** `type=SYSCALL syscall=execve`, `comm=".cache-helper"`,
  `exe="/var/tmp/.cache-helper"`, `uid=1000` but `euid=0`, `AUID="analyst"`.

## Detection

See `detections/08-setuid-abuse.md`.

## Cleanup note

The setuid-root shell was deleted from `victim01` (`rm /var/tmp/.cache-helper`) right
after the audit events were confirmed indexed — a root-shell backdoor isn't something to
leave sitting on the box even in a lab. The auditd records proving the technique ran are
permanent in Splunk.

## Honest gap

- **`chmod 4755` is the loud way.** A stealthier operator sets the bit with a raw
  `chmod(2)` from compiled code, or targets an *existing* system setuid binary with a
  known escalation (GTFOBins-style) rather than dropping a new one. The first still trips
  `perm_mod`; the second wouldn't — it needs a baseline of the box's known-good setuid
  inventory (see the detection's honest gap).
