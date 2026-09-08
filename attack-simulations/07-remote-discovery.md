# Attack 7 — Remote System Discovery (T1018)

**MITRE ATT&CK:** [T1018 — Remote System Discovery](https://attack.mitre.org/techniques/T1018/)

Follows Atomic Red Team's T1018 tests — enumerate other hosts on the network with
`nmap` / `arp`. After landing on `victim01` (attacks 1 and 4), the operator maps what
else is reachable before moving laterally.

## Instrumentation first

`70-discovery.rules` logs every `execve` by an interactive user (`auid` set), key
`proc_exec` — see `setup/03-auditd-instrumentation.md`. Recon commands are ordinary
binaries with revealing arguments, not special syscalls, so the rule is broad and the
detection does the identifying.

## Setup — attacker brings the tool

```
sudo apt-get install -y nmap
```

`nmap` isn't on the base image, so the operator installs it. The `apt-get install nmap`
execve is itself a secondary signal — tooling arriving on a fixed-purpose host.

## Execution

```
sudo nmap -sn 192.168.64.0/24              # host discovery: ping-sweep the whole subnet
sudo nmap -p 22,80,443,3389 192.168.64.1   # port scan the gateway
ip neigh show                              # read the ARP cache for already-known hosts
```

Three shapes of the same objective: a broad sweep of the `/24`, a focused port scan of
one host, and a no-noise read of the kernel's neighbour table (hosts this box has
already talked to). `192.168.64.1` is the UTM host; nothing leaves the hypervisor's
private network.

## Result

Every command lands as an `EXECVE` record (full argv in `a0`, `a1`, …) plus a sibling
`SYSCALL` record carrying `AUID="analyst"`, `key="proc_exec"`:

```
type=EXECVE argc=3 a0="nmap" a1="-sn" a2="192.168.64.0/24"
type=EXECVE argc=4 a0="nmap" a1="-p" a2="22,80,443,3389" a3="192.168.64.1"
type=EXECVE argc=3 a0="ip" a1="neigh" a2="show"
```

These three sit inside ~13,500 execve events for the window — the detection's job is to
pull them out of routine process noise.

## Detection

See `detections/07-remote-discovery.md`.

## Honest gap

- **`nmap` made this easy.** A named scanner binary is the least stealthy way to do
  T1018. The same enumeration via a bash `for` loop over `ping -c1` or `/dev/tcp` would
  show up as hundreds of `ping`/`bash` execs, not one `nmap` — a rate/fan-out detection,
  not a binary-name one. Noted as the harder variant, not built.
- **`ip neigh show` is dual-use.** Admins and monitoring run it constantly. It's kept in
  the detection here because in this lab it's clearly part of the recon burst, but on a
  real host it needs correlation (ran alongside a scan, from an unusual session) rather
  than alerting on its own.
