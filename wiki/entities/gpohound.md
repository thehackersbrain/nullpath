---
title: GPOHound
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, gpo, enumeration, active-directory, bloodhound]
---

# GPOHound

**GPOHound** (by williamla1337, part of PowerSploit) is the PowerShell
**GPO enumeration + attack-surface** tool — it maps **who can write which
GPOs**, which **OUs/machines each GPO is linked to**, and which GPOs are
therefore an **attack path** to code execution on high-value targets
(especially DCs). It's the *enumeration* side of [[gpo-abuse]] — the
"which GPOs should I exploit?" step — and feeds [[sharp-gpo-abuse]] /
[[powerview]] for the exploit. See [[gpo-abuse]] for the mechanics and
[[path-gpo-write-to-domain-admin]] for the chain.

## What it maps

- **GPO → linked OU/computer** — which machines apply each GPO (a GPO linked
  to the DC OU = Tier-0 code exec if writable).
- **Principal → GPO write edge** — which accounts/groups have
  WriteDacl/GenericWrite/owner on each GPO (the [[acl-abuse]] edge).
- **The combined attack surface** — "account X can write GPO Y, which is
  linked to DC Z" — the full [[gpo-abuse]] path in one query.

## Common invocations

```powershell
Import-Module .\GPOHound.ps1

# Collect GPO data (like SharpHound, for GPOs)
Invoke-GPOCollector -Domain corp.local -CollectionMethod STEALTH

# Which GPOs am I able to write?
Get-GPOsByGUID ... # or query the collected data:
Get-AttackPath -GPO <guid>   # attack paths through a specific GPO

# Find GPOs linked to a target (e.g. a DC's OU)
Get-GPOLinkedTo -OU "OU=Domain Controllers,DC=corp,DC=local"
```

## Detection

- **PowerShell execution** — the collector + queries (4104/4103).
- **GPO read/enumeration bursts** — many GPO object reads from one source
  (4661/5136-read).
- GPOHound itself is largely **read-only** enumeration — the loud part is the
  *exploit* it informs ([[sharp-gpo-abuse]]).

## Mitigations

- Same as the exploit it informs — restrict GPO edit-rights, alert on GPP
  object creation, tiering ([[gpo-abuse]]).

## Links

- [[gpo-abuse]] — the concept GPOHound enumerates
- [[sharp-gpo-abuse]] — the exploit tool GPOHound feeds
- [[powerview]] — the broader AD enumeration companion
- [[bloodhound]] — the graph alternative (GPO edges)
- [[acl-abuse]] — the GPO object-control edge
- [[path-gpo-write-to-domain-admin]] — the full chain

## References

- [GPOHound (GitHub)](https://github.com/PowerSploit/PowerSploit)
- [ired.team: GPO enumeration](https://www.ired.team/windows-offensive-security/group-policies)
- [gpo-abuse (this wiki)](gpo-abuse)
