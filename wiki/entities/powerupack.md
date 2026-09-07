---
title: PowerUpACK
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, powershell, active-directory, privesc, acl-abuse]
---

# PowerUpACK

**PowerUpACK** (by williamla1337, an extension of PowerSploit) is the
PowerShell **AD privilege-escalation + persistence toolkit** — the
object-control / ACL-abuse workhorse. Where [[powerview]] *enumerates* the
abuse edges, PowerUpACK *exploits* them: GenericWrite/GenericAll/WriteDacl
object writes, SID History injection, GPO abuse, AdminSDHolder, DSRM
backdoors, LAPS reads, and more. It's the "I found the edge, now exploit it"
tool for the [[acl-abuse]] family and the persistence primitives in
[[ad-persistence]].

## Capabilities (the abuse edges it exploits)

- **GenericWrite / GenericAll object writes** — the core [[acl-abuse]]
  primitives: write `msDS-KeyCredentialLink` (shadow credentials),
  `servicePrincipalName`, `manager`, group membership, etc. on a target
  object. See [[path-genericwrite-to-dcsync]].
- **SID History injection** — write a privileged group SID into a user's
  `sidHistory` ([[sid-history]]).
- **GPO abuse** — SharpGPOAbuse integration ([[gpo-abuse]],
  [[sharp-gpo-abuse]]).
- **AdminSDHolder / SDProp** — persistence via the AdminSD
  propagation object ([[ad-persistence]]).
- **DSRM backdoor** — `dSRMAdminPassword` / `dSRMPasswordInterval` writes for
  Directory Services Restore Mode persistence ([[ad-persistence]]).
- **LAPS read / set** — read `ms-Mcs-AdmPwd` or take over LAPS
  ([[laps]]).
- **Computer object abuse** — `primaryGroupID`, `msDS-AllowedToActOnBehalfOfOtherIdentity`
  (RBCD), `dNSHostName`, etc.
- **ACL / DACL manipulation** — `Add-ADObjectAcl`, `Set-ADObjectAcl` to add
  yourself a write ACE on a target (the "get the edge" step).

## Common invocations

```powershell
# Import
Import-Module .\PowerUpACK.ps1

# Find the abuse edges (pairs with Get-DomainObjectAcl)
Get-DomainObjectAcl -Identity <target> -Resolved |
  Where-Object { $_.ActiveDirectoryRights -match 'GenericWrite|GenericAll|WriteProperty|WriteDacl' }

# Add yourself a GenericWrite ACE on a target object (get the edge)
Add-ADObjectAcl -TargetIdentity <target> -PrincipalIdentity <you> -Rights GenericWrite

# Write a SID into a user's sidHistory (sid-history abuse)
Set-DomainObject -Identity <user> -Add @{ 'sidHistory'='S-1-5-21-<dom>-519' }

# Plant a shadow credential (msDS-KeyCredentialLink) — see shadow-credentials
# (PowerUpACK + a generated cert/key)

# LAPS read
Get-DomainComputer -Identity <comp> -Properties ms-Mcs-AdmPwd | Select ms-Mcs-AdmPwd
```

## Detection

- **5136 attribute edits** on privileged objects (sidHistory,
  msDS-KeyCredentialLink, servicePrincipalName, dSRMAdminPassword) — the
  per-technique tells (see the individual concept pages).
- **4738 logons** after a SID-history / shadow-credential write.
- **ACL (DACL) changes** — a new GenericWrite/WriteDacl ACE added to a
  high-value object.
- **PowerShell execution** — the module load + the `Set-DomainObject` /
  `Add-ADObjectAcl` calls (4104 module load, 4103 scriptblock).

## Mitigations

- **Restrict object-control ACEs** — don't let low-tier principals hold
  GenericWrite/WriteDacl on Tier-0 objects ([[acl-abuse]],
  [[ad-tiering-and-hardening]]).
- **Alert on the high-value attribute writes** (5136 on
  msDS-KeyCredentialLink, sidHistory, dSRMAdminPassword, GPO
  `gPCUser/GPOption` changes).
- **Tiering** — the structural fix: a low-tier principal shouldn't hold an
  edge into Tier-0 at all.

## Links

- [[acl-abuse]] — the object-control edges PowerUpACK exploits
- [[powerview]] — the enumeration side (find the edges)
- [[ad-persistence]] — the DCShadow/AdminSDHolder/DSRM primitives
- [[sid-history]], [[shadow-credentials]], [[laps]] — the specific abuses
- [[gpo-abuse]], [[sharp-gpo-abuse]] — the GPO abuse path
- [[bloodhound]] — how you find the edges PowerUpACK exploits

## References

- [PowerUpACK (GitHub)](https://github.com/williamla1337/PowerUpACK)
- [ired.team: AD access control / object abuse](https://www.ired.team/)
- [InternalAllTheThings: AD privesc](https://swisskyrepo.github.io/InternalAllTheThings/)
