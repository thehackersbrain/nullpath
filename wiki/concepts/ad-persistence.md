---
title: AD Domain-Dominance Persistence (DCShadow, Skeleton Key, AdminSDHolder)
type: concept
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, persistence, domain-dominance]
---

# AD Domain-Dominance Persistence

Once an attacker holds Domain Admin (or equivalent), these techniques let
them re-enter or maintain control even if the original compromised account
is remediated. All three require DA-equivalent access to set up. See
[[ad-persistence-dcshadow-skeletonkey-adminsdholder]] (source) for commands.

## DCShadow

Register as a rogue replication partner and push attribute changes
(`sIDHistory`, `primaryGroupID`, `AdminSDHolder` ACL, arbitrary attributes)
directly via MS-DRSR replication rather than a normal LDAP write —
avoiding the attribute-modify audit trail that a write would generate.
Requires `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All`.

Effectively a stealthier delivery mechanism for the same end-states as
[[dcsync]]/[[golden-silver-tickets]] (e.g. granting Enterprise Admin via
SID history). Full deep-dive (both the rogue-replication-partner and the
shadow-DC/DSRM variants): [[dcshadow]].

## Skeleton Key

LSASS memory patch on a DC: accepts one attacker-chosen master password
for *any* domain account, alongside the real password. Requires DA +
`SeDebugPrivilege` on the DC. Non-persistent across reboot (in-memory
patch) but trivial to reapply with continued access. Full deep-dive
(detection + why krbtgt rotation doesn't remove it): [[skeleton-key]].

### DSRM account abuse (related)

Every DC has a local DSRM Administrator account. Setting
`HKLM:\System\CurrentControlSet\Control\Lsa\DSRMAdminLogonBehavior = 2`
allows that account to authenticate over the network like a normal local
account — a DC-local backdoor independent of domain credentials.

## AdminSDHolder / SDProp Persistence

`AdminSDHolder`'s ACL is copied onto all "protected" objects (Domain
Admins, Enterprise Admins, etc.) every SDProp cycle (~60 min) — this is why
manual ACL edits on protected groups silently revert. Writing an
attacker-controlled ACE onto `AdminSDHolder` itself makes that ACE
**self-propagating** onto Domain Admins and friends every cycle, surviving
individual removal attempts.

## Relation to other techniques

- These are the "stay in" complement to [[dcsync]] and
  [[golden-silver-tickets]] (the "get in/get everything" techniques).
- [[krbtgt]] rotation (the standard Golden Ticket remediation) does **not**
  remove any of these three — they require separate remediation
  (AdminSDHolder ACL audit, LSASS/DC rebuild for Skeleton Key, replication
  partner audit for DCShadow).

## Detection

- Unexpected DC replication partners / registrations (DCShadow).
- Non-default ACEs on `AdminSDHolder` or sudden new ACEs on Domain
  Admins/Enterprise Admins after a quiet period.
- Any non-zero `DSRMAdminLogonBehavior` on a DC.
