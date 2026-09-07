---
title: "DCShadow — persist via a rogue AD replication partner"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, persistence, dcsync, ms-drsr, replication, domain-dominance]
---

# DCShadow — persist via a rogue AD replication partner

**DCShadow** is a domain-dominance **persistence** technique: instead of
writing an AD object the "normal" way (an **LDAP modify**, which leaves an
audit trail), the attacker **registers a rogue machine as a Domain
Controller / replication partner** and pushes attribute changes
(`sidHistory`, `primaryGroupID`, the **`AdminSDHolder`** ACL, arbitrary
attributes) **directly over MS-DRSR replication**. Because the change arrives
as *replication* (the same channel a real DC uses), it looks like a normal
inter-DC update — not a targeted LDAP write. It requires **DCSync-level
rights** (`DS-Replication-Get-Changes` +
`DS-Replication-Get-Changes-All`) plus the ability to register a DC object.
See [[ad-persistence]] (hub) and
[[ad-persistence-dcshadow-skeletonkey-adminsdholder]] (source) for the full
command set; this page is the dedicated deep-dive.

## How it works

1. **Register a rogue DC / replication partner** — create a computer object
   that AD will treat as a DC that can replicate (a "shadow DC"). This needs
   DA-level rights (or the equivalent ACLs).
2. **Push attribute changes over MS-DRSR** — instead of an LDAP modify to a
   specific object, the attacker issues the changes through the
   **replication protocol** (the same `Get-Changes`/`Partial-Add`/
   `Modify-Object` surface DCSync reads, but in *write* form). Examples:
   - Add a privileged SID to a user's **`sidHistory`**
     ([[sid-history]]) → that user is now in the group.
   - Change a user's **`primaryGroupID`** → group membership change.
   - Write an attacker ACE onto **`AdminSDHolder`** → the ACE
     **self-propagates** to Domain/Enterprise Admins every SDProp cycle
     (~60 min) — see [[ad-persistence]].
   - Write arbitrary attributes (e.g. a shadow cert via
     `msDS-KeyCredentialLink`, [[shadow-credentials]]).
3. **Result** — the end-state is identical to what a DCSync/Golden chain
   produces (an account elevated to DA/EA), but the *delivery* was
   replication, so the usual "who modified this object" LDAP audit
   (a targeted 4662 on the object) is muted.

## The "shadow DC" variant (DSRM-based)

A related, newer variant of the same name: an attacker who is DA **promotes a
new machine to a real DC** and **controls its local DSRM (Directory Services
Restore Mode) admin password**. Because **a local admin of a DC can DCSync**,
the attacker can — even after all their *domain* accounts are disabled/deleted
— log into the shadow DC's **local DSRM account** (a *local*, not domain,
credential) and **DCSync `krbtgt`** again. Key properties:
- The DSRM account is **per-DC and local** — it's not a domain object, so a
  domain-wide account sweep misses it.
- Setting **`HKLM\...\Control\Lsa\DSRMAdminLogonBehavior = 2`** on the DC lets
  the DSRM account authenticate **over the network** like a normal local
  account (a DC-local backdoor independent of domain creds). See
  [[domain-controller]] (the DSRM section).
- A **new, unexplained computer object in the `Domain Controllers OU`** is the
  tell.

Both variants share the core idea: **make AD treat your writes (or your
access) as if they came from a legitimate DC**, so remediation that only looks
at *domain* accounts and *LDAP writes* misses you.

## Why it's strong (and the detection gap)

- **Mutes the LDAP-modify audit** — the change arrives as replication, so the
  high-fidelity "X wrote `sidHistory` on Y" 4662 is weaker.
- **Survives account cleanup** (DSRM variant) — a *local* DC credential
  re-enters after your *domain* accounts are gone.
- **Survives `krbtgt` rotation** — like all three [[ad-persistence]]
  techniques, DCShadow/Skeleton Key/AdminSDHolder are *not* removed by rotating
  `krbtgt`; each needs its own remediation.

## Detection

- **Unexpected DC / replication partner** — a new computer object in the
  `Domain Controllers OU`, or an unexpected **DRSUAPI replication partner**
  registering/replicating (correlate 4662 + the new DC object).
- **Attribute changes that arrive via replication, not a targeted write** —
  the `sidHistory`/`primaryGroupID`/`AdminSDHolder` change present *without* a
  matching targeted LDAP 4662 from an admin workstation.
- **`DSRMAdminLogonBehavior = 2`** on a DC (the DSRM network-logon backdoor).
- **A DCSync (4662 Get-Changes/Get-ChangesAll) from a DC's DSRM/local
  context** rather than a domain account.

## Remediation

- **Audit + remove rogue replication partners** (the DC objects / DRSUAPI
  partners) and verify the `Domain Controllers OU` membership.
- **Audit `AdminSDHolder`** and protected-group ACLs (remove the planted ACE),
  and re-check `sidHistory`/`primaryGroupID` on privileged users.
- **Reset DSRM passwords** on DCs and set `DSRMAdminLogonBehavior` back to
  default (0/1).
- **Rebuild a shadow DC** if it's compromised (it holds a full directory
  copy + the DSRM secret).
- Correlate with a **`krbtgt` rotation (x2)** ([[krbtgt]]) as the broader IR
  action.

## Links

- [[ad-persistence]] — the hub (DCShadow / Skeleton Key / AdminSDHolder)
- [[ad-persistence-dcshadow-skeletonkey-adminsdholder]] — the source page (commands)
- [[dcsync]] — the rights DCShadow reuses (and the "get in" complement)
- [[domain-controller]] — the DSRM account + the DC a shadow DC impersonates
- [[sid-history]] — the classic attribute DCShadow writes to escalate
- [[krbtgt]] — why `krbtgt` rotation alone doesn't remove DCShadow
- [[golden-silver-tickets]] — the end-state DCShadow re-achieves
- [[ad-tiering-and-hardening]] — the DC/replication-audit baseline
