---
title: "Domain Controller & FSMO Roles"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, domain-controller, fsmo, dcsync, tier-0]
---

# Domain Controller & FSMO Roles

A **Domain Controller (DC)** is a server that runs **Active Directory Domain
Services (AD DS)** for a domain: it hosts a **replicated copy of the domain
directory** ([[ntds-dit]]), serves **Kerberos** (it *is* the KDC — the
`krbtgt` key lives here, [[krbtgt]]), answers **LDAP** ([[ldap]]), and holds
**SYSVOL** (group policy + netlogon scripts). A domain has **many DCs**; they
**replicate** to each other, so a compromise of *one* DC is a compromise of
*the domain*. That's why, in the [[ad-tier-model]], **DC = Tier 0**: it's the
crown jewel.

## Why a DC is the end-game

Every "get to Domain Admin" chain in `wiki/notes/` ends at a DC, because a DC
gives you:
- **DCSync** — replicate *any* account's hash/key over DRSUAPI, including
  `krbtgt` ([[dcsync]]). A local admin of a DC, or an account with
  `Get-Changes`/`Get-ChangesAll`, can DCSync.
- **The `krbtgt` secret** — forge any TGT (a [[golden-silver-tickets|Golden
  Ticket]]) for durable, domain-wide access.
- **The offline [[ntds-dit]]** — if you can't DCSync but you have a DC shell,
  take a VSS snapshot and dump the whole directory offline.
- **SYSVOL / GPO** — plant domain-wide policy (see [[gpo-abuse]]).
- **The DSRM local admin** — a *local* (non-domain) admin of the DC that can
  DCSync, the basis of [[dcshadow]] persistence.

## The five FSMO (Flexible Single Master Operation) roles

Certain **write** operations in AD are **single-writer** to avoid
replication conflicts. Those operations are pinned to one DC each — the
**FSMO role holders**. There are **five** (three per-forest, two per-domain):

| Role | Scope | What it controls | Attack relevance |
|------|-------|------------------|------------------|
| **Schema Master** | forest | the AD **schema** (object classes/attributes) | a [[ad-persistence|SDProp]]/AdminSDHolder persistence target; schema changes are global |
| **Domain Naming Master** | forest | **add/remove domains** to/from the forest | control over new domains (trust surface, [[ad-trust-attacks]]) |
| **PDC Emulator** | domain | **time source**, password-change propagation, **relative-id (RID) allocation fallback**, and the first DC a logon is tried against | the DC you **target for DCSync** (it's the "primary" for many operations); password changes replicate from here first |
| **RID Master** | domain | allocates **relative IDs (RIDs)** for new objects (SIDs) | where new user/computer SIDs are minted |
| **Infrastructure Master** | domain | maintains **cross-domain group→member SID** references | relevant in multi-domain/forest ([[ad-structure]]), cross-domain trust resolution |

**Practical points:**
- **You can find the holders** with `netdom query fsmo` or PowerShell
  `Get-ADForest` / `Get-ADDomain`. On a live box, `nltest /dsgetdc` finds the
  DC serving you.
- **The PDC emulator is the usual DCSync target** — it's the "primary" DC and
  where password changes land first. But *any* DC works for DCSync (all
  replicate the full directory); the PDC is just the conventional choice.
- **Role seizure is a recovery move** — if a role holder DC is gone, an admin
  can seize the role to another DC (`ntdsutil` / `Set-ADDomainController`).
  An attacker who can seize a role (rare, needs DA) can pin operations to a
  DC they control.

## DSRM (Directory Services Restore Mode)

Each DC has a **local** account (the **DSRM** account, `Administrator` in the
`Domain Controllers OU` context / the DSRM password) used to log into the DC
in **restore mode** (offline) and to administer the DC *locally*. Key
property: **the DSRM account is a local admin of that DC, and a local admin of
a DC can DCSync.** The DSRM password is **per-DC** (stored as a hash on the
domain's `msDS-DirectoryServiceAndAccountRecoveryPassword`), and **not** a
domain object — so it survives domain-wide account cleanup. This is the
foundation of [[dcshadow]] (persist via a DC's local/DSRM admin) and a
recurring "backup DA" path.

## Detection (a DC is being abused)

- **4662** on the domain object (DCSync) — see [[dcsync]].
- **VSS creation / NTDS.dit access** — an offline dump, see [[ntds-dit]].
- **`krbtgt` rotation** (a `krbtgt` password change) — an IR response to a
  suspected Golden, see [[krbtgt]].
- **FSMO role changes** — a role holder change on a DC (unusual outside
  recovery).
- **A new DC appearing** (a computer object in the `Domain Controllers OU`
  you didn't authorize) — a [[dcshadow]] tell.

## Links

- [[ad-tier-model]] — DC = Tier 0
- [[dcsync]] — the DC's headline capability (replicate any secret)
- [[krbtgt]] — the DC-held key that signs all TGTs
- [[ntds-dit]] — the DC's directory database (offline dump)
- [[dcshadow]] — persistence via a DC's local/DSRM admin
- [[ad-structure]] — where the DC sits in the domain/forest hierarchy
- [[ad-persistence]] — DCShadow/Skeleton Key/AdminSDHolder hub
- [[gpo-abuse]] — SYSVOL/GPO as a DC-held attack surface
- [[ad-tiering-and-hardening]] — the DC-protection baseline
