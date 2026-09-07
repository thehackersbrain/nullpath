---
title: "AD Tiering Model (Tier 0 / 1 / 2)"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, architecture, defense-in-depth, mitigation]
---

# AD Tiering Model (Tier 0 / 1 / 2)

The **Microsoft / Azure tiering model** is the canonical way to partition an
AD environment by *how much trust* a compromise of that system implies. It's
the architectural skeleton that nearly every AD attack path in this wiki is
measured against: most chains are just "get from a lower tier to a higher
one." The *controls* that enforce the model live in
[[ad-tiering-and-hardening]]; this page defines the tiers themselves.

## The tiers

### Tier 0 — the crown jewels (domain / enterprise)
Compromise here = full domain (or enterprise) compromise, because Tier 0
holds the **`krbtgt` key** ([[krbtgt]]), the **DCs**, and the global
security principals.
- **Domain Controllers** (all FSMO roles, [[ntds-dit]]/[[dcsync]] source) —
  see [[domain-controller]] for what a DC is and its FSMO/DSRM surface
- **Domain/Enterprise Admin** accounts and the built-in admins (`Domain
  Admins`, `Enterprise Admins`, `Schema Admins`, `Accounting/CR/Schema/DCO
  Admins`)
- **AD CS** (CA + Enterprise CA — a compromised CA mints domain-wide
  identities; see [[ad-cs-esc-attacks]])
- **Domain/forest trust keys**, the **gMSA** secrets, **SCCM/MECM
  Admins**, the **AD RMS/AIP** keys
- Any object whose compromise yields a **DCSync** right or a `krbtgt` hash

### Tier 1 — infrastructure (servers)
Compromise here = you can reach Tier 0 *if* a Tier 1 admin account also has
Tier 0 rights (the classic "server admin is also Domain Admin" mistake).
- **Domain-joined member servers** (file, print, app, DB, RDS, jump boxes)
- **Service accounts with broad rights** ([[service-account]]) — especially
  ones with **delegation** ([[kerberos-delegation-abuse]]), **DCSync** ACLs,
  or local admin on other servers
- **SCCM/MECM** servers (the NAA/PS remoting surface in [[sccm-abuse]])

### Tier 2 — user endpoints
The widest, weakest tier. The starting point of most attacks.
- **Domain-joined workstations / laptops**
- **Standard user** accounts
- Apps that store/cached domain creds ([[lsass]], [[sam-database]], [[ccache]])

## The trust-flow rule

The model's one rule: **a system may only *manage* systems at or below its
tier, and admin credentials may only *log in* at or above their tier.**
- A Tier 2 user's creds may be used on Tier 2 machines — *never* to reach a
  Tier 0 DC or Tier 1 server admin.
- A Tier 1 (server) admin may log into Tier 1 servers and Tier 0 — but its
  creds should **never be cached on a Tier 2 box**.
- A Domain Admin may log into Tier 0/1/2, but should do it **from a PAW**
  (a dedicated, hardened Tier 0 workstation), never from a regular Tier 2
  laptop.

**When the rule breaks, an attack chain closes.** The most common real-world
violations, and the chains they enable:
- *A server admin is also a Domain Admin* → Tier 1 foothold = Tier 0
  (the [[pass-the-hash-and-ticket|PtH]]/DCSync ladder).
- *A DA's laptop is a regular Tier 2 box* → one Tier 2 compromise = the DA's
  creds in [[lsass]] = domain (the reason for PAWs).
- *A service account with DCSync runs on a Tier 1 server* → Tier 1 = Tier 0
  ([[service-account]], [[dcsync]]).
- *No PAW / no tiering* → unconstrained lateral until you hit a DA.

## How this wiki uses the model

Every `path-*.md` in `wiki/notes/` is implicitly "Tier N → Tier 0." When
reading an attack page, track **which tier the attacker is in and which tier
the next step reaches**:
- Tier 2 foothold → **Tier 1** via [[kerberoasting]]/[[pass-the-hash-and-ticket]]
  (a service acct with server admin) or [[laps]].
- Tier 1 → **Tier 0** via [[dcsync]], [[golden-silver-tickets]],
  [[kerberos-delegation-abuse]], [[resource-based-constrained-delegation]].
- Tier 0 → durable via [[ad-persistence]] (DCShadow, skeleton key) or
  [[krbtgt]] rotation.

## Detection/mitigation anchors

- **Tier 0** is where you correlate **4768/4769** (DC-side) and **4662**
  (DCSync) — the [[dcsync]]/[[golden-silver-tickets]] detections.
- **Tier 1** is where **4624 Type 3** (PtH) and **7045** (service install)
  lateral detection lives ([[pass-the-hash-and-ticket]]).
- **PAW** and **Protected Users** are the two strongest single-tiering
  controls (see [[ad-tiering-and-hardening]]).

## Links

- [[ad-tiering-and-hardening]] — the control baseline that enforces this model
- [[krbtgt]] — the Tier 0 key that makes Tier 0 = domain
- [[service-account]] — the Tier 1 objects that most often bridge to Tier 0
- [[dcsync]], [[golden-silver-tickets]] — the Tier 0 end-game
- [[kerberos-delegation-abuse]], [[resource-based-constrained-delegation]] — Tier 1→Tier 0 bridges
- [[sccm-abuse]] — a Tier 1 surface
- [[gmsa]] — protecting Tier 1 service secrets
