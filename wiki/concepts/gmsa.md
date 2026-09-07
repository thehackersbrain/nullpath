---
title: Group Managed Service Accounts (gMSA)
type: concept
created: 2026-06-12
updated: 2026-09-06
tags: [active-directory, service-accounts, mitigation, gmsa, offline-cracking]
---

# Group Managed Service Accounts (gMSA)

A **Group Managed Service Account** is a service account whose **password is
auto-rotated by AD/Windows** (a 120-character, effectively uncrackable
secret, rolled on an interval). It's **the single most-repeated mitigation in
this wiki** — it's what breaks the *offline-cracking* leg of [[kerberoasting]],
[[as-rep-roasting]], and Silver Ticket forgery in [[golden-silver-tickets]].
This page is the full mechanics: what a gMSA actually is in AD, why the
rotation defeats offline cracking, and — because this is an attack wiki — the
**ways a gMSA is still attacked**.

## What a gMSA is in AD

- A gMSA is a **computer-like object** (it joins the domain like a machine
  account — see [[service-account]]) that carries the **service's SPN(s)**
  (e.g. `MSSQL/SVR01`) instead of (or in addition to) its own. The service
  authenticates to the domain *as the gMSA*, so the gMSA is the Kerberos
  identity of the service.
- The gMSA's **secret** (its password/key) is stored in AD and **distributed
  to the host(s) that run the service** via a key-distribution mechanism (the
  host's LSA picks up the current key; a configurable **key-rollover
  interval** controls how often it's regenerated and re-distributed).
- The key is **cached in LSASS on the host running the service** (as an LSA
  secret) — which is both how the service uses it and a target (see below).
- **The rotation is the point**: every rollover, the old password/key is
  invalidated and a new one is distributed. Any ticket or hash captured
  *before* the rollover is useless *after* it.

## Why rotation defeats offline cracking

Most credential-cracking AD attacks ([[kerberoasting]], [[as-rep-roasting]],
the Silver-Ticket forgery in [[golden-silver-tickets]]) depend on the target
account having a **static** password weak enough to crack offline, and the
cracked key staying valid. A gMSA's secret is:
- **effectively uncrackable** (120 random chars → ~800-bit entropy), and
- **short-lived** (even a cracked key dies at the next rollover).

So gMSA neutralizes the *crack* — it does **not** neutralize *using* a
legitimate gMSA identity, and it does **not** stop the attacks that need the
gMSA's *current* key live (see below).

## Where it's cited as the mitigation

- [[kerberoasting]] — neutralizes offline cracking of the TGS.
- [[as-rep-roasting]] — same, for the AS-REP.
- [[golden-silver-tickets]] — neutralizes Silver Ticket forgery against the
  service account.
- [[kerberos-delegation-abuse]] — recommended for accounts used in
  constrained delegation.

See [[ad-tiering-and-hardening]] for the broader hardening baseline.

## Attacking a gMSA (it's not unbreakable)

Rotation defeats *offline cracking of a stale key*, but a gMSA is still a
**live, privileged identity** with an **SPN** and a **cached key**. The
gMSA-specific attack surface:

1. **Crack the *current* key before it rolls** — pull the TGS
   ([[kerberoasting]]) or the AS-REP and race the rollover window. Short
   interval = smaller window; default intervals leave minutes-to-an-hour of
   exposure. (Rotation shortens, doesn't eliminate, the crack window.)
2. **Dump the cached key from the host's LSASS** — the gMSA key sits in
   **LSASS on the machine running the service** (an LSA secret). A
   [[lsass]] dump on that host (comsvcs/procdump) yields the **current gMSA
   password/key in memory** — no offline cracking, no waiting for the
   window. This is the most reliable "beat the rotation" path.
3. **DCSync / offline NTDS dump** — a gMSA is a computer-like object with a
   password, so a [[dcsync]] or an offline [[ntds-dit]] dump
   ([[secretsdump]]) exposes its **current password** directly (no cracking,
   no window). You then hold the live gMSA identity.
4. **Write/ACL the gMSA object** — if the gMSA object (or its key attribute)
   is writable by a low-priv principal ([[acl-abuse]]), the attacker can
   **reset the gMSA password to a known value** and use the service identity
   after the new key propagates (or, in some configs, force immediate
   re-distribution).
5. **Use the gMSA identity directly** — once you hold the current key
   (via 2/3/4), you authenticate *as the service* (e.g. to the SQL/AD CS/IIS
   instance), which often means the **service's own elevated context** —
   frequently a real foothold on a sensitive host, independent of whether the
   gMSA is in a privileged group.

The net: **gMSA removes the *crack* but not the *identity***. The defense
that actually closes these is protecting the **gMSA object's ACL** (who can
read/reset its key) and the **hosts running it** (LSASS protection), not just
relying on rotation.

## Detection

- **A TGS request for a gMSA SPN** (4769) followed by successful use — a
  kerberoast racing the rotation window.
- **LSASS access on a gMSA host** (Sysmon 10) — the cached-key dump path.
- **DCSync/NTDS exposure of the gMSA** — 4662/DRSUAPI or an offline dump
  (correlate the gMSA object with the DCSync event).
- **A gMSA password reset / key-rollover out of band** — an unexpected
  rollover or a reset by a non-service account.

## Mitigations

- **Use gMSA** for service accounts with SPNs (the primary control).
- **Shorten the key-rollover interval** (shrinks the crack-window and the
  exposure of a dumped key).
- **Protect the gMSA object ACL** — restrict who can read/reset the key
  attribute to the specific host + the gMSA service group.
- **Protect LSASS on gMSA hosts** (PPL/Credential Guard — [[lsass]],
  [[ad-tiering-and-hardening]]) to close the in-memory key dump.
- **Avoid putting gMSAs in privileged groups**; scope the SPN to the service
  only.

## Links

- [[service-account]] — the account types (gMSA is the managed variant)
- [[kerberoasting]] — the primary attack gMSA mitigates
- [[as-rep-roasting]] — the sibling cracking attack
- [[golden-silver-tickets]] — the Silver Ticket forgery gMSA mitigates
- [[lsass]] — where the cached gMSA key lives (the dump target)
- [[dcsync]], [[ntds-dit]], [[secretsdump]] — the direct "current key" paths
- [[acl-abuse]] — the gMSA-object write/reset path
- [[ad-tiering-and-hardening]] — the broader hardening baseline
