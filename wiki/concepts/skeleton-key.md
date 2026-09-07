---
title: "Skeleton Key — the LSASS memory patch on a DC"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, persistence, lsass, kerberos, domain-dominance, memory-patch]
---

# Skeleton Key — the LSASS memory patch on a DC

**Skeleton Key** is a domain-dominance **persistence** technique: an attacker
with **DA + `SeDebugPrivilege` on a DC** **patches the DC's LSASS in memory**
so that, in addition to the real account keys, **one attacker-chosen "skeleton
key" is accepted for *any* domain account's Kerberos logon**. Once patched,
the attacker can **forge a Golden Ticket signed with the static skeleton key**
and it will be **accepted on every DC running the patch** — even after the
real `krbtgt` is rotated, because the patch checks the *static* key, not the
live `krbtgt`. See [[ad-persistence]] (hub) and
[[ad-persistence-dcshadow-skeletonkey-adminsdholder]] (source) for the command
set; this page is the dedicated deep-dive.

## How it works

1. **Patch LSASS on a DC** — with `SeDebugPrivilege` (DA) on the DC, the
   attacker attaches to **LSASS** ([[lsass]]) and patches the
   **Kerberos key-verification code path** in memory. The patch inserts a
   check: *if the presented TGT's key matches the attacker's static
   "skeleton key", accept it* (alongside the normal real-key check).
2. **Distribute the patch** — because all DCs run the same LSASS image and an
   attacker with DA can write to every DC, the patch is typically applied to
   **all DCs** (via a GPO push of a patched LSASS module, a PsExec'd
   injection, or a DSRM/`SeDebug` loop). Now every DC in the domain accepts
   the skeleton key.
3. **Forge a Golden Ticket with the static key** — the attacker mints a TGT
   for (say) `Administrator` signed with the **skeleton key** (not the real
   `krbtgt`). Any DC with the patch accepts it → durable DA.

## Why it's a strong persistence

- **Survives `krbtgt` rotation** — the standard Golden-Ticket remediation
  (rotate `krbtgt` x2, [[krbtgt]]) does **not** remove the patch. The patched
  LSASS still accepts the *static* skeleton key. So even "correct" IR
  (krbtgt rotation) leaves the attacker in.
- **Domain-wide** — once on all DCs, the key works everywhere, not just one
  DC.
- **In-memory (non-disk-persistent) by default** — the patch is in LSASS
  memory, so a **DC reboot** reverts it (LSASS reloads from the clean on-disk
  image). That's both its weakness (a reboot kills it) and why it's "easy to
  reapply" while you still have access — and why defenders don't just reboot
  blindly (they need to confirm the on-disk image is clean too).

## The "real" persistence variants

The base Skeleton Key is in-memory and dies on reboot. To make it survive
reboot, the attacker persists the *patch source*:
- **Patch the on-disk LSASS image / a DLL it loads** (so a reboot reloads the
  patched code).
- **A GPO that pushes the patch** at DC startup.
- Combined with [[dcshadow]]/[[ad-persistence]] to re-apply after a reboot or
  DC rebuild.

## Detection

- **LSASS memory scan / integrity check** — compare the in-memory
  Kerberos-verification code path against the known-good on-disk image (a
  **memory-vs-disk LSASS mismatch** on a DC is the tell). Tools like
  `mimilib`/`Goddard`/LSASS-integrity monitors do this.
- **A Golden Ticket that outlives a `krbtgt` rotation** — you rotated
  `krbtgt` (x2) but a DA's TGT *still* works → strong Skeleton Key signal.
- **A TGT whose signing key isn't the current (or previous) `krbtgt`** — a
  key that matches *neither* live krbtgt rotation → the static skeleton key.
- **Non-default LSASS module / unexpected DLL loaded into LSASS** on a DC.
- **A GPO or scheduled task that touches LSASS on all DCs** at startup.

## Remediation

- **Remove the patch** — the reliable way is to **rebuild the DCs from a
  known-clean image** (or confirm + restore the clean on-disk LSASS) and
  **restart LSASS** on each DC (a DC reboot reloads the clean image).
- **Rotate `krbtgt` (x2)** — necessary but *not sufficient* (the static key
  survives); do it *in addition* to removing the patch.
- **Audit for the persistence source** — on-disk LSASS image, startup GPOs,
  scheduled tasks, and any rogue DC/replication partner
  ([[dcshadow]]) that could re-apply.
- Correlate with the broader [[ad-persistence]] cleanup (AdminSDHolder ACL
  audit, DSRM reset).

## Links

- [[ad-persistence]] — the hub (DCShadow / Skeleton Key / AdminSDHolder)
- [[ad-persistence-dcshadow-skeletonkey-adminsdholder]] — the source page (commands)
- [[lsass]] — the process that gets patched
- [[krbtgt]] — the key whose rotation Skeleton Key survives
- [[golden-silver-tickets]] — the Golden Ticket forged with the skeleton key
- [[dcshadow]] — the sibling persistence (rogue replication / shadow DC)
- [[dcsync]] — the "get in" complement (Skeleton Key is the "stay in")
- [[ad-tiering-and-hardening]] — the DC-protection + LSASS-integrity baseline
