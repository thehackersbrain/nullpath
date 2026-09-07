---
title: "Kerberos Armoring (FAST) — the pre-auth hardening"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, active-directory, hardening, fast, preauth, detection]
---

# Kerberos Armoring (FAST)

**FAST** (Flexible Authentication Secure Tunneling, RFC 6113) — "**Kerberos
armoring**" in AD — wraps the AS and TGS exchanges in an **armored channel**
keyed by the machine's TGT, so the sensitive pre-authentication data is no longer
exposed in a form an attacker can grind offline. It's the defensive counterpart
to the roasting family: where it's **enforced**, the cheap offline attacks on the
AS exchange stop working. Knowing its scope tells you which roasts still work and
where a downgrade is possible.

## What it actually protects (and what it doesn't)

- **Protects the AS exchange.** The pre-auth timestamp and the AS-REP are
  encrypted inside the armor, which:
  - **Kills [[as-rep-roasting]]** for armored clients — the AS-REP's crackable
    blob is no longer exposed.
  - **Blunts password brute-force** of the AS-REQ pre-auth (no offline timestamp
    to attack).
- **Does *not* by itself stop [[kerberoasting]].** A TGS is still encrypted with
  the *service account's* key, so a Kerberoast remains an offline crack of that
  key — **[[gmsa]] / strong service passwords** are the Kerberoast mitigation,
  not FAST.
- **Does not stop [[timeroasting]]** — that abuses MS-SNTP (NTP), a different
  protocol entirely, outside the Kerberos armor.
- Enables **compound identity / claims** (Dynamic Access Control): "user X on
  device Y," which some access decisions rely on.

## Enabling / enforcing it

Two GPO settings, and it only holds when **all DCs** and the **clients** support
it:

- **DC side** — *"KDC support for claims, compound authentication and Kerberos
  armoring"* → **Supported** or, to force it, **"Fail unarmored authentication
  requests"** (enforcement).
- **Client side** — *"Kerberos client support for claims, compound
  authentication and Kerberos armoring"* → **Enabled**.

Until it's in **enforcement** mode, unarmored requests are still answered.

## Attack relevance (the downgrade)

- **Not enforced = still roastable.** If FAST is merely *supported* (not "fail
  unarmored"), an attacker simply sends an **unarmored AS-REQ** and gets the
  roastable AS-REP anyway — the classic "armoring configured but not enforced"
  gap. Check for enforcement, not just presence.
- **Legacy clients** that don't speak FAST fall back to unarmored — a mixed
  estate leaves a soft spot.
- **RC4 still hurts** — armoring is orthogonal to enctype; disable RC4 too
  ([[kerberos-encryption-types]]).
- FAST is part of what **Protected Users** membership pulls in (AES-only, no
  delegation, shorter TGT) — the account-level hardening that pairs with it.

## Detection / hardening posture

- **Audit for unarmored AS-REQs** once armoring is meant to be enforced — an
  unarmored request in an armored domain is either legacy or an attacker
  downgrading to roast.
- Roll armoring to **enforcement** ("fail unarmored"), disable **RC4**, and put
  Tier-0 / high-value accounts in **Protected Users** ([[ad-tiering-and-hardening]]).
- Remember the residual gaps: Kerberoasting ([[gmsa]]) and Timeroasting
  ([[timeroasting]]) are *not* covered by armoring — mitigate those separately.

## Links

- [[as-rep-roasting]] — the attack FAST enforcement actually kills
- [[kerberoasting]] / [[gmsa]] — the roast FAST does *not* stop (use gMSA)
- [[timeroasting]] — the NTP-based roast outside the armor
- [[kerberos-preauth]] — the pre-auth exchange being armored
- [[kerberos-encryption-types]] — disable RC4 alongside armoring
- [[ad-tiering-and-hardening]] — where armoring fits the baseline (Protected Users)
