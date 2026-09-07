---
title: AD Trust Attacks (SID Filtering & Forest Boundaries)
type: concept
created: 2026-06-13
updated: 2026-09-07
tags: [active-directory, trusts, lateral-movement, privilege-escalation]
---

# AD Trust Attacks (SID Filtering & Forest Boundaries)

The **domain is not a security boundary in AD — the forest is.** Trusts
within a forest (parent/child, etc.) offer essentially no protection once
any domain in the forest is compromised. Trusts *between forests* are
meant to be a real boundary, and **SID filtering** is the enforcement
mechanism. See [[ad-forest-trust-attacks]] (source) for full detail.

## SID filtering basics

- Cross-forest trust: SIDs from the source forest are filtered when
  crossing — forest-specific SIDs (Domain/Enterprise Admins, RID 500-1000),
  non-existent-domain SIDs, anything not from the source forest, are
  stripped from the PAC.
- "ResourceGroup" PAC entries (domain-local groups from the destination
  forest) are the only cross-forest group memberships normally allowed.

## How filtering gets weakened

- **SID history enabled across the trust** (`netdom trust
  /enablesidhistory:yes`) sets `TREAT_AS_EXTERNAL`, dropping filtering to
  external-trust level. An attacker controlling the source forest can then
  spoof any group SID with RID > 1000 — i.e. forge a [[golden-silver-tickets|
  Golden Ticket]] with arbitrary group memberships in the trusting forest.

## Transitivity bypass — CVE-2020-0665

Even *without* SID history, the trusting forest's DC periodically refreshes
its set of "allowed" SIDs from `msDS-TrustForestTrustInfo` via
`NetrGetForestTrustInformation`. CVE-2020-0665 abused this: an attacker
fully controlling Forest A could hook `lsass.exe`'s processing of that RPC
call (Frida + `RtlLengthSid`) to insert a *local SAM SID* (e.g. RID 500 on
a Forest B member server) into Forest A's trusted-SID set. After Forest B's
~24h refresh, a forged ticket containing that local-admin SID is accepted
on the Forest B member server.

- Only member servers/workstations affected (DC local SAM only active in
  DSRM).
- Patched Feb 2020 — post-patch hosts reject Kerberos service tickets
  carrying SIDs local to their own domain (Event ID 4675).

## Relation to other techniques

- This is fundamentally a [[golden-silver-tickets|forged ticket]] technique
  applied across a trust boundary — same forgery mechanics, different SID
  validation context.
- Compromise of [[krbtgt]] in one forest + a weak/legacy trust into another
  forest is a classic "second forest" pivot.

## Detection

- Event ID 4675 for filtered-SID rejections (post CVE-2020-0665 patch).
- Audit any trust with SID history enabled — flag as high-risk.
- Monitor `NetrGetForestTrustInformation` calls and
  `msDS-TrustForestTrustInfo` changes.

## See also

- [[cve-2020-0665]] — the forest trust transitivity bypass detailed above
- [[path-cross-forest-trust-pivot]] — the end-to-end cross-forest chain
