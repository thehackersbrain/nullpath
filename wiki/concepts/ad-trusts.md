---
title: "AD trusts (types, direction, transitivity, SID filtering)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, trusts, forest, sid-filtering, fundamentals]
---

# AD trusts

A **trust** lets principals in one domain authenticate to resources in another.
Understanding the *shape* of a trust — its **type**, **direction**,
**transitivity**, and whether **SID filtering** is applied — is what tells you
whether a compromise in one domain reaches another, and how. The single most
important consequence, drilled into every trust attack: **within a forest the
forest is the security boundary, not the domain** — own any domain and you own
the forest. This page is the fundamentals hub for [[trust-key-abuse]],
[[ad-trust-attacks]], [[foreign-security-principals]], [[cross-forest-adcs]] and
[[sid-history]].

## Trust types

| Type | Created | Transitive | Boundary | SID filtering (default) |
|---|---|---|---|---|
| **Parent-child** | automatic (new child domain) | yes | intra-forest | **off** (full trust) |
| **Tree-root** | automatic (new tree in forest) | yes | intra-forest | **off** |
| **Shortcut** | manual (optimize intra-forest auth) | yes | intra-forest | off |
| **External** | manual (domain ↔ domain, different forests) | **no** | inter-forest | **on** (quarantine) |
| **Forest** | manual (forest root ↔ forest root) | yes (within each forest) | inter-forest | **on** (honors trusted forest's own SIDs) |
| **Realm** | manual (to a non-Windows Kerberos realm) | configurable | external | n/a |

The split that matters: **intra-forest trusts do not filter SIDs** (SID history
is honored), so a forged PAC with a privileged SID from *another* domain in the
same forest is accepted. **Inter-forest trusts filter** foreign privileged SIDs
by default — which is why cross-forest attacks are harder and lean on foreign
principals, delegation, PKI, or a SID-filtering weakness ([[ad-trust-attacks]]).

## Direction vs. access (they're opposite)

Trust **direction** is the reverse of **access** direction. If domain A
*trusts* B (A is trusting, B is trusted; a one-way *incoming* trust on A), then
**B's users can access A's resources**, not the other way around. Two-way trusts
are just two one-way trusts. When enumerating, read it as "who can reach *into*
this domain."

## The trust key (the forgeable secret)

Each trust is backed by a **Trusted Domain Object (TDO)** holding a shared
**trust key** — a password on an inter-domain trust account named
`<TRUSTED_DOMAIN>$`. When you authenticate across a trust, your home KDC issues
an **inter-realm referral TGT encrypted with the trust key**, which the target
KDC accepts. Hold that key (DCSync the trust account) and you can **forge
inter-realm tickets** directly — see [[trust-key-abuse]].

`trustAttributes` flags shape behavior: `WITHIN_FOREST`, `FOREST_TRANSITIVE`,
`QUARANTINED_DOMAIN` (SID filtering on external), and `TREAT_AS_EXTERNAL`
(0x40) — the last of which weakens forest-trust filtering and is central to
[[ad-trust-attacks]] / CVE-2020-0665.

## Enumeration

```bash
nltest /domain_trusts /all_trusts                 # native, on-host
Get-ADTrust -Filter *                             # RSAT
Get-DomainTrust ; Get-ForestTrust                 # PowerView
nxc ldap dc01 -u user -p pass -M enum_trusts      # remote ([[ad-enumeration]])
# BloodHound models trusts as edges — the cleanest way to see cross-domain paths
```

Read from each TDO: the **other domain**, the **direction**, **transitive?**,
and `trustAttributes` (is it within-forest? quarantined? TREAT_AS_EXTERNAL?).

## Why attackers care

- **Intra-forest (child ↔ root):** the domain is *not* a boundary. A child DA →
  forest-root **Enterprise Admin** via SID-history injection or the trust key
  ([[trust-key-abuse]], [[sid-history]]). `raiseChild.py` automates it.
- **Inter-forest:** SID filtering blocks the easy PAC forge, so you pivot via
  **foreign group membership** ([[foreign-security-principals]]),
  **unconstrained delegation** coercion across the trust, **AD CS** cross-forest
  enrollment ([[cross-forest-adcs]]), **password reuse**, or a filtering
  weakness ([[ad-trust-attacks]]).

## See also

- [[trust-key-abuse]] — forging inter-realm TGTs / child→parent EA
- [[ad-trust-attacks]] — SID filtering weaknesses, TREAT_AS_EXTERNAL, CVE-2020-0665
- [[foreign-security-principals]] — cross-trust group membership abuse
- [[cross-forest-adcs]] — PKI as a cross-forest authentication bridge
- [[sid-history]] — the SID-history mechanism trusts honor (or filter)
- [[krbtgt]] / [[golden-silver-tickets]] — the forgery primitives trusts extend
