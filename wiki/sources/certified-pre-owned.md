---
title: "Certified Pre-Owned — Abusing Active Directory Certificate Services (SpecterOps)"
type: source
created: 2026-09-07
updated: 2026-09-07
tags: [source, red-team, ad-cs, pki, esc, specterops]
---

# Certified Pre-Owned (SpecterOps)

The foundational AD CS attack whitepaper by **Will Schroeder** and **Lee
Christensen** ([[specterops]], 2021) that defined the **ESC1–ESC8** escalation
taxonomy the whole industry now uses. It's the canonical source behind this
wiki's [[ad-cs-esc-attacks]] page and the tooling (Certify → [[certify]],
later Certipy → [[certipy]]).

- **URL**: https://posts.specterops.io/certified-pre-owned-d95910965cd2 (blog);
  full PDF whitepaper linked from the post.

## Key takeaways

- Certificates are a **durable authentication credential**: a minted cert
  authenticates via **PKINIT** and survives password resets — the persistence
  angle in [[ad-cs-esc-attacks]] and [[pass-the-cert]].
- Introduced the **ESC** numbering: misconfigured templates (ESC1–3),
  vulnerable CA/ACLs (ESC4–7), and **NTLM relay to web enrollment** (ESC8) —
  the last chains with [[ntlm-relay-coercion]] into [[esc8-ntlm-relay-adcs]].
- Established **UnPAC-the-hash** as a follow-on ([[pkinit-unpac-the-hash]]):
  turn a cert into the account's NT hash directly.
- The theft/persistence categories (THEFT/PERSIST) underpin the AD CS section
  of the defensive baseline in [[ad-tiering-and-hardening]].

## Touches

[[ad-cs-esc-attacks]], [[esc8-ntlm-relay-adcs]], [[pass-the-cert]],
[[pkinit-unpac-the-hash]], [[shadow-credentials]], [[specterops]], [[certify]],
[[certipy]].
