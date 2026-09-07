---
title: SpecterOps
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [organization, red-team, active-directory, bloodhound, ad-cs]
---

# SpecterOps

**SpecterOps** is a red-team firm and a primary source for AD offensive
technique development and the tooling this wiki relies on. They created
**[[bloodhound]]** (and SharpHound), defined the **AD CS ESC1-15** numbering
used throughout [[ad-cs-esc-attacks]], and published the research behind
**[[diamond-ticket]]**, **[[honeytokens]]**, and numerous ACL / delegation /
trust attacks. Their blog (posts.specterops.io) is a canonical reference.

## Key contributions referenced in this wiki

- **BloodHound / SharpHound** — the AD attack-path graph
  ([[bloodhound]]).
- **AD CS ESC1-15** — the "Certified Pre-Owned" research and the ESC
  numbering ([[ad-cs-esc-attacks]]).
- **The Diamond Ticket** — the AES128-downgrade Golden Ticket
  ([[diamond-ticket]]).
- **Honeytokens for AD** — the canary detection patterns
  ([[honeytokens]]).
- **Access Control Attack Patterns** — the object-control / ACL abuse
  framework ([[acl-abuse]]).
- Numerous delegation / trust / Kerberos write-ups feeding
  [[kerberos-delegation-abuse]], [[ad-trust-attacks]],
  [[s4u2self-s4u2proxy]].

## Why they matter for this wiki

- They are the **naming + research source** for a large share of the
  techniques and tools here — the ESC numbering, BloodHound edges, and the
  Diamond Ticket all trace to them.

## Links

- [[bloodhound]] — their flagship tool
- [[ad-cs-esc-attacks]] — the ESC1-15 they defined
- [[diamond-ticket]] — their research
- [[honeytokens]] — their detection patterns
- [[acl-abuse]] — their access-control framework

## References

- [SpecterOps blog](https://posts.specterops.io/)
- [BloodHound (SpecterOps)](https://www.bloodhound.readthedocs.io/)
- [Certified Pre-Owned (AD CS)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
