---
title: "blog.harmj0y.net — Will Schroeder's offensive AD research"
type: source
created: 2026-09-07
updated: 2026-09-07
tags: [source, red-team, active-directory, kerberos, acl, delegation]
---

# blog.harmj0y.net (Will Schroeder)

Will Schroeder's ("harmj0y", [[specterops]]) research blog — the origin of much
of the modern **Kerberoasting**, **Kerberos delegation**, and **ACL-abuse**
tradecraft, and of **PowerView** / **PowerUp**. A primary source behind this
wiki's credential-access and object-control pages.

- **URL**: https://blog.harmj0y.net/ (and the PowerView/PowerSploit docs).

## Key takeaways

- Popularised **Kerberoasting** as a practical technique and the SPN-write
  "targeted Kerberoast" ([[kerberoasting]], [[acl-abuse]]).
- Deep **delegation** analysis (unconstrained/constrained/RBCD and the S4U
  flow) feeding [[kerberos-delegation]],
  [[resource-based-constrained-delegation]] and [[s4u2self-s4u2proxy]].
- **ACL/DACL abuse** methodology and the [[bloodhound]] edge model
  ([[acl-abuse]]); authored **PowerView** for the enumeration behind it.
- "Do I have any [privileged] rights?" object-control framing that underlies
  the [[acl-abuse]] page and much of [[gpo-abuse]].

## Touches

[[kerberoasting]], [[kerberos-delegation]],
[[resource-based-constrained-delegation]], [[s4u2self-s4u2proxy]],
[[acl-abuse]], [[gpo-abuse]], [[bloodhound]], [[powerview]], [[specterops]].
