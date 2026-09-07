---
title: "ADSecurity.org — Sean Metcalf's AD attack & defense research"
type: source
created: 2026-09-07
updated: 2026-09-07
tags: [source, red-team, active-directory, kerberos, reference]
---

# ADSecurity.org (Sean Metcalf)

Sean Metcalf's long-running research site — the canonical early source for
**Kerberos attack** documentation (Golden/Silver tickets, krbtgt, DCSync
mechanics) and matched detection/hardening guidance. Much of the Kerberos-side
detail and event-ID detection across this wiki traces back here.

- **URL**: https://adsecurity.org/ (see the "Mimikatz", "Kerberos", and
  "Attack Defense & Detection" tags).

## Key takeaways

- Definitive write-ups of **Golden** and **Silver** ticket forgery
  ([[golden-silver-tickets]]) and the **krbtgt** double-rotation remediation
  ([[krbtgt]]).
- **DCSync** mechanics and the replication-rights model ([[dcsync]]), plus the
  4662 replication-GUID detection this wiki cites.
- Early, thorough **Kerberos protocol** breakdowns feeding
  [[kerberos-authentication]], [[kerberos-encryption-types]] and the RC4
  downgrade detection signal.
- Detection-forward throughout — a primary reference for the defensive baseline
  in [[ad-tiering-and-hardening]].

## Touches

[[golden-silver-tickets]], [[krbtgt]], [[dcsync]], [[kerberos-authentication]],
[[kerberos-encryption-types]], [[mimikatz]], [[ad-tiering-and-hardening]].
