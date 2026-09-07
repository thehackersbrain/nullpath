---
title: ired.team
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [organization, reference, active-directory, offensive, defensive]
---

# ired.team

**ired.team** is a comprehensive, actively maintained **AD attack + defense
knowledge base** (offensive experiments + detection/mitigation). It is one of
the two primary reference sites cited across this wiki (alongside
[[internalallthethings]]) for the concrete commands, event IDs, and
detection logic on nearly every technique page.

## Coverage referenced in this wiki

- **Kerberos attacks** — [[kerberoasting]], [[as-rep-roasting]],
  [[golden-silver-tickets]], [[pass-the-key|PtK]], [[diamond-ticket]],
  [[s4u2self-s4u2proxy]], [[kerberos-preauth]], [[kerberos-pac]].
- **NTLM relay / coercion** — [[ntlm-relay-coercion]], [[esc8-ntlm-relay-adcs]],
  [[rbcd-via-ntlm-relay]], [[krbrelay]].
- **AD CS** — [[ad-cs-esc-attacks]], ESC1-15 detail.
- **ACL / object control** — [[acl-abuse]].
- **Credential dumping** — [[lsass]], [[sam-database]], [[ntds-dit]],
  [[dcsync]].
- **Delegation / trusts** — [[kerberos-delegation-abuse]],
  [[ad-trust-attacks]], [[sid-history]].

## Why it matters for this wiki

- It is the **command + detection reference** behind the `## Commands` and
  `## Detection` sections on most pages — the "run this, look for that event"
  layer.
- Pairs with [[internalallthethings]] as the two go-to AD references.

## Links

- [[kerberos-authentication]] — the protocol hub it documents
- [[ad-cs-esc-attacks]] — the AD CS reference
- [[ntlm-relay-coercion]] — the relay reference
- [[lsass]] / [[ntds-dit]] / [[sam-database]] — the dumping references
- [[internalallthethings]] — the companion reference

## References

- [ired.team](https://www.ired.team/)
- [ired.team: AD Kerberos abuse](https://www.ired.team/active-directory-kerberos-abuse/)
