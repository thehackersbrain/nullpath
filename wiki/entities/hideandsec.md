---
title: hideandsec.sh
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [organization, reference, active-directory, shadow-credentials, pki]
---

# hideandsec.sh

**hideandsec.sh** is a (French) security research blog known for deep AD / PKI
attack research — most notably the **Shadow Credentials** work
(`msDS-KeyCredentialLink` key-trust abuse) that this wiki's
[[shadow-credentials]] and [[pkinit-unpac-the-hash]] pages are built on, plus
PKINIT and Kerberos pre-auth research.

## Key contributions referenced in this wiki

- **Shadow Credentials** — the `msDS-KeyCredentialLink` plant → PKINIT → NT
  hash recovery technique ([[shadow-credentials]], [[whisker]]).
- **PKINIT / UnPAC the hash** — certificate-based Kerberos pre-auth and
  `PAC_CREDENTIAL_INFO` NT-hash recovery ([[pkinit-unpac-the-hash]],
  [[kerberos-pac]]).
- **Kerberos / PKI** research feeding [[kerberos-preauth]] and
  [[kerberos-authentication]].

## Why it matters for this wiki

- It is the **technique source** for the shadow-credential / PKINIT attack
  family — the "plant a cert, become the account, read their hash" play.

## Links

- [[shadow-credentials]] — the technique it originated
- [[pkinit-unpac-the-hash]] — the NT-hash recovery it detailed
- [[whisker]] — the tooling that implements it
- [[kerberos-pac]] — the PAC_CREDENTIAL_INFO it reads
- [[kerberos-preauth]] — the PKINIT pre-auth context
- [[certipy]] — the related AD CS cert tooling

## References

- [hideandsec.sh](https://hideandsec.sh/)
- [hideandsec: Kerberos shadow credentials](https://hideandsec.sh/2021-05-27-kerberos-shadow-credentials.html)
