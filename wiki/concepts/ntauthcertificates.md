---
title: "NTAuthCertificates (the forest client-auth trust store)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, pki, trust]
---

# NTAuthCertificates

`NTAuthCertificates` is the AD object
(`CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,
DC=...`) holding the set of **CA certificates trusted to issue
client-authentication certificates for AD logon**. If a CA's cert is in this
store, certs it issues can be used for **PKINIT** ([[kerberos-authentication]]).

## Why it matters

- It is the **trust anchor** for cert-based logon forest-wide. Every ESC that
  ends in "authenticate with the cert" implicitly relies on the issuing CA
  being in NTAuth.
- **Writing to it is domain dominance.** An attacker who can add their **own
  CA certificate** here can then forge/issue arbitrary client-auth certs for
  any account and log in as them — the [[golden-certificate]] persistence
  technique. Write access requires Enterprise Admin-equivalent, so this is a
  post-dominance persistence primitive, not an entry point.

## Enumeration

```bash
certipy find -stdout           # lists CAs and NTAuth trust
# LDAP: read cACertificate on the NTAuthCertificates object
```

## Red-team notes (OPSEC)

- Adding a CA cert to NTAuth is loud and durable — it survives krbtgt rotation
  and password resets, but the object write (5136) and a new, unknown CA in
  NTAuth are high-fidelity tells.
- Removing a legit CA from NTAuth is a **DoS on cert logon** — don't, unless
  the engagement explicitly tests it.

## Links

- [[pki-and-ad-cs-architecture]], [[ad-cs-esc-attacks]]
- [[golden-certificate]] — forging certs once you can trust your own CA
- [[certified-pre-owned]]
