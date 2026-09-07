---
title: "Golden Certificate (CA-key forgery / rogue CA in NTAuth)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, pki, persistence, kerberos]
---

# Golden Certificate

The **certificate analog of the golden ticket**: a client-auth certificate
that authenticates as a high-value account (a DC machine account, a DA, or
`krbtgt` itself) because the issuing CA is — or has been made — trusted
forest-wide. Two routes:

1. **CA key compromise** — you hold the CA's private key (CA server box,
   [[esc12]]-class findings, HSM misconfig) and **forge** a cert for any
   subject with **ForgeCert**. No enrollment, no CA interaction.
2. **Rogue CA in the trust store** — you add **your own CA cert** to
   [[ntauthcertificates]] (Enterprise-Admin-class write), then issue certs
   from your CA for any account. The forest trusts *your* CA for PKINIT
   ([[kerberos-authentication]]) as if it were the real one.

## Exploit

```bash
# Route 1: you have the CA cert + key -> forge a cert for krbtgt / a DA
ForgeCert.exe -target <DA_UPN> -caCert ca.crt -caKey ca.key   # then PKINIT with it

# Route 2: rogue CA in NTAuth (EA write on CN=NTAuthCertificates) ->
# issue from your CA as normal (certipy req against your CA), then:
certipy auth -pfx krbtgt.pfx -dc-ip <DC_IP>
# or on Windows:
Rubeus.exe asktgt /user:krbtgt@corp.local /certificate:<B64_PFX> /ptt
```

Once the PKINIT TGT is in hand you're at the same plateau as
[[golden-silver-tickets]]: DCSync, TGT forgery, persistence.

## Golden cert vs golden ticket

| | Golden ticket | Golden certificate |
|---|---|---|
| Needs | krbtgt **hash** | CA **key** or NTAuth **write** |
| Ticket | forged **offline** (no KDC) | **KDC-minted** TGT via PKINIT (4768) |
| Survives | krbtgt reset (until re-forge) | password reset + krbtgt rotation (to expiry) |
| Killed by | krbtgt reset | **cert revocation / CRL**, removing your CA from NTAuth |
| Tell | 4769 *without* a 4768, unusual lifetime | 4768 **PKINIT** from an unusual source / unknown issuer |

## Red-team notes (OPSEC)

- **The cert is your persistent secret** — it outlives password resets and
  krbtgt rotations, which makes it the *stickiest* domain-dominance artifact
  there is; store it before you do anything else.
- **Route 2 is the persistence play** — the NTAuth write is loud (5136 on
  `CN=NTAuthCertificates`), but once it's in, every TGT you mint looks like a
  normal PKINIT logon.
- **Kill-switch awareness** — a defender who finds the cert can revoke it /
  CRL it; that's also your cleanup path (revoke + remove CA from NTAuth).

## Detection

- **4768 with PKINIT pre-auth** where the cert's issuer isn't a known-good CA
  (or the subject is `krbtgt`/a DC machine account that never logs in with
  certs).
- **5136** on `CN=NTAuthCertificates` — a new CA cert object appearing.
- **CRL/OCSP anomalies** — certs revoked in a burst; OCSP queries failing.
- CA-side: **4886/4887** for machine/krbtgt subjects on a CA that rarely
  issues them.

## Mitigations

- Protect the CA key (HSM, no key export) — route 1 is dead without it.
- **ACL the NTAuthCertificates object**; alert on 5136 (route 2).
- Constrain which CAs can issue **machine/krbtgt** certs; use CRL/OCSP
  checking (the cert *revocation* path is your escape hatch).
- See [[ad-persistence]] — golden certs sit alongside DCShadow/Skeleton Key
  as a durable domain-dominance foothold.

## Links

- [[ntauthcertificates]] — the trust store route 2 writes
- [[pki-and-ad-cs-architecture]] — where CAs/keys live
- [[golden-silver-tickets]] — the Kerberos-forgery analog
- [[pkinit-unpac-the-hash]] — what a cert buys you (PKINIT TGT, UnPAC)
- [[ad-persistence]] — the persistence family this belongs to
- [[esc12]] — the CA-key-compromise condition
- [[certified-pre-owned]]
