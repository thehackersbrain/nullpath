---
title: "Cross-forest AD CS (PKI as an authentication bridge)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, trusts, forest, esc, pkinit]
---

# Cross-forest AD CS

AD CS trust is **separate from** AD domain/forest trust, and that's the danger:
when an enterprise CA's certificates are published into **another forest's**
`NTAuthCertificates` / AIA (a deliberate cross-forest PKI setup), that CA becomes
**trusted to authenticate principals in the other forest** — extending the
authentication boundary *past* the domain/forest trust's SID filtering. If any
template on that CA is ESC-vulnerable, the misconfiguration is now
**cross-forest**: a principal in the trusting forest can mint a certificate that
authenticates as a user in the CA's forest. This is the "adcs-forests"
intersection of [[ad-cs-esc-attacks]] and [[ad-trusts]].

## Why PKI crosses the boundary

- Certificate-based auth ([[pkinit-unpac-the-hash]]) validates that the issuing
  CA chains to a cert in the target's **`NTAuthCertificates`** object
  ([[ntauthcertificates]]) — *not* on domain/forest SID filtering. Publish a
  foreign CA into NTAuth and its certs are honored for logon.
- So the trust that matters for AD CS attacks is **"is this CA in my NTAuth?"**,
  which can be true across a forest trust when admins set up cross-forest
  enrollment (shared PKI, subordinate CAs, or manual NTAuth publication).

## Attack shapes

- **Cross-forest ESC1 (and friends).** A template on forest A's CA that lets
  low-priv principals enroll and supply the subject (SAN) — if forest B trusts
  that CA and B's users can enroll — yields a cert authenticating as an arbitrary
  A user. The ESC1/ESC9/ESC15 mechanics are unchanged ([[esc1]]); the trust just
  makes them reachable from the other forest.
- **ESC8 / ESC11 relay across the trust.** Coerce a machine in forest A
  ([[ntlm-relay-coercion]]) and relay to a CA endpoint reachable across the
  trust — machine cert → authentication in that forest ([[esc8]], [[esc11]]).
- **Shared/subordinate CA hierarchies.** A root CA cross-signed or published into
  both forests means a compromise of the CA (or its key — [[golden-certificate]])
  forges auth in **both** forests.

## Finding it

```bash
# Certipy shows CAs, their NTAuth publication, templates, and cross-forest reach.
certipy find -u user@forestb.local -p pass -dc-ip <dcB> -stdout -vulnerable
# Enroll against the OTHER forest's CA explicitly:
certipy req -u user@forestb.local -p pass -ca 'FORESTA-CA' -template <vuln> \
  -target ca.foresta.local -upn administrator@foresta.local
```

Confirm the CA's cert actually sits in the target forest's `NTAuthCertificates`
([[ntauthcertificates]]) — that publication is the precondition; without it the
foreign cert won't authenticate.

## Red-team notes (OPSEC)

- **NTAuth is the real trust boundary here** — enumerate it in *both* forests
  before assuming a path. Cross-forest AD CS abuse only exists where someone
  deliberately published the CA across; it's a narrower, higher-value finding
  than intra-forest ESC.
- The enrollment/relay footprint is the same as the underlying ESC
  ([[ad-cs-esc-attacks]] detection) — the novelty is the *identity* the cert
  authenticates as sits in another forest, which defenders rarely correlate
  across the trust.

## Detection

- **Enrollment (4886/4887)** on the CA for a principal from a foreign forest, or
  for a SAN/UPN that doesn't match the enrollee.
- Changes to **`NTAuthCertificates`** / cross-forest CA publication — a rare,
  high-signal PKI configuration event to baseline and alert on.
- The relay/coercion tells of [[esc8]] / [[esc11]] where those are the vector.

## Links

- [[ad-cs-esc-attacks]] — the ESC family this makes cross-forest
- [[ntauthcertificates]] — the object whose publication defines the trust
- [[pki-and-ad-cs-architecture]] — CA hierarchy / cross-signing context
- [[ad-trusts]] — the forest trust this rides alongside (but bypasses SID filtering)
- [[esc1]] / [[esc8]] / [[esc11]] — the concrete vectors; [[golden-certificate]] for CA-key forgery
- [[certipy]] — enumeration and cross-forest enrollment
