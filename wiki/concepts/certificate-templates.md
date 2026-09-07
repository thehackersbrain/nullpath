---
title: "Certificate Templates (the ESC1-4 surface)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, pki, templates]
---

# Certificate Templates

A **certificate template** is the AD object (`CN=<name>,CN=Certificate
Templates,CN=Public Key Services,CN=Services,CN=Configuration,...`) that
defines how a cert is issued. The four attacker-relevant knobs:

- **EKUs** (`pKIExtendedKeyUsage`) — does the cert allow **Client
  Authentication** (`1.3.6.1.5.5.7.3.2`), **Smart Card Logon**, **Any
  Purpose**, or **Certificate Request Agent**? Client-auth-capable is what
  enables PKINIT logon.
- **Subject** — `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`: does the **requester
  supply the SAN**? If yes, they can request a cert *for anyone* → [[esc1]].
- **Enrollment rights** — the template DACL: which principals may enroll.
  Low-priv enroll + a dangerous EKU/subject = escalation.
- **Manager approval / authorized signatures** — issuance guardrails; when
  absent, enrollment is instant.

## Abuse map

| Misconfig | ESC |
| --- | --- |
| Enrollee-supplied SAN + client-auth EKU + low-priv enroll | [[esc1]] |
| Any Purpose / no EKU | [[esc2]] |
| Certificate Request Agent EKU | [[esc3]] |
| Writable template DACL (reconfigure to ESC1) | [[esc4]] |
| No `szOID_NTDS_CA_SECURITY_EXT` (no SID binding) | [[esc9]] |

## Red-team notes (OPSEC)

- `certipy find -vulnerable -stdout` classifies every template offline; act on
  the single one that applies rather than enrolling broadly.
- ESC4 reconfiguration writes the template object — **5136** fires; flip it,
  enroll, flip it back.

## Links

- [[pki-and-ad-cs-architecture]], [[ad-cs-esc-attacks]]
- [[certificate-mapping]] — how the issued cert maps back to an account
- [[certified-pre-owned]], [[certipy]]
