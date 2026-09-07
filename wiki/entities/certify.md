---
title: Certify (Go AD CS attack tool)
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, active-directory, ad-cs, esc, go]
---

# Certify (Go AD CS attack tool)

**Certify** is a **Go** AD CS attack tool — effectively the Go-native sibling
of [[certipy]] (and like Rubeus, by **mholtes**). It enumerates and abuses
the **ESC1–ESC15** certificate-authority misconfigurations in
[[ad-cs-esc-attacks]]: it finds vulnerable CAs/templates, requests certs, and
can **escalate** (e.g. an ESC1 cert for a privileged group → a DA). Output is
the same **`.pfx`/`.kirbi`** cert + ticket format certipy produces, so the two
are interchangeable in a chain.

## What it does

- **`certify find`** — enumerate CAs and templates, **detect** which
  **ESC** vulns are present (the scanner). This is the "which ESC is exploitable
  here" first step.
- **`certify req`** — **request a certificate** from a vulnerable CA/template
  (e.g. an **ESC1** machine/user template), returning a `.pfx`.
- **`certify req` + `-template`/`-msds`** — target a specific vulnerable
  template (the equivalent of certipy's `req -template ...`).
- Produces the **cert → TGT** (Kerberos) or **cert → SAML/NTLM** artifacts you
  then pass to a DA. See [[ad-cs-esc-attacks]].

## Typical invocations

```bash
# Enumerate CAs + detect which ESC vulns are present
certify find -v -u <user> -p '<pass>' -dc <dc>

# Request an ESC1 cert (a vulnerable machine/user template) -> .pfx
certify req -u <user> -p '<pass>' -ca <ca-name> -template <template> -out evil.pfx

# (certipy-equivalent) request + get a TGT from the cert
#   certipy -> gettgtpkinit ; certify -> the cert -> Rubeus asktgt / klist
```
**Verify:** a `.pfx` you can turn into a TGT (Kerberos) or an NTLM auth — the
ESC endgame. See [[path-esc1-template-to-domain-admin]] for the full ESC1 chain.

## Why it's here

- **Go = single static binary** — easy to drop on a Windows/Linux box without
  a Python runtime; a lighter footprint than certipy in some tradecraft.
- **Same model as certipy** — if you know one, you know the other; pick by
  runtime availability. The wiki treats them as the two AD CS tools
  (certipy = Python, certify = Go).
- **Scanner + abuser in one** — `find` (detect) + `req` (abuse) covers the
  whole ESC workflow.

## Detection / notes

- A **certificate request** (a new cert issued from a CA to an unusual
  subject / template) is the primary tell — CAs log `Certify`/`req` as a
  normal **CRL/CA audit** event (a cert issued on a *machine* template by a
  *user*, or on a vulnerable template).
- The **TGT from the cert** (a 4768 from a cert-backed subject) is the
  Kerberos tell. See [[ad-cs-esc-attacks]] detection.

## Links

- [[ad-cs-esc-attacks]] — the ESC1–15 vulns it abuses
- [[certipy]] — the Python twin (same workflow, different runtime)
- [[path-esc1-template-to-domain-admin]] — the ESC1 → DA chain
- [[rubeus]] — the TGT-from-cert step (asktgt)
- [[service-principal-name]] — cert-backed SPN auth
- [[dcsync]] — the domain endgame after ESC
