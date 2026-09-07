---
title: "PKI & AD CS Architecture (CA, templates, enrollment)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, pki, fundamentals]
---

# PKI & AD CS Architecture

The moving parts an attacker reasons over before touching
[[ad-cs-esc-attacks]]: what issues certificates, what governs *who* gets
*what*, and where trust is anchored.

## The components

- **Enterprise CA** — a Windows CA integrated with AD; issues certs based on
  **templates**. Its computer object and the CA host are high-value.
- **Certificate templates** — the blueprints that decide the EKUs, who may
  enroll, whether the requester supplies the subject, and issuance
  requirements. See [[certificate-templates]] — misconfigured templates are
  the ESC1-4/ESC9 surface.
- **NTAuthCertificates** — the forest store of CA certs trusted to issue
  **client-authentication** certs for AD logon. See [[ntauthcertificates]];
  a rogue CA cert added here is domain-wide forgery ([[golden-certificate]]).
- **Enrollment interfaces** — Web Enrollment (`/certsrv/`, the ESC8 surface),
  the RPC endpoint ICPR (ESC11), and DCOM. All accept AD authentication and
  are relay targets ([[ntlm-relay-coercion]]).

## Why it's an attack surface

A cert that carries a **client-authentication EKU** and a **subject/SAN the
attacker controls** is a login as that subject via **PKINIT**
([[kerberos-authentication]], [[pkinit-unpac-the-hash]]). Every ESC is a
different way to obtain exactly that. The mapping from cert → account is
governed by [[certificate-mapping]] (the ESC9/ESC10 surface).

## Red-team notes (OPSEC)

- **Enumerate offline first** — `certipy find -vulnerable` maps CAs, templates,
  NTAuth, and flags every ESC from LDAP without enrolling anything.
- **Certs are durable** — valid to expiry through password resets; the tradeoff
  is CA-side issuance logging (see [[kerberos-event-ids]] / AD CS 4886/4887).

## Links

- [[ad-cs-esc-attacks]] — the ESC hub
- [[certificate-templates]], [[ntauthcertificates]], [[certificate-mapping]]
- [[certified-pre-owned]] — the source (SpecterOps whitepaper)
- [[certipy]] — enumeration + exploitation
