---
title: "ADFS Device & Computer Authentication"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [ad, adfs, device, computer, machine, mfa, red-team]
---

# ADFS Device & Computer Authentication

**Authenticating to ADFS as a *machine* or *device* instead of a user.** ADFS
accepts non-user identities: **machine accounts** (via Kerberos/NTLM) and **device
certificates** (via PKINIT). Because device/computer logon is treated as
pre-trusted, it is often **MFA-exempt** — so a machine hash or device cert you
already hold from elsewhere in the engagement becomes an ADFS login to federated
apps. It's the "reuse an identity you already own" path into the federation.

This is the direct sibling of [[shadow-credentials]] and [[service-account]]
abuse: the same machine/device identity, pointed at ADFS instead of a local box.

## The mechanics

### Machine-account ADFS auth

A machine account (`COMPUTER$`) holds a **Kerberos key** (its password). ADFS can
authenticate a machine account over **Kerberos or NTLM**:

```
machine account key (you already hold it — hash, dcsync, gMSA, ...)
  → authenticate to ADFS as COMPUTER$ (Kerberos/NTLM)
  → ADFS issues a token for the RPTs that accept machine auth
  → (MFA-exempt) present token to the federated app
```

The prerequisite is a Relying Party Trust that **allows Kerberos/NTLM auth** —
enumerate the RPTs first ([[adfs]]). If the RPT accepts machine auth, your
machine key is a ready-made login.

### Device-certificate ADFS auth (PKINIT)

A **registered device** holds a **device certificate** (often issued via AD CS /
Intune). ADFS authenticates the device over **PKINIT** (certificate-based
Kerberos):

```
device cert (you already hold it — stolen, forged, ESC template, ...)
  → PKINIT to ADFS as the device
  → ADFS issues a token for the RPTs that accept device/cert auth
  → (MFA-exempt, registered devices are trusted)
```

This reuses the entire [[shadow-credentials]] / [[pkinit-unpac-the-hash]] cert
playbook — the device cert you plant, steal, or mint becomes an ADFS identity.

### Device registration / MDM

ADFS integrates with device management (Intune/MDM). A **registered, trusted
device** can obtain **MFA-exempt** or device-code-based auth. A device you control
that's registered in the tenant is a standing, MFA-free ADFS path.

## Why it's high-value

- **MFA-exempt by design** — device/computer auth is pre-trusted, so no second
  factor. Defeats MFA without a vuln (contrast [[adfs-mfa-bypass]]).
- **Identity reuse** — you don't need a new credential; the machine hash or
  device cert you *already* have from the domain is the login.
- **Quiet** — a machine/device auth to ADFS looks like routine device logon, not
  a user typing a password; lower signal than an interactive MFA bypass.

## Tooling

- **Manual Kerberos/NTLM to the ADFS WS-Trust / Kerberos endpoint** — present the
  machine key; the quietest.
- **PKINIT** via a client stack (`kinit` with the device cert, or a small
  Kerberos client) — the device-cert path.
- **Impacket / Rubeus** — the Kerberos primitives for the machine-key path
  ([[impacket]], [[rubeus]]).

## Red-team notes (OPSEC)

- **RPT auth-type check first** — the machine/device path only works if the target
  RPT *accepts* Kerberos/NTLM/cert auth. Enumerate the RPTs ([[adfs]]) and pick
  the one that does; don't spray a machine key at an RPT that only takes forms+MFA.
- **Prefer the identity you already hold** — if the engagement already handed you a
  machine account (Tier 0 or not) or a device cert, that's the cheapest ADFS login.
  Reuse before you mint.
- **A Tier 0 machine account is the jackpot** — a DC or privileged machine account
  authenticating to ADFS often lands in the most-trusted RPTs. Map which RPTs a
  machine auth reaches before you commit.
- **Device certs are durable** — a planted device cert (via [[shadow-credentials]]
  or an [[ad-cs-esc-attacks|ESC]] template) is a *standing* MFA-free ADFS path,
  not a one-shot. Weigh that persistence against the footprint.

## Detection

- **ADFS auth by a machine account or device** — event 25/125 where the subject is
  a `COMPUTER$` or a device principal, not a user.
- **PKINIT to ADFS** — a certificate-based Kerberos logon (4768 pre-auth type 12)
  landing on the ADFS path, from a device cert.
- **MFA-exempt device logon** — ADFS success for a device with no MFA challenge
  (event 368 with no preceding MFA).
- **The cross-domain tell** — a machine account / device cert that was used for a
  *local* action (service, WMI) also authenticating to *ADFS* shortly after (the
  identity-reuse correlation).
- **New/abnormal device cert** — a device cert that just appeared (planted)
  authenticating to ADFS (the [[shadow-credentials]] tell).

## Links

- [[adfs]] — the hub (RPT enumeration, the attack-surface map)
- [[adfs-mfa-bypass]] — the vuln-based MFA bypass (this is the by-design one)
- [[adfs-preauth]] — the Kerberos pre-auth surface this drives
- [[shadow-credentials]] — the device/user cert this reuses
- [[pkinit-unpac-the-hash]] — the PKINIT path the device-cert auth uses
- [[service-account]] — the machine accounts ADFS accepts
- [[ntauthcertificates]] — the device certs that authenticate to ADFS
- [[pki-and-ad-cs-architecture]] — the cert infra behind the device path
