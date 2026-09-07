---
title: Kerberos Authentication (AD)
type: concept
created: 2026-06-12
updated: 2026-09-07
tags: [kerberos, active-directory, protocol, hub]
---

# Kerberos Authentication (AD)

The default authentication protocol in Active Directory, and the **hub** for
every Kerberos attack in this wiki. Almost every technique here abuses one stage
of this flow, one ticket, or one key — this page maps them all to where they
hook in. For the ticket internals see [[tgt-tgs]], [[kerberos-pac]],
[[kerberos-preauth]], [[kerberos-encryption-types]]; for where tickets live see
[[ccache]] and [[ticket-and-credential-opsec]].

## Core flow

1. **AS-REQ / AS-REP** — the client pre-authenticates ([[kerberos-preauth]]) to
   the **KDC** (on the DC) and receives a **TGT**, encrypted with the
   **`krbtgt`** key ([[krbtgt]]) and carrying the client's **PAC**
   ([[kerberos-pac]]).
2. **TGS-REQ / TGS-REP** — the client presents the TGT to request a **service
   ticket (TGS)** for a target **SPN** ([[service-principal-name]]). The TGS is
   encrypted with the **target service account's** key.
3. **AP-REQ** — the client presents the TGS to the service, which decrypts it
   with its own key. Delegation ([[kerberos-delegation]]) rides on top via
   **S4U2self / S4U2proxy** ([[s4u2self-s4u2proxy]]).

The full ticket model (TGT vs TGS, which key signs which, which attack hits
which) is [[tgt-tgs]].

## The Kerberos attack map

### Roasting (offline-crack a key exposed by the protocol)

| Attack | What you crack | Page |
|---|---|---|
| **Kerberoasting** | a TGS encrypted with a **service account** key | [[kerberoasting]] |
| **AS-REP Roasting** | an AS-REP for a **preauth-disabled** user | [[as-rep-roasting]] |
| **Targeted roasting** | a victim you *make* roastable via an ACL write (SPN / UAC bit) | [[targeted-roasting]] |
| **Timeroasting** | a **computer** account password via MS-SNTP, unauthenticated | [[timeroasting]] |

### Ticket & PAC forgery (build a ticket from a secret or a flaw)

| Attack | Secret / flaw | Page |
|---|---|---|
| **Golden Ticket** | forge a TGT with the `krbtgt` key | [[golden-silver-tickets]] |
| **Silver Ticket** | forge a TGS with a service key | [[golden-silver-tickets]] |
| **Diamond Ticket** | modify a *real* TGT's PAC | [[diamond-ticket]] |
| **Sapphire Ticket** | inject a *real* privileged PAC via S4U2self | [[sapphire-ticket]] |
| **Trust ticket** | forge an inter-realm TGT with the trust key | [[trust-key-abuse]] |
| **MS14-068** | forge a PAC via broken signature validation (legacy) | [[ms14-068]] |
| **noPac** | sAMAccountName spoof → S4U2self ticket **as a DC** | [[nopac]] |

### Credential reuse (present a ticket/key you already hold)

| Attack | Material | Page |
|---|---|---|
| **Pass-the-Ticket** | a stolen TGT/TGS | [[pass-the-hash-and-ticket]] |
| **Overpass-the-Hash** | an NT hash → a *real* KDC TGT | [[overpass-the-hash]] |
| **Pass-the-Key** | an AES key → a TGT | [[pass-the-key]] |
| **Pass-the-Cert** | a cert → PKINIT TGT | [[pass-the-cert]] |

### Delegation (impersonate via S4U)

| Attack | Attribute | Page |
|---|---|---|
| **Unconstrained** | `TrustedForDelegation` → capture a TGT | [[unconstrained-delegation]] |
| **Constrained** | `msDS-AllowedToDelegateTo` | [[kerberos-delegation]] |
| **RBCD** | `msDS-AllowedToActOnBehalfOfOtherIdentity` | [[resource-based-constrained-delegation]] |
| **S4U mechanics** | S4U2self / S4U2proxy | [[s4u2self-s4u2proxy]] |
| **Bronze Bit** | flip the S4U2proxy forwardable bit (CVE-2020-17049) | [[bronze-bit]] |

### PKINIT / certificate path

| Attack | Vector | Page |
|---|---|---|
| **Shadow Credentials** | write `msDS-KeyCredentialLink` → PKINIT | [[shadow-credentials]] |
| **UnPAC-the-hash** | recover the NT hash from a PKINIT PAC | [[pkinit-unpac-the-hash]] |
| **AD CS (ESC1–16)** | mint an auth cert → TGT | [[ad-cs-esc-attacks]] |

### Relay, persistence & gotchas

- **Kerberos relay** — relay the AS/TGS exchange itself: [[krbrelay]].
- **Skeleton Key** — patch DC LSASS to accept a master key: [[skeleton-key]].
- **The double-hop** — why a WinRM/psexec second hop fails: [[kerberos-double-hop]].
- **Ticket handling** — kirbi/ccache, injection, purge: [[ccache]],
  [[ticket-and-credential-opsec]].

## Detection (the shared signals)

- **4768 (AS-REQ/TGT)** and **4769 (TGS-REQ)** are the two core events — most
  Kerberos detection is *correlating* them: a **4769 with no 4768** (Silver /
  stolen ticket), a **4768 with no pre-auth** (AS-REP roast, type 0), a **4768
  from a non-DC host**, an S4U **4769 where client ≠ service**, or a machine
  account renamed to a DC ([[nopac]]). Full table: [[kerberos-event-ids]].
- **RC4 (etype `0x17`) downgrades** in an AES domain — nearly every crack/forge
  benefits from RC4, so it's a broad tell ([[kerberos-encryption-types]]).
- **Honey SPNs / honey accounts** — cheap, high-fidelity ([[honeytokens]]).

## Defenses (the shared mitigations)

- **[[gmsa]]** — auto-rotated service secrets defeat Kerberoast/Silver *cracking*.
- **[[kerberos-armoring-fast]]** (enforced) — kills AS-REP roasting and pre-auth
  brute; pairs with **Protected Users** (AES-only, no delegation, short TGT).
- **Disable RC4** ([[kerberos-encryption-types]]).
- **Rotate `krbtgt` twice** after a suspected Golden/DCSync ([[krbtgt]]).
- **[[ad-tiering-and-hardening]]** — the architectural blast-radius limit.

## Links

- [[tgt-tgs]] · [[kerberos-pac]] · [[kerberos-preauth]] ·
  [[kerberos-encryption-types]] · [[kerberos-event-ids]] — the internals
- [[krbtgt]] — the key that signs every TGT
- [[kerberos-delegation]] — the UDE/CDE/RBCD family
- [[redteam-ad-methodology]] — where Kerberos attacks sit in an engagement
