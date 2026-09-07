---
title: "TGT and TGS — the two Kerberos tickets"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, kerberos, tickets, authentication]
---

# TGT and TGS — the two Kerberos tickets

Kerberos has exactly **two ticket types**, and every Kerberos attack in this
wiki is an attack on one of them or on the key that signs it. Getting the
distinction straight makes the attack map trivial:

- **TGT (Ticket-Granting Ticket)** — the *login* ticket. Proves "I am user X"
  to the **TGS service** on the domain controller. You get it from the KDC
  (AS-REQ) after a successful [[kerberos-preauth|pre-authentication]]. It
  carries the **PAC** (see [[kerberos-pac]]) and is the ticket every other
  ticket is derived from. Default lifetime **10h**, renewable up to ~7 days.
  It is **encrypted with the `krbtgt` key** ([[krbtgt]]) — which is why a
  leaked `krbtgt` lets you forge any TGT.
- **TGS (service ticket)** — the *service* ticket. Proves "I am user X" to
  **one specific service** (one [[service-principal-name|SPN]]). You get it
  from the KDC (TGS-REQ) by *presenting your TGT*. Default lifetime **60
  min**, not renewable by default. It is **encrypted with the target
  service's key** — which is why a leaked *service* secret lets you forge
  TGSs for that service only.

## Why the split matters for attacks

The asymmetry is the whole game: **a TGT is domain-wide (any service); a TGS
is service-scoped.** So:

| Attack on | What you forge/steal | What it buys | Wiki page |
|-----------|---------------------|--------------|-----------|
| **TGT** | with `krbtgt` key | any user, any service, domain-wide | [[golden-silver-tickets]] (Golden) |
| **TGT** | modify a *real* TGT's PAC with the `krbtgt` key | stealthier than Golden | [[diamond-ticket]], [[sapphire-ticket]] |
| **TGT** | forge an inter-realm TGT with a **trust** key | cross-domain / forest | [[trust-key-abuse]] |
| **TGT** | copy a live one | that user, that session | [[pass-the-hash-and-ticket]] (PtT) |
| **TGT** | copy the AES key (ARM64/`lsass`) | any user, no `krbtgt` needed | [[pass-the-key]] |
| **TGT** | request one from a hash, no preauth | that user, real TGT | [[overpass-the-hash]], [[as-rep-roasting]] |
| **TGS** | with a *service* key | any user → *that one service* | [[golden-silver-tickets]] (Silver) |
| **TGS** | request one for a service SPN | the service's hash, offline | [[kerberoasting]] |
| **TGS** | forge one via RBCD + S4U2Proxy | any user → that SPN, no creds | [[resource-based-constrained-delegation]] |
| **TGS** | relay the TGS-REQ itself | escalate the ticket | [[krbrelay]] |

**Detection angle:** the DC logs **4768** (TGT/AS-REQ) and **4769**
(TGS/TGS-REQ). Most Kerberos detection is *correlating these two events* —
a 4769 with no prior 4768 (a Silver Ticket), a 4768 with no pre-auth (AS-REP),
a 4768 from a non-DC host, RC4 (`rc4-hmac`) downgrades, or a 4769 where the
*client ≠ the service account* (S4U impersonation). See
[[golden-silver-tickets]] and [[kerberos-authentication]] for the event
fields.

## Practical handles

- A TGT/TGS you **hold** lives in a **ccache** ([[ccache]]) — you dump, copy,
  and inject it; that's "pass the ticket."
- A TGT/TGS you **forge** is built offline with `ticketer.py` / Rubeus —
  that's Golden/Silver.
- A TGT you **request** with a hash is "overpass" — a *real* ticket, which
  is why it's cleaner than PtH but leaves a 4768.
- The TGS is what a service *validates* on the wire (the Silver Ticket
  validates against the service's key, so the DC never sees it).

## Links

- [[kerberos-authentication]] — the AS-REQ/TGS-REQ flow these tickets live in
- [[kerberos-preauth]] — the AS-REQ pre-auth that gates the TGT
- [[kerberos-pac]] — the PAC inside the TGT
- [[krbtgt]] — the key that signs TGTs
- [[golden-silver-tickets]] — forging a TGT vs forging a TGS
- [[diamond-ticket]] — the enterprise-wide TGT
- [[pass-the-key]], [[pass-the-hash-and-ticket]], [[overpass-the-hash]] — stealing/requesting a TGT
- [[kerberoasting]] — the TGS as a cracking target
- [[resource-based-constrained-delegation]], [[s4u2self-s4u2proxy]] — forging a TGS
- [[krbrelay]] — relaying a TGS request
- [[service-principal-name]] — what a TGS is *for*
- [[ccache]] — where the tickets live on disk/memory
