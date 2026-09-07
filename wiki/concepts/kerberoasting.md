---
title: "Kerberoasting — offline cracking of service (TGS) tickets"
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [kerberos, tgs, spn, service-account, offline-cracking]
---

# Kerberoasting — offline cracking of service (TGS) tickets

**Kerberoasting** is the offline attack on **service accounts with an SPN**:
request a **TGS** for the service (a normal, *permitted* Kerberos operation),
take the **encrypted TGS**, and **crack the service account's password
offline**. The service's SPN is the trigger; a weak service password is the
prerequisite. The raw source summary lives in
[[kerberoasting]] (sources) — this is the working concept page. See
[[service-principal-name]] for what an SPN is and how they're enumerated.

## Why it works

- A TGS for a service SPN is issued by the DC **to any authenticated user**
  (default ACLs let `Authenticated Users` request TGSs for any SPN) — so a
  low-priv user can pull a TGS for **every** SPN in the domain.
- The TGS is **encrypted with the service account's key** (derived from its
  password, per the [[kerberos-encryption-types]] enctypes).
- You don't need the service's password to *get* the TGS — only to *use* it.
  So the ticket itself is the cracking target: **RC4 (0x17)** / **AES128
  (0x11) / AES256 (0x12)** TGSs can be cracked offline (hashcat `-m 13100`
  for RC4, `-m 19700`/`19800` for AES, John `--format=krb5tgs`).
- If the cracked password belongs to a **service account running with
  elevated rights** (SQL/AD CS/IIS on a sensitive host, or a domain-group
  membership), you've effectively cracked a foothold on that service.

## The flow

1. **Enumerate SPNs** — find every account with an SPN (the kerberoastable
   set): `Get-ADUser -SPN */*` (AD module), `Get-DomainUser -SPN $true`
   (PowerView), `GetUserSPNs.py` (impacket), **BloodHound** `hasSPN`. See
   [[service-principal-name]].
2. **Request TGSs** — for each SPN, request a service ticket
   (`GetUserSPNs.py -request`, `Rubeus.exe kerberoast`,
   `Get-DomainSPNTicket -SPN <spn>`).
3. **Offline crack** — hashcat `-m 13100` (TGS RC4) / `-m 19700`/`19800`
   (TGS AES128/AES256) / John `--format=krb5tgs`. RC4 tickets are the easiest.
4. **Exploit the cracked service account** — use the password/hash to log on
   to the service host, or if the service account is privileged (domain
   group, [[acl-abuse]] target), escalate. The end-to-end chain:
   [[path-kerberoast-to-domain-admin]].

## The gMSA caveat (why it's "the recurring mitigation")

A **gMSA** ([[gmsa]]) is the standard *defense*: its service password is
auto-rotated (effectively uncrackable and short-lived), so even if you pull
the TGS, the cracked key goes **stale** at the next rotation. gMSA
neutralizes the *offline cracking* leg — not the TGS-request leg. See
[[gmsa]] for the full mechanics and why it's the single most-repeated
mitigation in this wiki.

## Red-team notes (OPSEC)

- **Target, don't spray.** Roast the two or three SPN accounts that actually
  matter (pick them from the graph / [[bloodhound]] `hasSPN`), not every SPN —
  one principal pulling *all* SPNs is the 4769-burst signature blue teams hunt.
- **Mind the enctype.** RC4 (`0x17`) TGSs crack fastest, but RC4 on an
  AES-enforced domain is the highest-signal tell ([[kerberos-encryption-types]]);
  on a mature target, request AES and crack slower to blend in.
- **Dodge the tripwires.** Validate a target against real usage (logon history,
  description) before roasting — a request for a honey SPN is malicious by
  definition ([[honeytokens]]).
- **Run it remotely.** `GetUserSPNs.py -request` from a Linux operator host
  (over your C2 tunnel) keeps tooling off the endpoint; on-host, `Rubeus.exe
  kerberoast /nowrap` runs from memory. Either way the 4769 footprint still
  lands on the DC — the tunnel hides the *tool*, not the *traffic*.
- **Space the requests** and prefer ticket renewal over re-request to keep TGS
  volume down.

## Detection

- **4769 (TGS request)** — a burst of TGS requests for many distinct SPNs by
  a single account (a normal user requests a few SPNs; a kerberoaster requests
  *all* of them). Correlate `TicketOption`/`TicketOptions` and the target SPN
  count.
- **4769 with `aes256`/`rc4`** — note the enctype (RC4 on a TGS is a weak-key
  signal; also a [[kerberos-encryption-types]] hardening gap).
- **A TGS request for a rarely-used SPN** (a service that normally gets few
  tickets).
- **Correlate with 4624 (type 3/9) on the service host** after a crack.

## Mitigations

- **Use gMSA** for service accounts with SPNs (the primary control —
  [[gmsa]]).
- **Force AES enctypes** on service accounts (disable RC4) — a cracked RC4
  key is the easiest; see [[kerberos-encryption-types]].
- **Restrict the ACL** that lets `Authenticated Users` request TGSs (narrow
  the kerberoastable set).
- **Long, random service passwords** (where gMSA isn't an option).
- **Alert on 4769 bursts** per account (detection control).

## Links

- [[service-principal-name]] — the SPN that makes an account kerberoastable
- [[tgt-tgs]] — the TGS this attack targets
- [[kerberos-authentication]] — the TGT→TGS flow this rides
- [[kerberos-encryption-types]] — the enctypes you're cracking
- [[gmsa]] — the primary mitigation (auto-rotated service secret)
- [[path-kerberoast-to-domain-admin]] — the end-to-end chain
- [[as-rep-roasting]] — the sibling attack (AS-REP, no TGS needed)
- [[acl-abuse]] — what the cracked service account's rights give you
- [[bloodhound]] — `hasSPN` enumeration
- [[krbtgt]] — the *TGT*-forgery key (contrast: krbtgt is domain-wide, a TGS
  key is single-service)
- [[harmj0y-blog]] — Will Schroeder's Kerberoasting/ACL research (source)
- [[the-hacker-recipes]] — current tool-forward recipes (source)
