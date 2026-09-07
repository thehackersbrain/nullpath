---
title: Overpass the Hash
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, kerberos, pass-the-hash, overpass, privilege-escalation]
---

# Overpass the Hash

**Overpass the Hash** (often "Pass the Hash → Kerberos") is the technique of
turning a captured **NTLM hash** into a **real, KDC-minted TGT** — instead of
forging a ticket offline (a [[golden-silver-tickets|Golden Ticket]]) or just
reusing the hash over NTLM (plain [[pass-the-hash-and-ticket|Pass the Hash]]).
You hand the KDC an AS-REQ using **RC4** with the victim's **NT hash as the RC4
key**, and the KDC issues a **legitimate TGT** for the victim. The ticket is
*real* (the KDC validated it) — no forged-lifetime tell, and you don't need
the `krbtgt` secret (which a Golden Ticket requires). See
[[kerberos-encryption-types]] for why RC4 (key = NT hash) is the lever.

## How it differs from the adjacent techniques

| Technique | What you hold | What the DC sees | Ticket |
| --- | --- | --- | --- |
| [[pass-the-hash-and-ticket\|PtH]] (NTLM) | NTLM hash | NTLM challenge-response | none / NTLM |
| **Overpass the Hash** | NTLM hash | a normal **RC4** AS-REQ (key = the hash) | **fresh, legitimate** TGT (KDC-minted) |
| [[pass-the-key\|PtK]] | AES/RC4 **key** | a normal AS-REQ with that key | fresh, legitimate TGT |
| [[golden-silver-tickets\|Golden Ticket]] | **krbtgt** secret | (nothing — it's forged offline) | **forged** TGT (lifetime tell) |

Overpass and PtK look identical on the wire (both are `asktgt` with a
hash/key); the distinction is *where the secret came from* and the *enctype*:
Overpass specifically uses the **NT hash as the RC4 key** to get a real TGT.
The payoff over a Golden Ticket: a **real** ticket (no offline forgery, no
stale-lifetime anomaly) and **no `krbtgt` needed**.

## The mechanics

1. You have the victim's **NT hash** (from [[dcsync]] `-just-dc-user <user>`,
   a [[lsass]] dump, or a [[sam-database]] / [[ntds-dit]] dump).
2. Request a TGT **via the KDC** using RC4 with that hash as the key:
   ```powershell
   Rubeus.exe asktgt /user:<victim> /domain:corp.local /rc4:<nt-hash> /ptt
   Rubeus.exe triage
   whoami /all   # corp.local\<victim> + its real group memberships
   ```
   The KDC checks the RC4 pre-auth against the victim's stored NT hash, it
   matches, and it **issues a real TGT** — that's the "overpass."
3. Use the TGT normally (TGS for services, lateral, DCSync if the victim has
   rights).

## Why it matters

- **Real ticket, no `krbtgt`** — unlike a Golden Ticket, you don't need the
  domain's most valuable secret; you only need the *user's* hash. Lower bar.
- **Clean 4768** — the KDC minted it, so the 4768 is a normal TGT request (no
  forged-lifetime tell). The detectable signal is an RC4 TGT request (the
  downgrade) and a hash-only auth from an unexpected source.
- **Hash → Kerberos bridge** — it's the cleanest way to take a cracked/dumped
  NT hash and *enter Kerberos* as that user, rather than being stuck in NTLM.
- Pairs with [[kerberoasting]] / [[dcsync]] / [[as-rep-roasting]] (hash
  sources) and then feeds any hash-based lateral movement.

## Detection

- **4768 TGT with RC4 (`0x17`)** — an RC4 TGT request on an AES domain is the
  primary tell (see [[kerberos-encryption-types]]).
- **Hash-only auth from an unexpected source** — a user TGT requested where
  the user isn't normally active.
- **Contrast with Golden** — a Golden Ticket shows an *impossibly long/odd
  lifetime*; Overpass shows a *normal* lifetime but an RC4 enctype.

## Mitigations

- **Force AES** (drop RC4 for TGTs) — removes the RC4 lever
  ([[kerberos-encryption-types]]).
- **Crack + rotate** the dumped hash — Overpass is only as good as the
  captured hash's validity.
- **Alert on RC4 TGT requests** and on 4768 from unusual sources.
- Protect the hash sources ([[lsass]], [[ntds-dit]], [[sam-database]]).

## Links

- [[pass-the-hash-and-ticket]] — the PtH/PtT family this extends into Kerberos
- [[pass-the-key]] — the AES-key analogue (same wire shape)
- [[golden-silver-tickets]] — the offline-forgery contrast (needs krbtgt)
- [[kerberos-encryption-types]] — why RC4 (key = NT hash) is the lever
- [[dcsync]], [[lsass]], [[sam-database]] — the NT-hash sources
- [[kerberos-authentication]] — the AS-REQ stage Overpass drives
- [[path-overpass-the-hash-to-local-admin]] — the end-to-end "hash → local admin on a target" chain

## References

- [ired.team: Overpass the Hash](https://www.ired.team/active-directory-kerberos-abuse/overpass-the-hash)
- [SpecterOps / ired.team: Kerberos](https://www.ired.team/active-directory-kerberos-abuse/)
- [pass-the-hash-and-ticket (this wiki)](pass-the-hash-and-ticket)
