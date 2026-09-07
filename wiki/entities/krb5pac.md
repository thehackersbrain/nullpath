---
title: Krb5PAC (Kerberos PAC manipulation library)
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, kerberos, pac, python, tickets]
---

# Krb5PAC (Kerberos PAC manipulation library)

**Krb5PAC** (by **0x7a**, Python) is the go-to library for **reading and
manipulating the Kerberos PAC** ([[kerberos-pac]]) inside TGT/TGS tickets
([[tgt-tgs]]). Where Rubeus is the "get me a ticket" engine, Krb5PAC is the
"let me *surgically edit the PAC inside that ticket*" engine. It's the
plumbing behind several high-value chains: **UnPAC-the-hash** (extract an NT
hash from a PAC), **SID History** (inject a privileged SID into a ticket's
PAC), and **RBCD TGS forgery** (build the PAC for a forged S4U2Proxy TGS).

## What it does

- **Parse a PAC** — given a ticket (ccache/kirbi), extract the PAC and its
  structures: the **client SIDs**, the **`PAC_CREDENTIAL_INFO`** (the
  NTLM/LM hashes block), the **client name/SID**, and the **signing keys**.
- **Extract the NT hash (UnPAC)** — pull the account's **NT hash** out of
  `PAC_CREDENTIAL_INFO`. This is the **[[pkinit-unpac-the-hash|UnPAC
  the-hash]]** step: after a PKINIT TGT + an S4U2Self/U2U TGS-REQ (the
  session key that decrypts `PAC_CREDENTIAL_INFO`), Krb5PAC reads the NT out.
  (Impacket's `getnthash.py` and Rubeus `/getcredentials` do the equivalent.)
- **Modify the PAC (SID History)** — **add a privileged SID** (e.g. the
  Domain Admins SID) to the ticket's client-SID list and re-sign it, so the
  target accepts the user *as a member of that group*. This is the
  [[sid-history]] primitive.
- **Forge a TGS PAC (RBCD)** — build the PAC for a forged
  **S4U2Proxy** TGS when doing [[resource-based-constrained-delegation]]
  (the `getST.py` / Rubeus `s4u` flow), i.e. crafting the impersonated user's
  PAC into the service ticket.

## Typical use (with Rubeus / Impacket)

```bash
# UnPAC the hash: PKINIT TGT -> S4U2Self/U2U TGS (session key) -> NT hash
gettgtpkinit.py -cert-pfx CERT.pfx -pfx-pass PASS DOMAIN/USER ccache
# (S4U2Self/U2U for the session key) then:
getnthash.py -key <SESSION_KEY> DOMAIN/USER        # Impacket
# or Krb5PAC-based: read PAC_CREDENTIAL_INFO with the session key -> NT hash

# SID History: inject a privileged SID into a TGT/TGS PAC (see sid-history)
# Krb5PAC: load ticket -> add S-1-5-21-...:512 to client SIDs -> re-sign -> inject

# RBCD: forge the S4U2Proxy TGS PAC (see resource-based-constrained-delegation)
# getST.py / Rubeus s4u drive this; Krb5PAC is the underlying PAC craft
```
**Verify:** an extracted **NT hash** (UnPAC), a ticket whose **client SID list
now includes the privileged SID** (SID History), or a **valid forged TGS**
(RBCD).

## Why it's here

- **The PAC is the "who are you, and what groups" claim** inside a ticket —
  most ticket-forgery and hash-recovery attacks are, at the byte level, PAC
  edits. Krb5PAC is the standard tool for those edits.
- **Bridges three chains** — UnPAC (cert→NT hash), SID History (ticket→group
  membership), RBCD (forge TGS). If you're doing any of those "by hand,"
  Krb5PAC is where the PAC work happens.
- **Pairs with Rubeus/Impacket** — Rubeus/Impacket orchestrate the KDC
  dialogue; Krb5PAC does the offline PAC surgery on the resulting tickets.

## Detection / notes

- Krb5PAC is **offline** (it edits a ticket you already have) — so the tell
  is on the **server that accepts the edited ticket**: a logon where the
  user's **group membership (in the PAC) doesn't match AD** (SID History), or
  a TGS with a **PAC the service accepted that the DC never issued** (RBCD
  forgery).
- For **UnPAC**, the tells are the **PKINIT 4768** + the **S4U2Self/U2U
  4769** (a user requesting a TGS to itself) — see [[pkinit-unpac-the-hash]].
- **PAC signature key** matters: the re-signed PAC must be signed with a key
  the target accepts (the service's key for a TGS, `krbtgt` for a TGT) — see
  [[kerberos-pac]] and [[krbtgt]].

## Links

- [[kerberos-pac]] — the structure Krb5PAC reads/edits
- [[pkinit-unpac-the-hash]] — the UnPAC-the-hash chain (NT from PAC)
- [[sid-history]] — the PAC SID-injection chain
- [[resource-based-constrained-delegation]], [[s4u2self-s4u2proxy]] — the RBCD TGS forgery
- [[tgt-tgs]] — the tickets whose PAC is edited
- [[shadow-credentials]] — the cert→PAC→NT path that feeds UnPAC
- [[rubeus]], [[impacket]] — the orchestration tools Krb5PAC pairs with
- [[krbtgt]] — the TGT PAC signing key
