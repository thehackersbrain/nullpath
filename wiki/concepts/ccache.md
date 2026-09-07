---
title: ccache (Kerberos credential cache)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [kerberos, ccache, ticket, tooling, lateral-movement]
---

# ccache (Kerberos credential cache)

A **ccache** (credential cache) is the file that holds your **Kerberos
tickets** for a session — the TGT and any TGSs, plus their encryption keys.
It's the "ticket wallet" that every tool in this wiki reads from or writes to:
Rubeus dumps/injects tickets, Impacket scripts take `-k -no-pass` and read
`$KRB5CCNAME`, `kinit`/`klist` manage it on Linux, and a stolen
`.ccache`/`.kirbi` **is** the Pass-the-Ticket credential
([[pass-the-hash-and-ticket]]). If you can read, write, or forge the ccache,
you control the Kerberos identity for that session. See
[[kerberos-authentication]] for what the tickets inside actually are.

## What's in it

- The **TGT** (for `krbtgt`) — the master ticket that proves you're a valid
  domain principal.
- Any **TGSs** you've requested (for specific SPNs — service tickets).
- Each ticket's **encryption type and session key** (RC4/AES) — the key is what
  lets you request further tickets (the [[pass-the-key]] angle).
- The **PAC** in the TGT (group membership) — and, in the PKINIT path, the
  **PAC_CREDENTIAL_INFO** that carries the account's **NT hash** (the
  "UnPAC the hash" recovery, see [[pkinit-unpac-the-hash]]).

## Formats (the two you'll actually touch)

- **`.ccache`** — the MIT krb5 / Linux format. What Impacket, `kinit`, and
  `Rubeus` (via `/ticket:` or export) use. Point the tool at it with
  `KRB5CCNAME`.
- **`.kirbi`** — the Windows / Mimikatz format (`sekurlsa::tickets /export`).
  Mimikatz `kerberos::ptt` injects it. Rubeus can read/convert between the two.

These are interchangeable in practice — Rubeus and Mimikatz both convert
between `.ccache` and `.kirbi`, so a ticket dumped on one OS is usable on the
other.

## How tickets move in and out (the daily workflow)

```bash
# Linux (Impacket / krb5) — USE a ccache
export KRB5CCNAME=Administrator.ccache
klist                     # list what's in the cache
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local   # -k = use the cache

# Rubeus (Windows) — dump / triage / inject
Rubeus.exe dump /service:krbtgt /nowrap          # -> base64 TGT (or /outputfile)
Rubeus.exe ptt /ticket:<base64-ticket>            # inject into the current session
Rubeus.exe triage                                  # list cached tickets

# Mimikatz (Windows) — export / inject
sekurlsa::tickets /export       # dump all tickets to .kirbi files
kerberos::ptt <ticket>.kirbi    # inject
```

The pattern is always the same: **obtain a ticket (legit, stolen, or forged) →
get it into a ccache/.kirbi → point the exec/auth tool at it → you're that
identity for the ticket's lifetime.** See [[pass-the-hash-and-ticket]] (stolen
ticket → PtT), [[golden-silver-tickets]] (forged ticket), and [[pass-the-key]]
(key → new legit TGT).

## Why the ccache is the pivot point

- **It's the credential** — a valid ccache *is* the identity, no password or
  hash needed (unlike [[overpass-the-hash]] / [[pass-the-hash-and-ticket|PtH]]).
- **It's forgeable** — with the `krbtgt` key you mint a Golden TGT directly
  into a ccache ([[golden-silver-tickets]]); with a service key, a Silver TGS.
- **It's recoverable** — dump the live process's cache (LSASS) or the file.
- **It has a lifetime** — tickets expire (TGT ~10h by default), so a ccache is
  a *temporary* identity unless you re-mint. [[ad-tiering-and-hardening]]
  (Protected Users) shortens this to 4h and stops caching.

## Detection

- **4769 TGS-REQ with no matching 4768 AS-REQ** — a TGS presented that was
  never requested for that session (a forged/injected ticket — the PtT/Golden
  tell). See [[golden-silver-tickets]].
- **RC4 (`0x17`) enctype** in ticket requests — a downgrade signal
  ([[kerberos-encryption-types]]).
- **Same Logon ID from multiple source IPs** — one ccache reused across hosts.
- **Abnormal ticket lifetimes** — a TGT that outlives the policy (forged).
- **Honeytokens** — a canary TGT/TGS that fires when its ccache is touched.

## Mitigations

- **Shorten TGT lifetime** (4h for Tier-0 / Protected Users) — shrinks the
  window a stolen ccache is useful ([[ad-tiering-and-hardening]]).
- **Credential Guard** — keeps tickets in an isolated enclave, harder to dump.
- **Enforce AES** — kills the RC4-downgrade tell and raises the forging bar
  ([[kerberos-encryption-types]]).
- **PAC validation** — the DC re-checks the PAC, catching some forged tickets.
- **Honeytokens** — canary tickets that alert on first use.

## Links

- [[kerberos-authentication]] — the TGT/TGS the ccache holds
- [[pass-the-hash-and-ticket]] — the PtT workflow (use a stolen ccache)
- [[golden-silver-tickets]] — forging a TGT/TGS into a ccache
- [[pass-the-key]] — key → fresh legit TGT (no forgery)
- [[ticket-manipulation]] — the kirbi↔ccache conversion + PtT one-liner cheat-sheet
- [[diamond-ticket]] — the modify-a-real-TGT forgery (loaded into a ccache)
- [[pkinit-unpac-the-hash]] — reading the NT hash out of the TGT PAC
- [[kerberos-encryption-types]] — the etype of the keys in the cache
- [[krbtgt]] — the secret a Golden ccache is forged with
- [[honeytokens]] — canary tickets

## References

- [MIT krb5: ccache format](https://web.mit.edu/kerberos/krb5-1.12/doc/user/creds.html)
- [ired.team: Kerberos tickets](https://www.ired.team/active-directory-kerberos-abuse)
- [Rubeus (Ghostpack)](https://github.com/lyshark/Ghostpack)
