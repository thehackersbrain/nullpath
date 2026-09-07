---
title: Kerbrute
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, kerberos, enumeration, password-spray, go]
---

# Kerbrute

**Kerbrute** (by Rohitab) is the Go **Kerberos brute-force / user-enumeration
tool** — the fast, low-and-slow password-spray and user-existence oracle for
AD. It operates purely at the **AS-REQ** stage (no SMB/WinRM needed, works
across the KDC), so it's the go-to for credential spraying and confirming
which accounts exist before a full attack. It's the enumeration companion to
[[crackmapexec]] (SMB/WinRM spray) and feeds the hash/key capture that
[[kerberoasting]] / [[dcsync]] / [[overpass-the-hash]] consume.

## Capabilities

- **User enumeration** — Kerbrute distinguishes *valid* from *invalid* users
  via AS-REQ error differences (`KRB5_PRINCIPAL_UNKNOWN` vs
  `KRB5_LAST_IN`/pre-auth challenges) — the "does this account exist?" oracle.
- **Password spray** (`password`) — a **low-and-slow** AS-REQ spray across a
  user list × password list, with per-DC rate limiting to stay under account
  lockout thresholds.
- **AS-REP Roasting** (`asrep`) — enumerate accounts with **Kerberos
  pre-authentication disabled** (the [[as-rep-roasting]] target list) by
  checking for the pre-auth-less AS-REP.
- **Kerberoasting** (`kerberoast`) — enumerate + request TGSs for
  SPN-owning accounts (the [[kerberoasting]] / [[service-principal-name]]
  candidate list).
- **NTLM hash / pass-the-hash** — some modes accept NT hashes.

## Common invocations

```bash
# User enumeration (does the account exist?)
kerbrute userenum -d corp.local -dc dc01.corp.local users.txt

# Password spray (low-and-slow; -c concurrency, -t threads)
kerbrute password -d corp.local -dc dc01.corp.local users.txt passwords.txt -c 5 -t 2

# AS-REP roast enumeration (pre-auth disabled accounts)
kerbrute asrep -d corp.local -dc dc01.corp.local users.txt

# Kerberoast enumeration (SPN-owning accounts)
kerbrute kerberoast -d corp.local -dc dc01.corp.local users.txt
```

## Detection

- **4768 / 4769 bursts** — many AS-REQs (spray) or TGS-REQs (kerberoast) from
  one source.
- **4771** — Kerberos pre-authentication failure (a spray miss).
- **Account lockouts** (4740) if the spray is too aggressive — the tell of a
  *noisy* spray; Kerbrute's low-and-slow mode exists to avoid this.
- **AS-REP (pre-auth type 0) 4768** — the asrep-roast enumeration.

## Mitigations

- **Account lockout thresholds** + alert on 4740 — catches aggressive spray.
- **Low-and-slow detection** — alert on many *distinct* principals failing
  pre-auth from one source in a window.
- **Alert on bulk 4769 / asrep / kerberoast enumeration** (see
  [[kerberoasting]], [[as-rep-roasting]]).
- **Kerberos pre-auth enforcement** — fewer pre-auth-disabled accounts =
  smaller AS-REP surface ([[kerberos-preauth]]).

## Links

- [[kerberoasting]], [[as-rep-roasting]] — the enumeration targets
- [[service-principal-name]] — the SPN list kerberoast mode builds
- [[overpass-the-hash]] — what a sprayed/cracked hash feeds into
- [[crackmapexec]] — the SMB/WinRM spray counterpart
- [[kerberos-preauth]] — the pre-auth-disabled surface asrep mode targets
- [[dcsync]] — the next stage once a good cred is found

## References

- [Kerbrute (GitHub)](https://github.com/rohitab/kerbrute)
- [ired.team: Kerberoasting / AS-REP](https://www.ired.team/active-directory-kerberos-abuse/)
