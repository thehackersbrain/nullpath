---
title: "AS-REP Roasting — cracking accounts with pre-auth disabled"
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [kerberos, asrep, preauth, offline-cracking, credential-access]
---

# AS-REP Roasting — cracking accounts with pre-auth disabled

**AS-REP Roasting** targets accounts with **Kerberos pre-authentication
disabled** (the `DONT_REQ_PREAUTH` flag). Because pre-auth is off, the DC's
**AS-REP** reply contains the **TGT encrypted directly with the account's
key** — no random nonce, no encrypted timestamp to check. You pull that
AS-REP, extract the **RC4 (0x17)** hash, and **crack the account's password
offline**. It's the AS-REQ-stage sibling of [[kerberoasting]] (which is the
TGS stage). The raw source summary lives in [[as-rep-roasting]] (sources);
this is the working concept page.

## Why it works

- Normally, Kerberos **pre-authentication** (an encrypted timestamp) proves
  you know the password *before* the DC issues a TGT — and it's what makes an
  offline "roast" hard (you need a valid pre-auth to get a useful TGT). See
  [[kerberos-preauth]].
- If an account has **pre-auth disabled**, the DC skips the pre-auth check
  and returns a **TGT encrypted with the account's key in the AS-REP itself**.
  That AS-REP is the cracking target: an **RC4 (0x17 / "krb5asrep")** hash.
- **Who has pre-auth disabled** (the roastable set) — service accounts set up
  to authenticate **from non-Windows clients / without a keytab** (a common
  legacy misconfig), **computer accounts** in some configs, **guest**, and
  **any account someone toggled `DONT_REQ_PREAUTH` on** to simplify a
  non-interactive login. A **gMSA** does *not* set pre-auth off (it uses a
  normal key), so it's not inherently roastable this way — see [[gmsa]].

## The flow

1. **Enumerate pre-auth-disabled accounts** — find accounts with
   `DONT_REQ_PREAUTH` set (the AS-REP-roastable set):
   `Get-ADUser -Filter {UserAccountControl -bitnot 4194304}` (the
   `DONT_REQ_PREAUTH` bit), PowerView `Get-DomainUser -Preauth $false`, or
   BloodHound (the `preauth=false` flag). See [[kerberos-preauth]] for the
   UAC bit.
2. **Request an AS-REQ** — ask the DC for a TGT for each such account
   (`GetNPUsers.py`, `Rubeus.exe asrep`, `asreproast`). The DC returns the
   AS-REP (the TGT encrypted with the account key).
3. **Offline crack** — hashcat `-m 18200` (krb5asrep-rc4) / John
   `--format=krb5asrep`. Same offline-crack game as [[kerberoasting]].
4. **Exploit the cracked account** — log on with the password/hash
   ([[pass-the-hash-and-ticket|PtH]]), or if it's a privileged service
   account, escalate. The end-to-end chain:
   [[path-asrep-roast-to-domain-admin]].

## Commands

```bash
# Impacket GetNPUsers — request AS-REPs (and crack) for preauth-off accounts
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip <dc> -format hashcat
GetNPUsers.py corp.local/ -user targetsvc -dc-ip <dc> -format hashcat
# (-no-pass for anonymous; a valid low-priv user also works)

# Rubeus
Rubeus.exe asrep /user:targetsvc /rc4 /nowrap
```

## Red-team notes (OPSEC)

- **Enumerate the target set first.** Pull `DoesNotRequirePreAuth` accounts
  from LDAP (or the graph) and roast only those — spraying AS-REQs across the
  forest is the 4768 type-0 burst the SOC watches for.
- **No creds needed to request**, so this is a classic pre-foothold move
  (`-no-pass`); pair it with [[kerbrute]] to enumerate valid users and find
  the pre-auth-less ones without touching a DC hard.
- **RC4 (`0x17`) is the crackable output** (hashcat `-m 18200`); the request
  itself is a normal AS-REQ, so the only tell is *volume* and *which* accounts.
- **Watch for honey accounts** deliberately left pre-auth-disabled — a roast
  of one is an instant tripwire ([[honeytokens]]).
- **Run remotely.** `GetNPUsers.py` from a Linux operator host over the tunnel
  keeps it off the endpoint; `Rubeus.exe asreproast` runs from memory on-host.

## Detection

- **Event 4768** (TGT issued) with **`TicketOption`/pre-auth type = 0**
  (no pre-auth) — the AS-REP-roast tell. A burst of **4768 type-0** for many
  accounts by a single principal is a roast sweep.
- **A 4768 type-0 for a rarely-used service account** — an anomaly.
- **Correlate with a later 4624** for that account (the cracked password in
  use).

## Mitigations

- **Enable pre-auth** on all interactive accounts (the `DONT_REQ_PREAUTH`
  bit off) — the primary control; see [[kerberos-preauth]].
- **Protected Users** — members of **Protected Users** are (by default)
  prevented from having pre-auth disabled / get a hardened Kerberos posture;
  see [[ad-tiering-and-hardening]].
- **gMSA / strong service passwords** for the service accounts that must
  keep pre-auth off ([[gmsa]]).
- **Alert on 4768 type-0 bursts** per principal.

## Links

- [[kerberos-preauth]] — the pre-auth mechanism this disables (and the UAC bit)
- [[kerberoasting]] — the TGS-stage sibling (same offline-crack game)
- [[kerberos-authentication]] — the AS-REQ/AS-REP stage this rides
- [[kerberos-encryption-types]] — the RC4 (0x17) you're cracking
- [[gmsa]] — why a gMSA isn't inherently AS-REP-roastable
- [[path-asrep-roast-to-domain-admin]] — the end-to-end chain
- [[ad-tiering-and-hardening]] — the Protected Users / pre-auth baseline
- [[kerbrute]] — AS-REQ user enumeration / spray that feeds this attack
