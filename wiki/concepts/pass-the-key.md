---
title: Pass the Key (PtK)
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [kerberos, active-directory, credential-access, lateral-movement]
---

# Pass the Key (PtK)

Authenticate to Kerberos using an account's **decrypted key** (the AES128,
AES256, or RC4/NT key derived from the password) instead of a pre-built
ticket. The key is used directly to compute the encrypted AS-REQ/TGS-REQ
pre-authentication data, so the KDC issues a *legitimate* ticket that is then
used normally. It sits between [[pass-the-hash-and-ticket|PtH]] (NTLM hash,
no Kerberos) and [[pass-the-hash-and-ticket|PtT]] (replaying a captured
ticket): you hold the raw key, not a ticket.

## How it differs from PtH / PtT

| Method | What you hold | What the DC sees | Ticket |
| --- | --- | --- | --- |
| [[pass-the-hash-and-ticket\|PtH]] | NTLM hash | NTLM challenge-response (or hash converted to key) | none / NTLM |
| **PtK** | AES/RC4 key | a normal Kerberos AS-REQ with valid encrypted pre-auth | **fresh, legitimate** TGT |
| [[pass-the-hash-and-ticket\|PtT]] | captured TGT/TGS | a replayed ticket | stolen ticket |

Because PtK produces a *fresh* ticket minted by the KDC, it leaves a normal
4768 event (no "forged ticket" lifetime anomalies), which is its main OPSEC
advantage over [[golden-silver-tickets]]-style offline forgery. Its main
disadvantage: you need the correct **enctype** key, and the target account
must still be Kerberos-authenticating (not locked, etc.).

## When you have the key

- [[dcsync]] — `secretsdump.py`/Mimikatz output gives you `aes128-cts-hmac-sha1-96`,
  `aes256-cts-hmac-sha1-96`, and `rc4_hmac_nt` for each account.
- [[pkinit-unpac-the-hash]] / [[shadow-credentials]] — recovering an NT hash
  lets you derive all three keys (`mkv5`-style key schedule).
- LSASS dump ([[lsass]]) — `sekurlsa::logonpasswords` shows `Key` (AES) and
  `NTLM` values.

## Commands

```powershell
# Rubeus — ask the KDC for a TGT using the raw key, inject it
Rubeus.exe asktgt /user:svc_sql /aes256:<64-hex> /ptt
Rubeus.exe asktgt /user:svc_sql /aes128:<32-hex> /ptt
Rubeus.exe asktgt /user:svc_sql /rc4:<ntlm-hash> /ptt
# then confirm
Rubeus.exe triage
whoami /all
```

```bash
# Impacket — getTGT.py takes a key and outputs a ccache you can use with -k
getTGT.py -spn cifs -dc-ip <dc-ip> DOMAIN/user:aes256:<64-hex>
# use it with any kerb-auth Impacket tool:
psexec.py -k -no-pass DOMAIN/user@<dc-ip>   # after exporting KRB5CCNAME
```

```
# Mimikatz — sekurlsa can build from a key (or use kerberos::golden offline)
privilege::debug
sekurlsa::ptt /id:<logon-id>        # if you dumped LSASS locally
```

## Detection

- **Event 4768** (TGT requested) with the expected service ticket follows —
  the ticket is *valid*, so the tell is context: a service account
  authenticating from a workstation IP, or a burst of TGTs for one account.
- The `ticket options` / encryption type in 4768 — if you forced RC4 on an
  AES domain, that's a [[kerberos-encryption-types]] downgrade signal.
- No 4624 Type 3 anomaly from the ticket itself (unlike [[golden-silver-tickets]]
  where a TGT outlives policy). Detection usually comes from *where/when* a
  normally service-bound account logs on.

## Mitigations

- [[gmsa]] — rotating, auto-managed keys so a captured key is short-lived.
- [[ad-tiering-and-hardening]] — limit what a service-account key can reach.
- Monitor 4768 for accounts that rarely (never) request TGTs from user workstations.

## Links

- [[kerberos-authentication]] — the AS-REQ stage PtK drives
- [[kerberos-encryption-types]] — which key (RC4/AES128/AES256) you must supply
- [[dcsync]], [[pkinit-unpac-the-hash]] — the two main ways to obtain the key
- [[pass-the-hash-and-ticket]] — the adjacent PtH/PtT techniques
- [[golden-silver-tickets]] — offline forgery, the contrast (stale ticket vs fresh)
- [[lsass]] — key theft source
- [[path-pass-the-key-to-domain-admin]] — the end-to-end chain

## References

- [Rubeus (GhostPack) — asktgt](https://github.com/GhostPack/Rubeus)
- [Impacket getTGT.py](https://docs.impacket-project.org/)
- [ired.team: Pass the Key](https://www.ired.team/active-directory-kerberos-abuse/kerberos-attacks)
