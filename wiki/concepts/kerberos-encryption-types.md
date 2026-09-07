---
title: Kerberos Encryption Types (RC4 / AES128 / AES256)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [kerberos, active-directory, encryption, detection]
---

# Kerberos Encryption Types (RC4 / AES128 / AES256)

Kerberos tickets and pre-authentication data are encrypted with an
**enctype** negotiated from the account's available keys. Which enctype ends
up in a ticket is a first-class **attack lever** (attacker picks the weakest
crackable one) and a first-class **detection signal** (RC4 on an AES domain
is anomalous).

## The encetypes

| etype (dec) | etype (hex) | Name | Key source | Notes |
| --- | --- | --- | --- | --- |
| 23 | `0x17` | RC4-HMAC | NTLM hash (MD4 of password) | Weakest; what cracking tools default to. RC4 usage is the canonical downgrade tell. |
| 17 | `0x11` | AES128-CTS-HMAC-SHA1-96 | derived from password (RFC 3962) | The "Diamond" downgrade target — still honored, quieter than RC4. |
| 18 | `0x12` | AES256-CTS-HMAC-SHA1-96 | derived from password | Strongest default on modern domains. |

The hex values you'll see in Event 4768/4769 (`ticket options` / encryption)
are the `0x11` / `0x12` / `0x17` forms. Every technique in this wiki that
mentions "RC4 (`0x17`) downgrade" is referring to the `23`/`0x17` row.

## Why attackers prefer RC4 / AES128

- **Cheaper cracking.** RC4-HMAC (`0x17`) and AES128 tickets crack far faster
  than AES256 in Hashcat/John. So [[kerberoasting]] and [[as-rep-roasting]]
  tooling requests RC4 by default (`/rc4opsec`, etype 23) to make offline
  cracking tractable.
- **Forgery flexibility.** [[golden-silver-tickets]] and
  [[diamond-ticket]] pick the enctype at build time; RC4 or AES128 forgoes
  the "strong" tell and can persist across `krbtgt` rotation.

## Where it's enforced

- **Per-account** — `userAccountControl` / the account's `msDS-SupportedEncryptionTypes`
  bitmask (bit 2 = RC4, bit 4 = AES128, bit 8 = AES256).
- **Domain-wide** — GPO *Domain Controller: Kerberos* policy
  (`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\SupportedEncryptionTypes`)
  and the *Network security: Kerberos encryption types* GPO.
- **Protected Users** — forces AES (no RC4/TGT caching), the recurring
  mitigation in [[ad-tiering-and-hardening]].

## Detection

- **RC4 (`0x17`) on an AES-enforced domain** — a TGS (4769) or TGT (4768)
  using RC4 where policy says AES is the single highest-signal Kerberos
  downgrade. Appears across [[kerberoasting]], [[as-rep-roasting]],
  [[golden-silver-tickets]], [[pass-the-hash-and-ticket]].
- **AES128 (`0x11`) TGT for a privileged account** on an AES256 domain —
  the [[diamond-ticket]] tell.
- **Enctype mismatch** — a TGT in AES256 but the follow-on TGS in RC4 (or
  vice versa) indicates a negotiated downgrade.

## Commands

```powershell
# Check an account's supported encryption types (bitmask)
Get-DomainUser targetuser -Properties mssds-supportedencryptiontypes

# Check the domain-wide Kerberos enctype policy
Get-DomainGPO | ...   # or on a DC:
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" /v SupportedEncryptionTypes

# Rubeus — force RC4 on a Kerberoast request (etype 23) for cheaper cracking
Rubeus.exe kerberoast /user:svc_sql /rc4opsec /outfile:sql.txt
```

```bash
# Crack by enctype (Hashcat modes)
hashcat -m 13100 spns.txt wordlist.txt   # TGS RC4 (etype 23)
hashcat -m 19700 spns.txt wordlist.txt   # TGS AES128
hashcat -m 19800 spns.txt wordlist.txt   # TGS AES256
hashcat -m 18200 asrep.txt wordlist.txt  # AS-REP RC4 (preauth / AS-REP roast)
hashcat -m 19600 tgt.txt   wordlist.txt  # TGT RC4 (golden ticket)
```

## Mitigations

- Enforce **AES256** domain-wide; drop RC4 from `krbtgt` and privileged
  accounts first.
- Alert on `0x17` (RC4) and, on an AES256 domain, on `0x11` (AES128) TGTs.
- [[gmsa]] + [[ad-tiering-and-hardening]] — rotating, AES-only service keys.

## Links

- [[kerberoasting]], [[as-rep-roasting]] — request RC4 to ease cracking
- [[golden-silver-tickets]], [[diamond-ticket]] — pick the enctype when forging
- [[pass-the-key]] — you must supply the matching key/enctype
- [[kerberos-pac]] — the signed blob the enctype protects
- [[ad-tiering-and-hardening]] — the AES-enforcement mitigation

## References

- [RFC 3962 — The Use of AES Encryption Modes in Kerberos](https://datatracker.ietf.org/doc/html/rfc3962)
- [MS-NRPC / Kerberos enctype bits](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kerb)
- [Hashcat modes (13100/19700/19800/7500)](https://hashcat.net/wiki/doku.php?id=cracking_hashcat)
