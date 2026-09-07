---
title: John the Ripper
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, cracking, password-recovery, cpu]
---

# John the Ripper

**John the Ripper** (JtR) is the long-standing **offline password cracker** —
the CPU-native complement to [[hashcat]] (the GPU option). Both crack the
same hashes harvested by [[kerberoasting]], [[as-rep-roasting]],
[[dcsync]]/[[lsass]]/[[sam-database]] dumps, and [[overpass-the-hash]] /
[[golden-silver-tickets]] (when the target key is a crackable password). Pick
JtR when you're on a CPU-only host (or want its format flexibility); pick
[[hashcat]] for raw GPU throughput.

## The Kerberos / NTLM formats that matter here

JtR names formats differently from hashcat modes, but they map 1:1 (see
[[hashcat]] for the mode numbers and [[kerberos-encryption-types]] for the
etype context):

| JtR format | Target | Source |
| --- | --- | --- |
| `nt` | **NTLM** hash | [[lsass]] / [[sam-database]] / [[ntds-dit]] dumps |
| `krb5tgs` | Kerberos 5 **TGS-REP** | [[kerberoasting]] (service acct password) |
| `krb5asrep` | Kerberos 5 **AS-REP** | [[as-rep-roasting]] (account password) |
| `krb5e16` / `krb5e17` / `krb5e23` | Kerberos 5 TGT, etype 18/17/23 | a stolen [[golden-silver-tickets\|Golden Ticket]] TGT |
| `netntlmv1` / `netntlmv2` | NTLMv1 / NTLMv2 challenge-response | captured relays |

## Common invocations

```bash
# NTLM hash (from a dump) — the "is it a weak password?" check
john ntlm_hashes.txt --wordlist=rockyou.txt

# Kerberoast TGS (RC4 etype 23) — straight from GetUserSPNs -format john
john spn_john.txt --wordlist=rockyou.txt

# AS-REP roast
john asrep.txt --wordlist=rockyou.txt

# Mask / incremental for structured passwords
john hashes.txt --mask='?l?l?l?l?l?l?d'
john hashes.txt --incremental:AlphaNumeric

# Show the cracked results
john --show
```

## Choosing JtR vs hashcat

- **GPU available + large wordlist/mask** → [[hashcat]] (far faster).
- **CPU-only / quick single-hash check / format flexibility** → JtR.
- Both read the *same* dump outputs (Mimikatz `sekurlsa::logonpasswords`,
  `secretsdump.py`, etc.) — the harvest step is identical, only the cracker
  differs.

## Detection / notes

- Offline — cracking is on the attacker's host; the upstream *harvest*
  (4768/4769/4662/LSASS access) is what's detectable.
- A cracked weak password is usually **reused** — check other systems
  (the lateral follow-on).

## Links

- [[hashcat]] — the GPU counterpart (same hashes, different engine)
- [[kerberoasting]], [[as-rep-roasting]] — the Kerberos hash sources
- [[lsass]], [[sam-database]], [[ntds-dit]] — the NTLM hash sources
- [[overpass-the-hash]] — what a cracked NT hash feeds into
- [[kerberos-encryption-types]] — the etype context

## References

- [John the Ripper](https://openwall.com/john/)
- [John the Ripper FAQ](https://openwall.com/john/faq.html)
- [ired.team: Cracking](https://www.ired.team/)
