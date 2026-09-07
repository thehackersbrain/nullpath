---
title: Hashcat
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, cracking, gpu, password-recovery]
---

# Hashcat

**Hashcat** (by zhang) is the GPU-accelerated **offline password cracker** —
the engine behind cracking the hashes harvested by [[kerberoasting]],
[[as-rep-roasting]], [[dcsync]]/[[lsass]]/[[sam-database]] dumps, and
[[golden-silver-tickets]] (when the `krbtgt`/service key is a crackable
password). It's the "what password was that?" half of every roast/dump
technique.

## The Kerberos / NTLM modes that matter here

| Mode | Target | What you're cracking |
| --- | --- | --- |
| `13100` | Kerberos 5 **TGS-REP**, etype 23 (RC4) | [[kerberoasting]] service-account password |
| `19700` | Kerberos 5 TGS-REP, etype 17 (AES128) | AES-encrypted kerberoast ticket |
| `19800` | Kerberos 5 TGS-REP, etype 18 (AES256) | AES-encrypted kerberoast ticket |
| `18200` | Kerberos 5 **AS-REP**, etype 23 (RC4) | [[as-rep-roasting]] account password |
| `19600` | Kerberos 5 **TGT-REP**, etype 23 (RC4) | a stolen/forged [[golden-silver-tickets\|Golden Ticket]] TGT |
| `1000` | **NTLM** | [[lsass]]/[[sam-database]]/[[ntds-dit]] local + domain account passwords |
| `5500` | **NTLMv2** | NTLMv2 challenge/response |
| `2100` | **LM** | legacy LM (rare) |

(See [[kerberos-encryption-types]] for the etype mapping — RC4 is `0x17`/23,
AES128 `0x11`/17, AES256 `0x12`/18.)

## Common invocations

```bash
# Kerberoast (RC4 TGS) — straight from GetUserSPNs -format hashcat
hashcat -m 13100 spn.txt rockyou.txt

# Kerberoast (AES)
hashcat -m 19700 spn.txt rockyou.txt      # AES128
hashcat -m 19800 spn.txt rockyou.txt      # AES256

# AS-REP roast
hashcat -m 18200 asrep.txt rockyou.txt

# NTLM hash (from lsass / sam / ntds dump)
hashcat -m 1000 ntlm_hashes.txt rockyou.txt

# Golden ticket TGT (if you have the TGT, not just the key)
hashcat -m 19600 tgt.txt rockyou.txt

# Mask / rule attacks for structured passwords
hashcat -m 1000 hashes.txt -a 6 '?u?l?l?l?d?s'        # mask
hashcat -m 13100 spn.txt rockyou.txt -r rules/best64.rule
```

## Why RC4 is the default request

Attacker tooling requests **RC4** (`/rc4opsec`, etype 23) during
[[kerberoasting]]/[[as-rep-roasting]] because mode `13100`/`18200` (RC4) crack
far faster than the AES modes — see [[kerberos-encryption-types]]. A domain
that forces AES removes the fast path.

## Detection / notes

- Offline — the cracking itself is on the attacker's host; the *harvesting*
  (4768/4769 bursts) is what's detectable upstream.
- A **cracked** weak password often means the account is reused — check for
  the same password elsewhere (the "lateral" follow-on).

## Links

- [[kerberoasting]], [[as-rep-roasting]] — the hash sources (RC4/AES modes)
- [[lsass]], [[sam-database]], [[ntds-dit]] — the NTLM hash sources
- [[golden-silver-tickets]] — TGT cracking (mode 19600)
- [[kerberos-encryption-types]] — the etype→mode mapping
- [[dcsync]] — when the "hash" is a crackable password, cracking recovers it

## References

- [Hashcat](https://hashcat.net/hashcat/)
- [Hashcat modes](https://hashcat.net/wiki/doku.php?id=cracking_hashcat)
- [ired.team: Cracking](https://www.ired.team/)
