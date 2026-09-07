---
title: "Pass the Hash (PtH) & Pass the Ticket (PtT)"
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [lateral-movement, ntlm, kerberos, pth, ptt, credential-reuse]
---

# Pass the Hash (PtH) & Pass the Ticket (PtT)

**Pass the Hash** and **Pass the Ticket** are the **credential-reuse** lateral
movement techniques: instead of cracking a stolen secret into a password, you
**use the secret directly** to authenticate. They're the "you already have the
key, just turn it" steps between a [[lsass]]/[[dcsync]] capture and a
[[remote-execution]] foothold on the next box. The raw source summary lives in
[[pass-the-hash-and-ticket]] (sources); this is the working concept page.

| | **PtH** | **PtT** |
|---|---|---|
| Protocol | **NTLM** ([[ntlm]]) | **Kerberos** ([[kerberos-authentication]]) |
| Credential reused | an **NTLM hash** | a **TGT/TGS ticket** |
| Where it's captured | LSASS / [[sam-database]] / [[dcsync]] | LSASS ticket cache (`.kirbi` / `.ccache`) |
| Valid until | the **password changes** | the **ticket expires** (~10h) |
| Target must accept | NTLM | Kerberos |
| Forged? | no (a real NTLM exchange) | no (a real ticket, just relocated) |

## PtH — the NTLM hash *is* the credential

- **Why it works** — NTLM is **challenge-response**: the client proves it
  knows the NT hash (it computes the response from the hash + the server
  challenge). The **plaintext password is never needed** on the client side —
  so a captured **NT hash** can stand in for the password. See [[ntlm]] for
  the protocol.
- **What you need** — the victim's **NT hash** (from a [[lsass]] dump, a
  [[sam-database]] read, or [[dcsync]] `-just-dc-user <user>`), and a target
  that will **accept NTLM** (most Windows SMB/RPC paths do by default).
- **How it's used** — authenticate with the hash instead of a password:

```powershell
# Mimikatz — local: spawn a process as the hashed user
privilege::debug
sekurlsa::pth /user:Administrator /domain:corp.local /ntlm:<nthash> /run:cmd.exe
```
```bash
# Impacket — remote exec / SMB with the hash (see [[remote-execution]])
psexec.py   -hashes :<nthash> corp.local/Administrator@<target>
wmiexec.py  -hashes :<nthash> corp.local/Administrator@<target>
smbexec.py  -hashes :<nthash> corp.local/Administrator@<target>
smbclient.py -hashes :<nthash> //<target>/IPC$
```

- **PtH's limits** — the **target must accept NTLM** (a Kerberos-only
  service, or a host with NTLM disabled/restricted, rejects it); **SMB
  signing / NTLMv2 session security** can blunt some uses; and it's a
  **NTLM tell** on the target (4624 type 3 NTLM). To convert a hash into a
  *Kerberos* credential instead, see **[[overpass-the-hash]]** (a real
  KDC-minted TGT from the NT hash) and **[[pass-the-key]]** (use the
  AES/RC4 key directly).

## PtT — relocate a live Kerberos ticket

- **Why it works** — a **TGT/TGS in LSASS is a bearer credential**: whoever
  presents it to a service is authenticated as its client, until it expires
  (default ~10h). You don't need the password or the keys — just the ticket.
- **What you need** — a captured **ticket** (from a [[lsass]] dump: Mimikatz
  `sekurlsa::tickets /export` → `.kirbi`, or `Rubeus.exe dump` → base64, or a
  `.ccache` — see [[ccache]]).
- **How it's used** — inject the ticket into a session and use it:

```powershell
# Mimikatz — dump + inject
sekurlsa::tickets /export            # -> .kirbi files
kerberos::ptt victim.kirbi
```
```powershell
# Rubeus — dump + inject (base64)
Rubeus.exe dump /nowrap
Rubeus.exe ptt /ticket:<base64 ticket>
```
```bash
# Impacket — use a .ccache
export KRB5CCNAME=stolen.ccache
psexec.py -k -no-pass corp.local/victim@<target>
```

- **PtT vs a forged ticket** — PtT **reuses a real** ticket (the DC minted
  it; the lifetime is normal); a **[[golden-silver-tickets|Golden/Silver
  Ticket]]** is **forged offline** (you control the lifetime — which is a
  tell). PtT is "steal the ticket," forgery is "make a ticket."

## Red-team notes (OPSEC)

- **Reuse beats cracking.** A hash/ticket used directly leaves no offline-crack
  window and no password-reset noise — but PtH forces **NTLM (4624 type 3)**,
  which stands out on a Kerberos-first estate; prefer [[overpass-the-hash]] /
  [[pass-the-key]] to move as *Kerberos* where you can.
- **PtT in memory, purge on exit.** Inject with `Rubeus.exe ptt` /
  `kerberos::ptt` (Windows) or a `KRB5CCNAME` [[ccache]] over the tunnel;
  `klist purge` / `kdestroy` when done so a stolen ticket doesn't linger.
- **Target by hostname, mind the clock.** Kerberos binds to SPNs, so use FQDNs
  (populate `/etc/hosts` when tunnelling) and keep skew < 5 min
  (`KRB_AP_ERR_SKEW`).
- **Don't reuse one ticket across many hosts** — the **same Logon ID from
  multiple IPs** is a classic PtT tell; and assume **honeytoken tickets**
  ([[honeytokens]]) exist.
- **Runs over the tunnel** — `nxc … -H <hash>`, `psexec.py -k -no-pass`,
  `secretsdump.py -hashes` from Linux; no tooling on the target
  ([[remote-execution]] for the exec step).

## Detection

- **PtH** — **4624 Logon Type 3 with NTLM** and **Key Length 0** (no cached
  credential → a hash/key was used, not a password); **4648** (explicit
  credential passed); **NTLM to a DC or SQL** from a host that normally uses
  Kerberos; a burst of NTLM type-3 from one source to many hosts.
- **PtT** — **4769 with no matching 4768** (a TGS request with no prior TGT
  on the DC); an **RC4 downgrade** on a ticket that should be AES; the **same
  Logon ID from multiple source IPs** (one ticket, many hosts); a ticket used
  close to its lifetime edge; **honeytoken tickets** ([[honeytokens]]).
- **Both** — correlate with the **capture** (a [[lsass]] dump / Sysmon 10, a
  [[dcsync]], a [[sam-database]] read) and with the subsequent lateral pattern
  (a [[remote-execution]] 4688/process-create on the next host).

## Mitigations

- **Restrict/disable NTLM** — the audit-policy **NTLM logon** category
  (Advanced Audit Configuration) + a Group Policy that disallows NTLM
  authentication (closes the PtH target surface). See
  [[ad-tiering-and-hardening]].
- **Protected Users** — Kerberos-AES-only, no credential caching, 4h TGTs
  (blunts both PtH-into-Kerberos and PtT caching); see
  [[ad-tiering-and-hardening]].
- **Credential Guard / PPL** — protects **LSASS** (where both hashes and
  tickets are captured) so the *capture* is harder; it doesn't validate
  presentation. See [[lsass]].
- **LAPS** — per-machine local-admin passwords stop a stale local-admin hash
  from being reused everywhere. See [[laps]].
- **Enforce AES Kerberos** — an RC4-only ticket is a tell (and RC4 is the
  weak path). See [[kerberos-encryption-types]].

## Links

- [[ntlm]] — the protocol PtH reuses (challenge-response, no plaintext)
- [[kerberos-authentication]] — the protocol PtT reuses (bearer tickets)
- [[lsass]] — where both the hashes and the tickets are captured
- [[sam-database]], [[dcsync]] — the other hash sources
- [[ccache]] — the ticket container for PtT
- [[overpass-the-hash]] — hash → *real* KDC-minted TGT (the Kerberos upgrade of PtH)
- [[pass-the-key]] — reuse the AES/RC4 key directly (no ticket, no hash)
- [[golden-silver-tickets]] — the *forged* (not relocated) ticket contrast
- [[remote-execution]] — the transports PtH/PtT drive (psexec/wmiexec/RDP)
- [[laps]], [[ad-tiering-and-hardening]] — the mitigation baseline
- [[path-pass-the-hash-to-domain-admin]] — the PtH end-to-end DA chain
