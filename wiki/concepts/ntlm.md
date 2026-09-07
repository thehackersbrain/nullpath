---
title: NTLM Authentication
type: concept
created: 2026-06-12
updated: 2026-09-06
tags: [ntlm, active-directory, protocol, pass-the-hash, relay]
---

# NTLM Authentication

Legacy Windows challenge-response authentication protocol, predating
Kerberos. Still enabled in most AD environments for backward compatibility.
It is the *other* half of the Windows auth story (the other is
[[kerberos-authentication]]) and the substrate for **Pass the Hash** and
**NTLM relay** — two of the most common AD attack primitives in this wiki.

## The mechanics (why the hash ≈ the password)

In NTLM the client proves identity by answering a random **challenge** using a
secret derived from the password. The server never sees the password — only a
hash-derived response — so:

- **NT hash** = `MD4(UTF-16LE(password))` — the "NTLM hash" /   `ntlm` hash.
  This is the value you see in [[lsass]], the **SAM**
  ([[sam-database]]), **NTDS.dit** ([[ntds-dit]]), and what
  [[hashcat]] mode `1000` cracks.
- **LM hash** (legacy) = two DES-encrypted halves of an uppercased,
  salted password — `hashcat` mode `2100`; almost never used now.
- **NTLMv1 response** = DES of the challenge using the NT hash as key —
  crackable (mode `5500`/NTLMv2 `5600` for the v2 challenge/response).
- **NTLMv2 response** = `HMAC-MD5` over the challenge using an NT hash–derived
  session key — the modern default; the *challenge/response* is what a relay
  captures, not the hash.

**Key consequence:** holding the NT hash lets you answer any challenge — so the
NT hash is *functionally the password*. That's the whole
[[pass-the-hash-and-ticket|Pass the Hash]] primitive.

## Where NTLM actually runs (the attack surface)

NTLM survives in the places Kerberos doesn't cover or where it's not enforced:
local logons, SMB file-share access, `net use`/UNC, WMI/RPC fallbacks, some
services, and **cross-forest / non-KDC** contexts. It's also the protocol a
**relay** operates on — the server's challenge-response is replayable to a
*different* server (that's [[ntlm-relay-coercion]] / [[esc8-ntlm-relay-adcs]] /
[[rbcd-via-ntlm-relay]]). The **WDigest** credential cache in [[lsass]] stores
the *plaintext* password for NTLM logons — the "just dump it" version of PtH.

## Why it's attacked

- **[[pass-the-hash-and-ticket|Pass the Hash]]** — pass a stolen NT hash
  directly to authenticate (SMB/WinRM/WMI), no cracking needed.
- **NTLM relay** — capture a challenge/response in flight and replay it to a
  second server to coerce an NTLM auth ([[ntlm-relay-coercion]],
  [[mitm6-ipv6-relay|mitm6]] + [[ntlmrelayx]]).
- **Cracking** — the NT hash is offline-crackable
  ([[hashcat]] mode `1000`) from a [[lsass]] / [[sam-database]] /
  [[ntds-dit]] dump.
- **RC4 (etype `0x17`)** — the Kerberos encryption type most attack tooling
  defaults to for speed is derived from NTLM-era crypto; RC4 usage is a
  recurring downgrade-detection signal across [[kerberoasting]],
  [[as-rep-roasting]], [[golden-silver-tickets]] — see
  [[kerberos-encryption-types]].

## Detection

- **Event 4624 with LogonType 3 (network) + Authentication Package `NTLM`** —
  the baseline NTLM-auth signal; alert on NTLM from unexpected sources.
- **Relay tells** — a host requesting an NTLM auth it didn't initiate, or two
  NTLM logons in a short window to *different* servers (see
  [[ntlm-relay-coercion]]).
- **WDigest plaintext in LSASS** — Sysmon 10 LSASS access; WDigest present
  means a password, not just a hash, is exposed.
- **SMB signing disabled** — NTLM relay is possible; audit which SMB hosts
  don't require signing.

## Mitigations

- **Disable/restrict NTLM** domain-wide via GPO (audit first, then block) —
  `Domain controller: Digest authentication` + `Network security: Restrict
  NTLM` policies. See [[pass-the-hash-and-ticket]].
- **Require SMB signing** + **Network Level Authentication (Kerberos)** —
  breaks the NTLM relay path (see [[ntlm-relay-coercion]]).
- **Disable WDigest** (or Credential Guard / VBS-isolated LSASS) so the
  plaintext isn't sitting in LSASS — see [[lsass]],
  [[ad-tiering-and-hardening]].
- **LAPS** (unique local-admin password per host) — limits NTLM local-admin
  hash reuse — see [[laps]], [[ad-tiering-and-hardening]].

## Links

- [[pass-the-hash-and-ticket]] — the PtH primitive this enables
- [[ntlm-relay-coercion]] — the relay + coercion family
- [[esc8-ntlm-relay-adcs]], [[rbcd-via-ntlm-relay]] — the relay→AD CS / RBCD
  chains
- [[mitm6-ipv6-relay]] — the IPv6 MITM/relay that forces NTLM
- [[lsass]], [[sam-database]], [[ntds-dit]] — where the NT hash lives
- [[kerberos-encryption-types]] — the RC4/NTLM relationship
- [[krbrelay]] — the "worst of both worlds" Kerberos+NTLM relay
- [[kerberos-authentication]] — the protocol NTLM is being phased out in favor of

## References

- [ired.team: NTLM](https://www.ired.team/windows-offensive-security/ntlm)
- [Microsoft: NTLM authentication](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-threat-vulnerabilities/ntlm)
- [InternalAllTheThings: NTLM](https://swisskyrepo.github.io/InternalAllTheThings/)
