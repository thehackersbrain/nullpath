---
title: Responder (LLMNR/NBNS/MDNS NTLM capture + auto-relay)
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, ntlm, relay, llmnr, nbns, coercion]
---

# Responder (LLMNR/NBNS/MDNS NTLM capture + auto-relay)

**Responder** (by **LaNcuster**) is the classic **NTLM-capture / relay** tool:
it **listens for name-resolution queries** — **LLMNR**, **NetBIOS-NS (NBNS)**,
and **mDNS** — and, when a host asks "where is `SOMETHING`?", answers "I'm
here" (its own IP). The victim then tries to **SMB/HTTP-authenticate to the
attacker**, sending its **NTLMv2** response, which Responder **captures and
can relay**. It's the IPv4/UDP-name-resolution sibling of **[[mitm6]]** (IPv6
DHCPv6) and the **[[wpad]]** capture — the three main "no-creds, make them
auth to me" plays.

## What it does

- **Listens** for **LLMNR (UDP 5355)**, **NBNS (UDP 137)**, **mDNS (UDP 5353)**
  queries and **spoofs the answer** → the victim targets the attacker.
- **Serves** the captured auth on **SMB (445)**, **HTTP (80, incl. a WPAD
  endpoint)**, and **LDAP** — so the victim's NTLM lands somewhere you control.
- **Captures NTLM** responses (hashcat/john formats) — crackable offline, or
  relayable.
- **`-A` (auto-attack)** — the headline feature: if Responder sees it has
  **write permission** (e.g. it can create a computer account / write LDAP),
  it **automatically relays the NTLM to LDAP and writes RBCD**
  (`msDS-AllowedToActOnBehalfOfOtherIdentity`) — the same RBCD end as
  [[rbcd-via-ntlm-relay]], but driven by name-resolution spoofing instead of
  WPAD/DHCPv6.

## Typical invocations

```bash
# Basic: listen for LLMNR/NBNS, serve SMB+HTTP, capture NTLM
Responder -I eth0 -wrfv

# Auto-attack: capture NTLM AND, if it can write LDAP, relay + write RBCD
Responder -I eth0 -A

# Relay the captured NTLM to a target (SMB/LDAP/ADCS)
Responder -I eth0 -A -smb2support
# (or pipe the hash to ntlmrelayx.py / crack it)
```
**Verify:** a captured **NTLMv2** (crackable) *or*, with `-A`, a **RBCD write**
on a target (the credential-less RBCD). See [[ntlm-relay-coercion]].

## Why it's here

- **The canonical LLMNR/NBNS tool** — if a box has LLMNR/NBNS enabled (still
  common), Responder is the go-to "make it auth to me" — no WPAD/DNS position
  needed, just a **promiscuous listener** on the segment.
- **`-A` auto-RBCD** — it collapses "capture NTLM → relay → write RBCD" into
  one tool, mirroring the [[rbcd-via-ntlm-relay]] chain but via name-resolution
  rather than WPAD.
- **Contrast with [[mitm6]]** — Responder = **IPv4 UDP name-resolution**
  (LLMNR/NBNS); mitm6 = **IPv6 DHCPv6/RA**. Use whichever the network allows;
  often both.

## Detection / notes

- **LLMNR/NBNS queries in the first place** are the tell — a host asking
  "where is `X`" over LLMNR/NBNS (it should have resolved via DNS) means the
  name isn't in DNS. **Disabling LLMNR/NBNS** (Group Policy) removes the
  target.
- **A burst of NTLM (4624 Type 3 / 4776) to a new host** on the segment after
  a name-resolution query.
- With **`-A`**, the downstream **RBCD write** (new computer account /
  `msDS-AllowedToActOn...`) is the high-fidelity alert — same as
  [[rbcd-via-ntlm-relay]].
- **SMB signing** on the victim blocks the *SMB* relay (but not the NTLM
  *capture* for cracking); **EPA** blocks relay to the target.

## Links

- [[llmnr-nbt-ns-poisoning]] — the technique Responder exploits (LLMNR/NBT-NS spoofing)
- [[mitm6-ipv6-relay]] — the IPv6 DHCPv6 sibling (same "no-creds RBCD" goal)
- [[wpad]] — the HTTP/WPAD capture sibling
- [[rbcd-via-ntlm-relay]] — the RBCD endgame `-A` drives
- [[ntlm-relay-coercion]] — the coercion/relay hub
- [[ntlmrelayx]] — the general relay Responder can feed
- [[ntlm]] — the NTLMv2 being captured
- [[ad-tiering-and-hardening]] — the "disable LLMNR/NBNS" control
