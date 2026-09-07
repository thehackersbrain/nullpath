---
title: "LLMNR/NBT-NS Poisoning (NTLM capture via name-resolution spoofing)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ntlm, relay, coercion, name-resolution, poisoning]
---

# LLMNR/NBT-NS Poisoning

**Make a Windows host authenticate to you by lying about where a name lives.**
When Windows can't resolve a single-label name in DNS, it falls back to two
legacy, **unauthenticated** name-resolution protocols:

- **LLMNR** — Link-Local Multicast Name Resolution, **multicast UDP 5355**
- **NBT-NS** — NetBIOS Name Service, **broadcast UDP 137**

A host on the same segment can answer that query with **its own IP**. The
victim then tries to **SMB/HTTP-authenticate to the attacker**, sending its
**NTLMv2** challenge-response — which the attacker **captures** (crack
offline) or **relays** (to LDAP for RBCD, to SMB for `ADMIN$`, to AD CS for
[[esc8]]-class plays). No creds needed, no shell needed — just a
**promiscuous listener** on the VLAN.

This is the IPv4/UDP-name-resolution sibling of [[mitm6-ipv6-relay]] (IPv6
DHCPv6) and the [[wpad]] capture — the three main "no-creds, make them auth
to me" plays. The canonical tool is [[responder]]; the relay destination is
usually [[ntlmrelayx]].

## The condition

- Victim(s) with **LLMNR or NBT-NS enabled** (still the default on many
  Windows installs — see mitigation).
- A name the victim requests that **isn't in DNS** — old hostnames, broken
  mapped drives, stale shortcuts, a typo'd `\\FILESERVER`.
- Attacker **on the same L2 segment** (multicast/broadcast reach).

## Exploit

```bash
# Responder: answer LLMNR/NBT-NS + mDNS, serve SMB/HTTP/LDAP, capture NTLMv2
Responder -I eth0 -wrfv

# Auto-attack: if the captured NTLM can write LDAP (e.g. MachineAccountQuota),
# Responder relays and writes RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
Responder -I eth0 -A

# Manual: capture, then relay the NTLMv2 to the target you want
ntlmrelayx.py -t ldap://<target> ...   # or -t smb://<target>/ADMIN$
```

Captured NTLMv2 → **hashcat `-m 5600`** (or crack with [[john-the-ripper]])
for the NT hash → [[pass-the-hash-and-ticket]]. With `-A`/RBCD, you skip the
crack entirely: **any user → that machine**
([[resource-based-constrained-delegation]], [[rbcd-via-ntlm-relay]]).

## Red-team notes (OPSEC)

- **Same-VLAN listener, zero footprint until the query** — Responder is silent
  until a name falls through DNS; the *query* is the victim's own behavior,
  so the trigger is quieter than a scan.
- **Throttle it** — a poisoned name that every host retries floods 4625/4776
  and trips the "NTLM to new host" alert; pick one stale name, one segment.
- **`-A` RBCD is the endgame** — collapse capture→relay→RBCD-write into one
  tool; the write (new computer account + the attribute) is the loud part, so
  only fire it when you've confirmed write permission.
- **Pick the play by network position** — LLMNR/NBT-NS needs only a VLAN seat;
  [[mitm6-ipv6-relay]] needs IPv6/DHCPv6; [[wpad]] needs a DNS record + a
  browser. Run whichever the target allows — often all of them.
- **Capture is always worth it** — even when you relay, the NTLMv2 on disk is
  a crackable NT hash (a fallback if the relay target later locks NTLM).

## Detection

- **The LLMNR/NBT-NS query itself** — Windows DNS Client **Event 5624** (LLMNR
  resolution of a single-label name) is the tell that the name *should* have
  been in DNS; NBT-NS is less logged, so **UDP 137/5355 flows** are the
  network-side telemetry.
- **4776 / 4624 Type 3 NTLM to an unusual host** on the segment, seconds after
  a name-resolution query.
- **4625 fan-out** to one new host from many sources — a poisoned name every
  client retries.
- With **`-A`**: the downstream **RBCD write** (new computer account /
  `msDS-AllowedToAct...`) — same high-fidelity alert as
  [[rbcd-via-ntlm-relay]].
- **SMB signing** on the victim blocks the *SMB* relay (not the *capture*).

## Mitigations

- **Disable LLMNR + NBT-NS via GPO** — Computer Config → Admin Templates →
  Network → DNS Client → *"Turn off multicast name resolution"* (LLMNR) and
  *"Turn off NetBIOS name resolution over TCP/IP"* (NBT-NS). The single
  highest-value control here ([[ad-tiering-and-hardening]]).
- **Block UDP 5355 / 137 at segment boundaries** so a poisoned name can't
  cross VLANs.
- **Fix the DNS** — most poisoning triggers are names that *should* resolve;
  stale single-label records in DNS kill the fallback.
- **SMB signing + EPA** — the relay controls once a capture happens.

## Links

- [[responder]] — the canonical LLMNR/NBT-NS/mDNS capture+relay tool
- [[ntlmrelayx]] — the relay destination for a manual capture
- [[mitm6-ipv6-relay]] — the IPv6 DHCPv6 sibling (same no-creds RBCD goal)
- [[wpad]] — the HTTP/DNS-record capture sibling
- [[rbcd-via-ntlm-relay]] — the credential-less RBCD endgame this feeds
- [[ntlm-relay-coercion]] — the relay hub these captures land in
- [[ntlm]] — the NTLMv2 being captured (hashcat 5600)
- [[hashcat]] — the offline crack of the capture
- [[ad-tiering-and-hardening]] — the "disable LLMNR/NBT-NS" baseline control
