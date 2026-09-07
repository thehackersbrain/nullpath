---
title: mitm6 / IPv6 NTLM Relay
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [ntlm-relay, ipv6, active-directory, coercion]
---

# mitm6 / IPv6 NTLM Relay

**mitm6** (by [[dirkjanm]]) is the IPv6 equivalent of the classic ARP-spoof
NTLM relay: it abuses **IPv6 SLAAC / rogue DHCPv6 / Duplicate Address
Detection (DAD)** to become the on-link "router," position itself in the
middle of victims' traffic, capture their **NTLM** authentications, and relay
them to a target. It's the workhorse for **credential-less RBCD** and AD CS /
SMB relay on modern networks where IPv6 is enabled (it almost always is).

## How it positions itself

- **Rogue DHCPv6** — answers victims' DHCPv6 requests, assigning them an
  address + the attacker as their router/gateway.
- **DAD / SLAAC spoofing** — claims the default gateway's address (or sends
  Router Advertisements), so victim traffic to the "internet" flows through
  the attacker.
- Once in line-of-sight, any victim service that speaks **NTLM** to a
  resource the attacker points them at (a file share, a
  [[wpad|WPAD/Proxy autoconfig]], a [[printer-bug|printer]], a web login)
  yields a relayable NTLM auth.

## The credential-less RBCD chain ("worst of both worlds")

The signature dirkjanm attack: **no valid creds needed**, just network
position + IPv6.

1. mitm6 answers DHCPv6 / spoofs the gateway on the VLAN.
2. Victims' browsers/clients request **[[wpad|WPAD]]** (`wpad.corp.local`) for proxy
   autoconfig → mitm6 serves a WPAD file pointing them at a resource.
3. The client authenticates to that resource with **NTLM** (its own machine/
   user identity) — mitm6 captures it.
4. mitm6 relays the NTLM to **LDAPS (389/tcp)** on a DC to perform **RBCD** —
   writing `msDS-AllowedToActOnBehalfOfOtherIdentity` onto a target computer
   (see [[kerberos-delegation-abuse]], [[rbcd-via-ntlm-relay]]).
5. Coerce a privileged user to authenticate to the attacker's RBCD-targeted
   machine → S4U2Self a TGS for them → domain dominance.

```bash
# mitm6 — rogue DHCPv6 + WPAD, relay to LDAPS for RBCD
mitm6 -i eth0 --relay-host dc01.corp.local --wpad --ldaps
# (variants: --smb for SMB relay, --adcs for AD CS, -s for the relay server)
```

## Other relay targets (same positioning)

- **SMB** — relay to `C$`/`ADMIN$` or to a host to run a command
  (`ntlmrelayx.py -t smb://<target>` once you have the auth).
- **AD CS** — relay to the CA web enrollment for a cert (ESC8 /
  [[esc8-ntlm-relay-adcs]]).
- **LDAP/LDAPS** — RBCD as above, or group membership writes.

## Why it's powerful

- **Credential-less** — you don't need any domain creds, just L2/L3 position
  and IPv6 enabled.
- **Sneaky** — it's "just" a router/DHCPv6 responder; hard to attribute
  without watching the link.
- **Composable** — the captured NTLM feeds the same relay targets as
  [[ntlm-relay-coercion]] (SMB, AD CS, LDAPS), so the downstream play is
  identical.

## Detection

- **DHCPv6 / Router Advertisement anomalies** — an unexpected DHCPv6 server or
  RA source MAC on the VLAN (a host MAC answering as the gateway).
- **DAD conflicts** — duplicate address detections for the gateway IP/MAC.
- **WPAD requests** to an unexpected server, and the resulting **NTLM** logons
  (4624 Type 3) from a workstation to a DC/LDAPS or CA.
- **RBCD writes** (5136 on `msDS-AllowedToActOnBehalfOfOtherIdentity`)
  followed by a 4769 S4U — the downstream effect.

## Mitigations

- **IPv6 hygiene** — disable SLAAC/DHCPv6 on unmanaged segments, or use
  **RA Guard** / DHCPv6 Guard on the switch to drop rogue RA/DHCPv6.
- **Restrict who can relay** — SMB signing, LDAP signing/Channel Binding
  (CBA/LDAPS) to kill the relayable-NTLM targets (see [[ntlm-relay-coercion]]).
- **Alert on** unexpected DHCPv6/RA sources, WPAD + NTLM to LDAPS, and RBCD
  writes.
- [[ad-tiering-and-hardening]] — limit what a relayed NTLM auth can touch.

## Links

- [[ntlm-relay-coercion]] — the NTLM relay + coercion hub (SMB/PetitPotam side)
- [[rbcd-via-ntlm-relay]] — the credential-less RBCD via mitm6/WPAD→LDAPS
- [[kerberos-delegation-abuse]] — RBCD/S4U2Self the relay feeds
- [[esc8-ntlm-relay-adcs]] — relay to AD CS for a cert
- [[dirkjanm]] — the author + the "worst of both worlds" write-ups
- [[s4u2self-s4u2proxy]] — the S4U2Self the RBCD chain ends in
- [[unconstrained-delegation]] — the UDE-to-DC abuse the captured TGT enables
- [[llmnr-nbt-ns-poisoning]] — the IPv4 name-resolution capture sibling
- [[wpad]] — the WPAD capture mitm6 drives (the IPv6/DHCPv6 variant)
- [[responder]] — the IPv4 LLMNR/NBNS capture sibling
- [[evilwpad]] — the IPv4 rogue-WPAD capture sibling (needs the `wpad` DNS record)

## References

- [mitm6 (dirkjanm)](https://github.com/dirkjanm/mitm6)
- [dirkjanm.io: RBCD / mitm6](https://dirkjanm.io/)
- [InternalAllTheThings: mitm6 / RBCD](https://swisskyrepo.github.io/InternalAllTheThings/)
