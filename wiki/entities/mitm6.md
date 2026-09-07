---
title: mitm6
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, python, ipv6, ntlm-relay, dirkjanm, rbc]
---

# mitm6

**mitm6** (by [[dirkjanm]]) is the **IPv6 NTLM relay / MITM** tool. It positions
the attacker on-link via **rogue DHCPv6** and/or **Duplicate Address
Detection (DAD) / SLAAC** gateway spoofing, then captures victims' **NTLM**
authentications (via WPAD proxy autoconfig, SMB, or a pointed resource) and
relays them to LDAPS/SMB/AD CS. It's the engine of
[[mitm6-ipv6-relay]] and the **credential-less RBCD** chain
([[rbcd-via-ntlm-relay]]).

## Capabilities

- **Rogue DHCPv6** — answers victims' DHCPv6 requests (attacker becomes
  router/gateway).
- **DAD / RA spoofing** — claims the gateway address / sends Router
  Advertisements.
- **WPAD** — serves a `wpad` proxy config pointing victims at the attacker's
  relay.
- **Relay** — forwards captured NTLM to `--ldaps` (RBCD), `--smb`, `--adcs`,
  or a custom `--relay-host`.

## Common invocations

```bash
# Credential-less RBCD: rogue DHCPv6 + WPAD -> relay to LDAPS for RBCD
mitm6 -i eth0 --relay-host dc01.corp.local --wpad --ldaps

# Relay to SMB
mitm6 -i eth0 --relay-host <target> --smb

# Relay to AD CS
mitm6 -i eth0 --adcs

# Serve WPAD only (let the victim auth to the attacker)
mitm6 -i eth0 --wpad
```

## Why it's special

- **No creds needed** — pure network position + IPv6 (see
  [[mitm6-ipv6-relay]]).
- **Composable** — the captured NTLM feeds the same targets as
  [[ntlmrelayx]] (LDAPS RBCD, SMB, AD CS).
- **Hard to detect** — "just" a DHCPv6/RA source; needs L2 visibility to spot.

## Detection

- **Rogue DHCPv6 / RA** — an unexpected DHCPv6 server or RA source MAC on the
  VLAN (a host MAC answering as the gateway).
- **DAD conflicts** — duplicate address detections for the gateway.
- **WPAD + NTLM** — a workstation NTLM-logon (4624 Type 3) to a DC/LDAPS or CA
  after a WPAD fetch.
- **Downstream** — 5136 RBCD writes, 4769 S4U (the RBCD effect).

## Mitigations

- **RA Guard / DHCPv6 Guard** on switches — drop rogue RA/DHCPv6.
- **Disable SLAAC/DHCPv6** on unmanaged segments.
- **LDAP signing / CBA** + **SMB signing** — kill the relayable targets
  ([[ntlm-relay-coercion]]).
- [[ad-tiering-and-hardening]] — limit what a relayed auth can reach.

## Links

- [[mitm6-ipv6-relay]] — the technique this tool implements
- [[rbcd-via-ntlm-relay]] — the credential-less RBCD chain
- [[ntlm-relay-coercion]] — the NTLM relay + coercion hub
- [[ntlmrelayx]] — the NTLM-side relay complement
- [[dirkjanm]] — the author
- [[kerberos-delegation-abuse]] — the RBCD/S4U2Self the relay feeds

## References

- [mitm6 (dirkjanm)](https://github.com/dirkjanm/mitm6)
- [dirkjanm.io](https://dirkjanm.io/)
- [InternalAllTheThings: mitm6 / RBCD](https://swisskyrepo.github.io/InternalAllTheThings/)
