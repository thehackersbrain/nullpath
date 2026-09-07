---
title: "WPAD (Web Proxy Auto-Discovery) — the no-prompt NTLM capture"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [windows, ntlm, relay, wpad, evilwpad, coercion, lateral-movement]
---

# WPAD (Web Proxy Auto-Discovery) — the no-prompt NTLM capture

**WPAD** (Web Proxy Auto-Discovery) is how a Windows browser *automatically*
finds its proxy configuration: on joining a network, the client looks up
**`wpad.<domain>`** in **DNS** and fetches
**`http://wpad.<domain>/wpad.dat`** over **plain HTTP (port 80)**. Because it
is (a) automatic, (b) HTTP, and (c) part of the browser's normal startup, it
is one of the cleanest **no-user-interaction NTLM-capture** targets on a
domain — the same capture that [[ntlm-relay-coercion]] turns into an RBCD
write.

## Why WPAD is a capture target

- The browser does a **GET `http://wpad.corp.local/wpad.dat`** with
  **Integrated Windows Authentication** → the server can answer with an
  **NTLM challenge** and receive the user's **NTLMv2 response**.
- No prompt, no user click, no "share not found" dialog — it happens on
  **every browser launch / network join**. That's what makes it "worst of
  both worlds" material: it's *ambient* (happens constantly, so a single hit
  is low-noise) and it yields a *live user's* NTLM, not a machine account.
- The attacker needs to **own the `wpad.<domain>` DNS name** (or redirect the
  client to it) — via a rogue **AD DNS** record, a **rogue DHCP** option, or
  the IPv6 **DHCPv6** path that **mitm6** uses. See [[mitm6-ipv6-relay]].

## The two flavors

| Flavor | Mechanism | Tool | Notes |
|--------|-----------|------|-------|
| **Rogue WPAD over DNS/IPv4** | attacker controls the `wpad.<domain>` A record (rogue AD DNS) | **evilwpad** (Go) | classic; needs a DNS position; `evilwpad` serves the PAC, captures NTLM, can **relay to LDAP** for RBCD |
| **WPAD via IPv6 DHCPv6** | mitm6 rogue DHCPv6 + RA points victims at a WPAD | **mitm6** (`--wpad`) | no DNS write needed; the IPv6 "coercion" path; see [[mitm6-ipv6-relay]] |

Both end the same place: a **captured NTLM** (user or machine) that gets
**relayed** — to **LDAP** to write `msDS-AllowedToActOnBehalfOfOtherIdentity`
(RBCD) or create a computer account, or to **SMB** for a file/AD-CS reach.
See [[rbcd-via-ntlm-relay]] and [[ntlmrelayx]].

## The credential-less RBCD chain (the "no creds" one)

```
attacker (a foothold / a DNS or DHCPv6 position)
  --own wpad.<domain> (rogue AD DNS) or serve WPAD via mitm6/DHCPv6-->
victim's browser --GET http://wpad.corp.local/wpad.dat (IWA)--> NTLM challenge
  --attacker (evilwpad / mitm6) captures victim NTLM-->
  --relay to LDAPS (RBCD) / create computer account-->
  --write msDS-AllowedToActOnBehalfOfOtherIdentity on a target-->
  --RBCD: getST.py S4U2Proxy as Administrator--> lateral / domain
```

This is the **[[rbcd-via-ntlm-relay]]** "credential-less" chain: the attacker
never needs a password — they just need a **network/DNS position** and a
**browser** to do the authenticating.

## Detection

- **An unexpected `wpad.<domain>` A record**, or WPAD requests resolving to a
  **non-standard IP** (not the real WPAD server).
- **A burst of NTLM (4624 Type 3 / 4776) from many hosts to one host** at
  once — the "ambient" tell (a real WPAD gets steady traffic; a rogue gets a
  *join-time burst*).
- **WPAD + the subsequent RBCD write** correlated: a `wpad` NTLM capture
  followed by a new computer account or an `msDS-AllowedToActOn...` change is
  the high-fidelity alert (see [[rbcd-via-ntlm-relay]]).
- **`wpad.dat` content that changed** (the PAC file) if you log WPAD content.

## Mitigations

- **Disable WPAD auto-discovery** in Group Policy
  (User → Admin Templates → Network → Web Proxy Auto-Discovery: Disabled) —
  stops the ambient capture entirely.
- **Pin / monitor the `wpad.<domain>` DNS record** — alert on changes.
- **EPA (Extended Protection for Authentication)** on the WPAD endpoint
  (binds the NTLM to the TLS/channel) — blocks *relay* of the captured NTLM
  even if captured.
- **Prefer HTTPS proxies / PAC over HTTPS** so the browser doesn't fall back
  to NTLM-over-HTTP.

## Links

- [[evilwpad]] — the canonical rogue-WPAD tool (PAC serve + NTLM capture + LDAP/RBCD relay)
- [[responder]] — the LLMNR/NBNS/mDNS (no DNS-record) capture sibling
- [[mitm6-ipv6-relay]] — the IPv6 DHCPv6 WPAD variant (the "no DNS write" path)
- [[rbcd-via-ntlm-relay]] — the credential-less RBCD chain WPAD feeds
- [[ntlm-relay-coercion]] — the coercion/relay hub
- [[ntlmrelayx]] — the relay that replays the captured NTLM to LDAP/SMB
- [[ntlm]] — the NTLMv2 response being captured
- [[smb]] — the relay target for the SMB flavor
- [[ad-tier-model]] — why an ambient *user* NTLM from a Tier 2 box is dangerous
- [[ad-tiering-and-hardening]] — the WPAD-disable + EPA controls
