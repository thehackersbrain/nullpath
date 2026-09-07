---
title: "evilwpad"
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, go, wpad, ntlm-capture, ntlm-relay, rbcd]
---

# evilwpad

**evilwpad** (by b1774, Go) is a **rogue WPAD** tool: it runs an HTTP server
that serves a **Proxy Auto-Config (PAC)** file and **captures the NTLM
authentication** browsers/clients send to it, then (in its LDAP mode) **relays
the captured NTLM to LDAP to inject RBCD**. It's the canonical tool for the
[[wpad]] attack — the "ambient, no-prompt" NTLM capture that needs **DNS
control** (a `wpad.<domain>` record pointing at the attacker) rather than a
name-resolution misconfiguration. See [[wpad]] for the WPAD mechanics and
[[ntlm-relay-coercion]] for where the captured NTLM goes.

## How it works

1. **Position in DNS** — the attacker needs a **`wpad` A/CNAME record** in the
   victim zone pointing at their IP. In AD that's typically a **rogue AD DNS
   zone** (a writable `wpad` record in the `_msdcs`/zone, or a child zone) —
   or any DNS the victims query that the attacker controls. (This is the key
   difference from [[responder]], which needs an LLMNR/NBNS/mDNS *fallback*,
   and from [[mitm6-ipv6-relay|mitm6]], which needs no DNS at all — just an
   IPv6 NDP position.)
2. **Serve the PAC** — a client's browser auto-discovers `http://wpad/` and
   fetches the PAC; evilwpad returns a PAC that points the client's traffic
   through the attacker's proxy, and the client **NTLM-authenticates to it**
   (no prompt, no user action).
3. **Capture + relay** — evilwpad captures the **NTLM auth** (victim user).
   In **LDAP/RBCD mode** it relays that NTLM to the domain controller's LDAP
   to **write `msDS-AllowedToActOnBehalfOfOtherIdentity`** (RBCD) on a target
   — see [[resource-based-constrained-delegation]] and
   [[path-mitm6-rbcd-to-local-admin]] (the credential-less analog).

## Common invocations

```bash
# Serve a rogue WPAD (you must control the wpad DNS record first)
evilwpad -ip <attacker-ip> -domain corp.local -cert cert.pem -key key.pem

# Capture NTLM, relay to LDAP, inject RBCD on a target computer object
evilwpad -ip <attacker-ip> -domain corp.local -ldap -t CORP\TARGET01$
# (a victim browser authenticating to wpad -> NTLM relayed to LDAP ->
#  msDS-AllowedToActOnBehalfOfOtherIdentity written on TARGET01$)
```
The exact flags vary by build; the core loop is **DNS position → PAC → NTLM
capture → (optional) LDAP/RBCD relay**.

## Detection

- **WPAD traffic to an unexpected server** — a `wpad` A record that changed,
  or clients fetching `http://wpad/` from a non-standard IP.
- **NTLM (4624 type 3) to the attacker's IP** from browser/user context (not
  a service account) — the capture tell.
- **An RBCD attribute write (5136/4662)** on a computer object right after a
  user NTLM to the WPAD server — the relay tell (see
  [[resource-based-constrained-delegation]]).

## Mitigations

- **Protect the `wpad` DNS record** — restrict who can create/change `wpad`
  in the zones (a writable `wpad` record is the whole prerequisite).
- **WPAD over HTTPS with a trusted cert** (or disable WPAD auto-discovery) —
  a client won't NTLM to a PAC over plain HTTP with an untrusted cert.
- **Restrict/monitor NTLM** and **alert on user-context NTLM to odd IPs** —
  see [[ntlm-relay-coercion]], [[ad-tiering-and-hardening]].

## Links

- [[wpad]] — the WPAD autoconfig attack this implements
- [[ntlm-relay-coercion]] — what the captured NTLM is relayed to
- [[resource-based-constrained-delegation]] — the RBCD the LDAP relay writes
- [[mitm6-ipv6-relay]] — the credential-less (no-DNS) alternative
- [[responder]] — the LLMNR/NBNS/mDNS (no-DNS-record) alternative
- [[ldap]] — the relay target
- [[path-mitm6-rbcd-to-local-admin]] — the RBCD end-to-end chain (mitm6 variant)

## References

- [evilwpad (b1774)](https://github.com/b1774/evilwpad)
- [WPAD / rogue-WPAD write-ups](https://www.ired.team/)
