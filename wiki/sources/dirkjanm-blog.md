---
title: "dirkjanm.io — Dirk-jan Mollema's relay & delegation research"
type: source
created: 2026-09-07
updated: 2026-09-07
tags: [source, red-team, active-directory, relay, rbcd, pkinit]
---

# dirkjanm.io (Dirk-jan Mollema)

[[dirkjanm]]'s research blog — the source of the modern **credential-less
relay** tradecraft: **mitm6** IPv6/DNS takeover, the **"worst of both worlds"**
mitm6 → LDAPS → **RBCD** chain, PKINIT/UnPAC work, and the `ntlmrelayx`
`--delegate-access` capability. Primary source behind this wiki's coercion/
relay and RBCD pages.

- **URL**: https://dirkjanm.io/ (and the mitm6 / krbrelayx / ROADtools repos).

## Key takeaways

- **mitm6** — rogue IPv6/DHCPv6 + WPAD to capture NTLM with no creds
  ([[mitm6-ipv6-relay]], [[wpad]]).
- **"Worst of both worlds"** — relay the captured machine auth to **LDAPS** and
  write **RBCD** on the victim so you can S4U-impersonate on it, entirely
  credential-less ([[rbcd-via-ntlm-relay]],
  [[resource-based-constrained-delegation]]).
- Authored **`ntlmrelayx` delegation/ADCS relay** features driving
  [[ntlm-relay-coercion]] and [[esc8-ntlm-relay-adcs]].
- **PKINIT / UnPAC-the-hash** tooling (PKINITtools) feeding
  [[pkinit-unpac-the-hash]] and [[pass-the-cert]].

## Touches

[[mitm6-ipv6-relay]], [[rbcd-via-ntlm-relay]],
[[resource-based-constrained-delegation]], [[ntlm-relay-coercion]],
[[esc8-ntlm-relay-adcs]], [[pkinit-unpac-the-hash]], [[wpad]], [[dirkjanm]].
