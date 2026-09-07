---
title: "The Hacker Recipes — AD attack cookbook (ShutdownRepo)"
type: source
created: 2026-09-07
updated: 2026-09-07
tags: [source, red-team, active-directory, reference, methodology]
---

# The Hacker Recipes

A community AD-attack **cookbook** (by Charlie Bromberg "Shutdown" et al.) —
concise, tool-forward recipes for the full domain kill-chain. One of the most
practical working references for AD tradecraft and a good cross-check for the
command syntax used across this wiki's technique pages.

- **URL**: https://www.thehacker.recipes/ (AD section:
  `/ad/movement/`).

## Key takeaways

- Organised by **movement primitive** (Kerberos, NTLM, credentials, DACL,
  delegations, ADCS, trusts) — mirrors this wiki's concept split and is a
  useful index when triaging an unfamiliar edge.
- Strong, current **Impacket / Certipy / bloodhound-python** command recipes —
  the Linux-operator syntax referenced in the OPSEC notes on
  [[kerberoasting]], [[dcsync]], [[resource-based-constrained-delegation]] and
  [[ad-cs-esc-attacks]].
- Covers the credential-less relay chains ([[ntlm-relay-coercion]],
  [[rbcd-via-ntlm-relay]], [[mitm6-ipv6-relay]]) and shadow credentials
  ([[shadow-credentials]]) with working invocations.

## Touches

[[kerberoasting]], [[dcsync]],
[[resource-based-constrained-delegation]], [[ad-cs-esc-attacks]],
[[ntlm-relay-coercion]], [[shadow-credentials]].
