---
title: Mvictor
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, sccm, mecm, powershell, lateral-movement]
---

# Mvictor

**Mvictor** (by williamla1337) is the PowerShell **SCCM / MECM offensive
toolkit** — it abuses the SCCM management plane for **lateral movement, code
execution, and credential extraction** without needing a traditional network
path. Where [[sccm-abuse]] describes the surface, Mvictor is the "do it" tool:
it drives SCCM's client-management features (task sequences, remote actions,
software/patch deployment, discovery) to reach and run on managed clients. See
[[sccm-abuse]] for the mechanics and [[path-sccm-naa-to-domain-admin]] for the
NAAs credential-recovery chain.

## Capabilities (the SCCM surface it abuses)

- **Lateral movement via SCCM** — use SCCM's client-management to **deploy /
  run** on any managed client (task sequence / remote action / script),
  bypassing firewall/SMB paths (the management channel is trusted).
- **Code execution** — push a script/task sequence to a target client and
  execute it in the client's context.
- **Credential / data extraction** — pull **discovery data** (hardware,
  installed software, users, paths) and abuse the **Site System / console**
  for site creds. See [[sccm-abuse]] for the discovery + NAA angle.
- **Client enumeration** — list managed clients, their site, and what you can
  run on them.

## Typical use

```powershell
Import-Module .\Mvictor.ps1

# Enumerate managed clients / the site
Get-SCCMClient ...
# Deploy / run on a target client via SCCM (task sequence / remote action)
Invoke-SCCMDeployment -Client <client-id> -Action RunScript -Script ...
# Extract discovery data / creds from the site
Get-SCCMDiscoveryData ...
```

## Detection

- **SCCM console / site-system activity** — deployments / remote actions from
  an unexpected admin context (SCCM event logs, `SMS_EXECUTIVE` / client
  action logs).
- **Task sequence / remote action bursts** — many clients hit at once from one
  operator.
- **The payload execution** — 4688 on the target clients.
- **Discovery-data reads** — bulk discovery queries from an unusual account.

## Mitigations

- **Restrict SCCM admin roles** — the management plane is powerful; limit who
  holds the admin console / site-system creds ([[sccm-abuse]]).
- **Alert on mass deployments / remote actions** from one operator.
- **Protect the Site System + console** — the NAA / site creds are the crown
  jewels ([[sccm-abuse]]).
- **Tiering** — an SCCM admin is effectively Tier-0.

## Links

- [[sccm-abuse]] — the SCCM surface Mvictor abuses
- [[path-sccm-naa-to-domain-admin]] — the NAA credential-recovery chain
- [[pxethief]], [[wdsfilecrawler]] — the PXE/WDS credential tools in the same family
- [[netexec]] — the "normal" lateral-movement path Mvictor bypasses
- [[ad-tiering-and-hardening]] — the structural (tiering) mitigation

## References

- [Mvictor (GitHub)](https://github.com/williamla1337/Mvictor)
- [sccm-abuse (this wiki)](sccm-abuse)
- [InternalAllTheThings: SCCM](https://swisskyrepo.github.io/InternalAllTheThings/)
