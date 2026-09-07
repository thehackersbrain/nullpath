---
title: wdsfilecrawler
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, wds, mdt, credential-extraction, file-sharing]
---

# wdsfilecrawler

**wdsfilecrawler** is the **WDS deployment-share crawler** — it walks the
**Windows Deployment Services** deployment share
(`\\<wds>\RemoteInstall\...` and the MDT deployment share) and harvests
**credentials from answer files** (`unattend.xml`, MDT `CustomScripts`,
`.xml`/`.ps1`/`.ini` files) that commonly embed local-admin passwords, domain
accounts, and MDT/OSD creds. It's the "read the deployment share for
secrets" tool in the [[wds-mdt-discovery]] family — the read-only credential
harvest complementing [[pxethief]] (the PXE-boot credential grab). See
[[wds-mdt-discovery]] for the full discovery + harvesting mechanics.

## What it finds

- **`unattend.xml`** / answer files — `<LocalAccounts>`, `<AdministratorPassword>`,
  OOBE credentials, MDT `UserDatabase`/`CustomSettings` creds.
- **MDT deployment share files** — `CustomSettings.ini`, `CustomScripts`,
  `Scripts` with embedded passwords / connection strings.
- **`drivers` / `outofbox`** configs with service-account creds.
- **The deployment share path itself** — confirms a WDS/MDT server is present
  and reachable (a discovery win).

## Typical use

```bash
# Point it at the WDS deployment share; it crawls + extracts creds
.\wdsfilecrawler.exe \\wds01.corp.local\RemoteInstall\OSImages
# -> parsed unattend.xml / MDT creds (local admin, domain, MDT service acct)
```

## Detection

- **SMB share enumeration** — a read crawl of the `RemoteInstall` / MDT
  deployment share from an unusual source (4656/4660, share access logs).
- **`unattend.xml` / answer-file reads** — mass file reads of the deployment
  share.
- **The credential use** — a logon with a harvested local/domain account.

## Mitigations

- **Restrict the deployment share ACLs** — don't leave the MDT/WDS share
  world-readable ([[wds-mdt-discovery]]).
- **Scrub answer files** — remove embedded creds from `unattend.xml` / MDT
  files after deployment (or use a secrets store).
- **Alert on deployment-share enumeration** from non-deployment sources.
- **Tiering** — the WDS/MDT plane is Tier-0-adjacent.

## Links

- [[wds-mdt-discovery]] — the WDS/MDT discovery + harvesting concept
- [[pxethief]] — the companion PXE-boot credential tool
- [[mvictor]] — the SCCM lateral-movement tool in the same family
- [[sccm-abuse]] — the SCCM plane the WDS/MDT creds often unlock
- [[ad-tiering-and-hardening]] — the tiering mitigation

## References

- [wdsfilecrawler (GitHub)](https://github.com/0xkbbh/wdsfilecrawler)
- [wds-mdt-discovery (this wiki)](wds-mdt-discovery)
- [InternalAllTheThings: WDS/MDT](https://swisskyrepo.github.io/InternalAllTheThings/)
