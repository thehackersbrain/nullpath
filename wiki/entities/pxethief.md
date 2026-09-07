---
title: PXEThief
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, sccm, wds, pxe, credential-extraction]
---

# PXEThief

**PXEThief** (by williamla1337) is the **PXE / network-boot credential-stealing
tool** for SCCM / WDS environments. It hooks the **PXE boot process** to
capture the **credentials used when a client network-boots** to the SCCM/WDS
server — typically the SCCM/WDS service account or a local-admin context —
turning "a machine that can PXE-boot" into a usable credential. It's the
credential-extraction half of the PXE/WDS attack surface; see [[sccm-abuse]]
and [[wds-mdt-discovery]] for the broader mechanics.

## How it works

1. A target machine (or one you can boot) **PXE-boots** toward the SCCM/WDS
   server (DHCP option 66/67 pointing at the WDS/SCCM PXE server).
2. PXEThief **intercepts the PXE/TFTP boot exchange** and captures the
   **credentials / auth** the boot process presents (the PXE service account or
   the machine's boot-time context).
3. The captured credential is replayed for access to the SCCM/WDS plane or the
   booted host.

## Typical use

```powershell
# On a host that can PXE-boot (or a boot environment):
# PXEThief hooks the boot and captures the PXE/WDS credentials
.\PXEThief.exe
# -> captured SCCM/WDS PXE credential (service account / boot context)
```

The exact invocation varies by build; the key is that it runs **at/around the
PXE boot** to grab the credential the boot presents. See [[wds-mdt-discovery]]
for how PXE boot is coerced/triggered (DHCP option hijack, PXE request).

## Detection

- **Unusual PXE boot** — a client PXE-booting from an unexpected MAC/location,
  or a burst of PXE requests (DHCP option 66/67, TFTP requests for the boot
  image).
- **TFTP boot-image requests** — pulls of the WDS/SCCM boot image
  (`boot.wim`/`smstsboot.wim`) from an unexpected client.
- **The credential use** — a logon with the captured PXE/WDS service account.

## Mitigations

- **Restrict PXE/WDS to expected MACs/locations** — a PXE boot from an
  unexpected client is a tell ([[wds-mdt-discovery]]).
- **Protect the PXE/WDS service account** — it's a standing credential.
- **Alert on TFTP boot-image pulls** and PXE request bursts.
- **Tiering** — the PXE/WDS plane is Tier-0-adjacent.

## Links

- [[wds-mdt-discovery]] — how PXE boot is discovered/coerced
- [[sccm-abuse]] — the SCCM plane the credential unlocks
- [[wdsfilecrawler]] — the companion WDS deployment-share crawler
- [[mvictor]] — the SCCM lateral-movement tool in the same family
- [[ad-tiering-and-hardening]] — the tiering mitigation

## References

- [PXEThief (GitHub)](https://github.com/williamla1337/PXEThief)
- [wds-mdt-discovery (this wiki)](wds-mdt-discovery)
- [sccm-abuse (this wiki)](sccm-abuse)
