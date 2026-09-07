---
title: NTDS.dit (AD Database)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, credential-access, ntds, domain-controller]
---

# NTDS.dit (AD Database)

`%SystemRoot%\NTDS\ntds.dit` is the **Active Directory database** on a Domain
Controller. It stores every AD object and its attributes — including the
**NTLM hashes and AES keys** for all accounts (users, computers, `krbtgt`)
and the domain's trust/ACL data. It's the offline analog of
[[dcsync]]: same secrets, obtained by taking the DC's disk instead of
replicating over DRSUAPI.

## What you get from it

- **Every account's** `ntlm` (NT hash) and `aes128`/`aes256` keys — including
  `krbtgt` (the [[golden-silver-tickets]] primitive) and all computer
  (machine-account) hashes.
- Group memberships, ACLs, trust info, `msDS-KeyCredentialLink`
  ([[shadow-credentials]] certs), GPO links, etc.
- Feeds [[pass-the-hash-and-ticket|PtH/PtT]], [[pass-the-key|PtK]],
  [[golden-silver-tickets]], and full offline BloodHound import.

## Offline extraction (volume + hives)

You need three things: a **snapshot** of the NTDS volume, the **SYSTEM**
hive (for the boot key), and (on older systems) the **SECURITY** hive.

```powershell
# On the DC (or a compromised DC shell) — take a VSS snapshot of C:
vssadmin create shadow /for=C:
# note the shadow ID, then expose it as a drive letter:
#   (mkshadow / mount, or use the shadow path directly)
```

```bash
# Impacket secretsdump — offline, from the copied files
secretsdump.py -ntds "D:\ntds.dit" -system "D:\SYSTEM" -security "D:\SECURITY"
# (adjust paths to your mounted shadow / copied files)
# Output: every account with NTLM + AES keys, including krbtgt
```

```
# Mimikatz (on the DC, online-ish)
lsadump::ntds /generate:<password> /system:SYSTEM /integrity:SECURITY /ntds:ntds.dit
# or, dumping the live DC:
lsadump::ntds
```

## Online extraction (no disk)

- **[[dcsync]]** — request the secrets over DRSUAPI replication; no VSS, no
  file copy, no DC-local forensics. Usually preferred on a live DC because it
  leaves less local trace (but a loud 4662).
- **Mimikatz `lsadump::ntds`** live, or **gsecdump**/**com+** for the LSA
  secrets portion.

## Detection

- **VSS creation** — `vssadmin create shadow` / the VSS service (Sysmon
  Event 1 for `vssadmin.exe`, 4697 for the VSS writer) on a DC is a
  high-fidelity offline-dump tell.
- **File access to NTDS.dit / SYSTEM** from a non-DC process.
- **4662** on the domain object (if it was a DCSync instead).
- DC service anomalies / `ntds.dit` open handles.

## Mitigations

- **Credential Guard / LSASS protection** limits online LSA dumps; for
  offline you defend the DC itself.
- **Restricted Admin / Tier-0** — [[ad-tiering-and-hardening]]: only Tier-0
  admins touch DCs, and DCs are monitored for VSS + NTDS access.
- **BitLocker on DC system volume** — an offline attacker who can't decrypt
  the volume can't read `ntds.dit` (the main disk-level defense).
- Alert on VSS + NTDS.dit access and on 4662 (DCSync).

## Links

- [[credential-dumping]] — the on-host secret stores map (NTDS is the domain offline one)
- [[dcsync]] — the online (no-disk) way to get the same secrets
- [[krbtgt]] — the headline secret in the dump (Golden Ticket)
- [[pass-the-hash-and-ticket|PtH/PtT]], [[pass-the-key|PtK]] — what you do with the hashes
- [[lsass]] — the online in-memory credential store (complementary target)
- [[sam-database]] — the *local* (non-AD) account store, by analogy
- [[secretsdump]] — the impacket tool that parses this offline (or DCSyncs it)
- [[gmsa]] — gMSA keys live in the dump too (a gMSA is a computer-like object)
- [[ad-tiering-and-hardening]] — the DC-protection mitigation
- [[domain-controller]] — the DC that hosts NTDS.dit (+ FSMO roles, DSRM)

## References

- [MS-ADTS / NTDS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts)
- [Impacket secretsdump.py](https://docs.impacket-project.org/)
- [ired.team: Offline hash dumping](https://www.ired.team/offensive-security-experiments/post-exploitation/offline-hash-dumping)
