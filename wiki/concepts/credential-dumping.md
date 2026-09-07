---
title: "Credential Dumping (on-host secret stores overview)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, credential-access, post-exploitation]
---

# Credential Dumping

Windows holds secrets in several **distinct stores**, each with its own
dump method, its own offline format, and its own detection footprint. This is
the map of *which store has what*, so the right tool goes at the right
secret. The detailed mechanics live on each store's page.

## The stores

| Store | What's in it | Where | Dump via |
|---|---|---|---|
| **[[lsass]]** | **live** NTLM hashes, **Kerberos TGT/TGS**, DPAPI master keys, cert keys | memory (`lsass.exe`) | procdump/comsvcs/minidump → mimikatz; or `secretsdump` via SMB |
| **[[sam-database]]** | **local** account NTLM hashes (+ LAPS) | `System32\config\SAM` + `SYSTEM` | offline hive copy → `secretsdump`/`secretsdump -sam` |
| **[[ntds-dit]]** | **every domain** account (NTLM + Kerberos keys), trusts | `NTDS.dit` on DCs | `secretsdump -ntds` (vssadmin/ntdsutil), `dcbackup` |
| **DPAPI** | browser stores, Wi-Fi, RDP creds, vault | per-user profile | `dpapi` (mimikatz) with the master keys from LSASS/SAM |
| **Cached domain creds** | last N domain logon NTLMs | `SYSTEM` hive `Cache` | offline `secretsdump -system` |
| **Registry** | auto-logon password, stored creds | `SYSTEM`/`Software` hives | hive copy + parse |
| **AD CS certs** | cert private keys + PFX | cert store / CA | `certipy`/`ForgeCert` ([[golden-certificate]]) |

## The two dump *postures*

- **Online (host access)** — you have a shell/session: LSASS is the prize
  (it has the live TGT *and* the NTLM *and* DPAPI keys in one file).
  `procdump -ma lsass.exe` → exfil → `mimikatz`/`Impacket secretsdump`.
- **Offline (file access only)** — you have the hives/`NTDS.dit` (e.g. via
  `SYSTEM`+`SAM`+`SYSTEM` from SMB `ADMIN$`, or a DC VSS snapshot):
  `impacket-secretsdump -sam SAM -system SYSTEM domain\host` for local,
  `impacket-secretsdump -ntds NTDS.dit ...` for domain. No code on the target.

## What each secret buys you (downstream)

- **NTLM hash** (any store) → [[pass-the-hash-and-ticket]]
- **Kerberos TGT** (LSASS) → [[pass-the-hash-and-ticket]] / [[pass-the-key]]
- **krbtgt** (NTDS) → [[golden-silver-tickets]]
- **DC machine NT** (LSASS/NTDS) → [[dcsync]]
- **DPAPI master keys** (LSASS/SAM) → decrypt stored creds offline
- **CA key / certs** (AD CS) → [[golden-certificate]] / PKINIT

## Red-team notes (OPSEC)

- **Prefer offline when you can** — an `NTDS.dit` + hives over SMB `ADMIN$`
  needs no execution on the DC (the noisiest host) and produces a clean,
  parseable secret set.
- **LSASS is the one-stop shop** but it's *in memory* — it's the store
  **CredGuard/VistA/Cimahi** class defenses guard first; the fallback is
  **comsvcs**/named-pipe or minidump with a renamed dump file.
- **Exfil before you parse** — the dump is your artifact; get it off the host
  (or at least out of `C:\`-root) before a defender wipes the pagefile.

## Detection

- **LSASS**: Sysmon 10 (`lsass.exe` access), Process Access to
  `lsass.exe` from an unusual parent, `comsvcs`/named-pipe creation. The
  telemetry is [[sysmon]]; the rule that fires on it is [[sigma]].
- **Offline hives**: `ADMIN$` access + VSS shadow copy creation on a DC
  (`vssadmin`), `NTDS.dit` opened from a non-DC context.
- The **secret reuse** (a new PtH/PtT from the dumped hash) is often the
  higher-fidelity downstream alert — see the per-technique pages.

## Links

- [[lsass]] — the live in-memory store (primary online target)
- [[sam-database]] — the local offline store
- [[ntds-dit]] — the domain offline store
- [[pass-the-hash-and-ticket]] — what the hashes do
- [[pass-the-key]] — what the TGT does
- [[dcsync]] — the DC-NT endgame
- [[golden-certificate]] — the AD CS secret path
- [[secretsdump]], [[mimikatz]], [[procdump]] — the tooling
- [[process-injection]] — running a dumper in another process's context (the OPSEC upgrade to a raw `procdump`)
- [[meterpreter]] — the C2 payload that drives the online dump
- [[sysmon]] / [[sigma]] — the host telemetry and the rule language that detect it
- [[defense-evasion-ad]] — the EDR/AMSI/ETW surface a live dump lands in
- [[windows-privilege-escalation]] — the local admin/SYSTEM you need *first* to reach LSASS/SAM in the first place
- [[windows-local-persistence]] — keeping that dumping foothold alive between visits
