---
title: "secretsdump.py"
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, python, impacket, ntds, dcsync, offline-dump]
---

# secretsdump.py

**`secretsdump.py`** is the **impacket** script for dumping AD and local
secrets, in **two modes**: **online/remote** (pull secrets from a live DC over
DRSUAPI — i.e. DCSync-style) and **offline** (parse a dumped `NTDS.dit` +
`SYSTEM`/`SAM`/`SECURITY` hive trio from a VSS snapshot or mount). It's the
default "get me the hashes" tool for both [[dcsync]] (remote, single or full
domain) and an offline [[ntds-dit]] dump. Part of [[impacket]].

## How it works

- **Remote (DRSUAPI / DCSync)** — connects to a DC with a domain credential
  and requests directory secrets over the **Directory Replication Service**
  (DRSUAPI), the same interface [[dcsync]] uses. Can dump the **whole domain**
  or a **single account** (`-just-dc-user`). No disk access, no VSS, no shell
  on the DC — just the replication rights.
- **Offline** — given the three registry hives (`SYSTEM`, `SAM`, `SECURITY`)
  plus `ntds.dit` (taken from a **VSS shadow copy** of `C:` on a DC, or a
  mounted/extracted volume), it decrypts and parses them locally: local
  account hashes from `SAM`, domain account hashes + `krbtgt` from
  `ntds.dit`, using the `SECURITY`/`SYSTEM` bootstrap keys.

## What it outputs

- **Domain users** — `NT` hashes, and (with `-history` / Kerberos key
  extraction) **RC4/AES** service keys, **LM** (if present).
- **`krbtgt`** — the domain TGT-signing key (the [[golden-silver-tickets|Golden
  Ticket]] source) and **any other account** you name via
  `-just-dc-user`.
- **Local (non-AD) accounts** — from `SAM` (the [[sam-database]]), for the
  local admin / service accounts on that machine.
- **Machine/computer accounts** — and, in recent versions, **gMSA** keys
  ([[gmsa]]).
- **Trust accounts** — inter-domain/forest trust keys (relevant to
  [[ad-trust-attacks]]).

## Common invocations

```bash
# Remote: full domain DCSync (needs a credential with Get-Changes/All)
secretsdump.py corp.local/attacker:'Pass' @dc01.corp.local

# Remote: single account (the classic krbtgt grab)
secretsdump.py -k -no-pass corp.local/Administrator@dc01 -just-dc-user krbtgt

# Remote: a specific set of users
secretsdump.py corp.local/attacker:'Pass'@dc01 -users 'krbtgt,DOMAIN\Admins\*'

# Offline: after a VSS snapshot of C: on a DC (copy hives + ntds.dit)
secretsdump.py -system SYSTEM -sam SAM -security SECURITY -ntds ntds.dit
```

For the offline leg, the VSS step (create the shadow copy of `C:`, then copy
`%SystemRoot%\System32\config\{SYSTEM,SAM,SECURITY}` and
`%SystemRoot%\NTDS\ntds.dit` off the snapshot) is what makes a live DC
dumpable without a reboot — see [[ntds-dit]] for the full offline flow.

## Detection

- **Remote** — **4662** on the domain/Configuration partition with
  `Get-Changes`/`Get-ChangesAll` (the DCSync tell), or a burst of DRSUAPI
  `Get-Changes-All` RPC calls; correlates with a 4768/4769 if the attacker
  then uses the keys.
- **Offline** — **VSS shadow-copy creation** on the DC (System log, Volume
  Shadow Copy provider / 5025-class event) followed by read access to
  `NTDS\ntds.dit` and the `config` hives; Sysmon 11 (registry) / 11 (file) on
  the `config` and `NTDS` paths.
- **Both** — a **DCSync + a VSS in the same window** from the same principal
  is a strong IR signal.

## Mitigations

- **Restrict DRSUAPI** — `Get-Changes`/`Get-ChangesAll` should be held only by
  DCs and the intended DCSync principals (not a broad AD group). See
  [[dcsync]], [[ad-tiering-and-hardening]].
- **Protect the DC volume** — restrict who can create VSS / read `NTDS.dit`
  and the `config` hives (admin count control, PAW — [[ad-tier-model]]).
- **Alert on** the 4662 DCSync pattern and on VSS creation + `ntds.dit` access
  on a DC.

## Links

- [[impacket]] — the framework this script belongs to
- [[ntds-dit]] — the database this dumps (offline flow + VSS)
- [[dcsync]] — the online (no-disk) capability this exposes
- [[sam-database]] — the local store dumped alongside
- [[krbtgt]] — the headline remote grab (`-just-dc-user krbtgt`)
- [[gmsa]] — gMSA keys in the output
- [[ad-trust-attacks]] — the trust accounts in the output
- [[ad-tier-model]] — the PAW/DC-protection that limits who can run it

## References

- [impacket `secretsdump.py` (SecureAuth)](https://github.com/fortresslab/impacket/tree/master/examples)
- [ired.team: dumping AD secrets (secretsdump / DCSync)](https://www.ired.team/)
- [Mimikatz `lsadump::dcsync` (the C# analog)](https://mimikatz-project.github.io/)
