---
title: "Procdump (LSASS / process memory dumper)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, credential-access, lsass, windows]
---

# Procdump

Sysinternals **Procdump** — the canonical Windows tool for dumping a
process's full memory to a file, here used for
**[[lsass]]** (`lsass.exe`) dumps. It's the "known-benign" way to get the
in-memory credentials that [[mimikatz]]/[[secretsdump]] then parse — the
dump is a local file you exfiltrate and process *offline*.

## Usage

```bat
:: full LSASS memory dump (requires admin; -ma = full memory)
procdump64.exe -accepteula -ma lsass.exe lsass.dmp

:: named-pipe variant (dodges the obvious filename in some EDR views)
procdump64.exe -accepteula -ma -o lsass.exe C:\Users\Public\perf.data
```

Parse the dump offline: `mimikatz` (`sekurlsa::logonpasswords`) or
`impacket-secretsdump -ntds`/LSASS handling — see [[credential-dumping]].

## Red-team notes (OPSEC)

- **Rename the dump** — `lsass.dmp` under `C:\` is a magnet; drop it in
  `C:\Users\Public\` or `%TEMP%` with a benign name, exfil fast, delete.
- **`procdump -ma` vs minidump** — `-ma` gives everything (TGTs, DPAPI keys);
  a **comsvcs** or **named-pipe** dump is quieter on Sysmon 10 than a raw
  file-map of LSASS.
- **It's a *Windows* binary** — run it from your foothold session, not over
  the tunnel; the dump is your artifact to carry back to the Linux box.

## Detection

- **Event 4688** command line `procdump ... -ma lsass` (the headline tell).
- **Sysmon 10** — `lsass.exe` ProcessAccess from a non-LSA parent
  (procdump's parent is cmd/powershell, not lsaiso).
- A `.dmp`/`.data` file ~50–200 MB appearing under `C:\` seconds before
  exfil.

## Links

- [[lsass]] — the process it dumps
- [[credential-dumping]] — the stores map procdump is part of
- [[mimikatz]] — parses the dump
- [[defense-evasion-ad]] — the EDR/ETW surface this lands in
