---
title: "Service Privilege Escalation"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, service, local, msi]
---

# Service Privilege Escalation

**Abusing a Windows *service* misconfiguration to run code as the account the
service runs under** — usually `LOCAL SYSTEM` or a privileged admin. Services
are the classic local-privesc target because they're long-lived, they run at a
higher privilege than the user you're on, and a surprising number of them are
misconfigured in a way a low-priv user can reach.

This is the single most common *clean* local privesc in the wild, and the
thing [[winpeas]] flags first.

## The vectors

### Unquoted service path

If a service's `ImagePath` has **spaces and no surrounding quotes**, Windows
resolves the path **left-to-right at each space** and tries to run the first
segment:

```
ImagePath = C:\Program Files\My App\svc.exe        (unquoted, has spaces)
→ Windows tries, in order:
   C:\Program Files\My.exe
   C:\Program.exe
   C:\Program.exe
```

If you can **write to** one of those resolved locations and drop a binary with
that name, the service (SYSTEM) executes *your* binary on (re)start. The fix is
to quote the path; the attack is to find the unquoted one with a writable
prefix.

```bat
:: enumerate service paths and their ACLs (PowerUp / manual)
wmic service get name,pathname,startmode
:: or the quick sweep
winpeas.exe -q   | findstr /i "unquoted"
```

### Weak service ACL (the DACL is the door)

Every service object has a **DACL**. If a low-priv user (or `Everyone`) holds
`SERVICE_ALL_ACCESS` / write on it, you can **change the binary path**, **change
the account it runs as**, or start/stop it at will.

```bat
sc sdshow <ServiceName>
:: look for (A;...;...)( Everyone / your SID with RW or GENERIC_ALL )
```

If you have write: point the `BinaryPathName` at your payload, set
`objSecurityDescriptor` so it runs as `LocalSystem`, `sc start`. PowerUp's
`Start-ServiceAbuse` automates exactly this (change path → start → capture).

### Writable service binary

If a low-priv user can **write the service's actual binary file** on disk,
replace it with your shellcode/binary and start the service. Same result,
different door (file ACL rather than service-object ACL).

### AlwaysInstallElevated (the MSI SYSTEM privesc)

Two installer policy values:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer  → AlwaysInstallElevated = 1
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer  → AlwaysInstallElevatedUser = 1
```

If either is set (admins set it to test MSI installs), **any user can install
an MSI with elevated (SYSTEM) rights** — no UAC prompt. Craft an MSI with a
`CustomAction` (or a `InstallExecuteSequence` that runs your binary) and
`msiexec /i evil.msi` → **code execution as SYSTEM**. One of the highest-
yield, most-underrated local privescs; check it on every box.

```bat
:: the two keys
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevated
reg query "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v AlwaysInstallElevatedUser

:: if set — build an MSI (msitools / a template) with a custom action, then:
msiexec /i evil.msi
```

## Tooling

- **[[winpeas]]** — flags unquoted paths, weak service ACLs, AlwaysInstallElevated.
- **PowerUp** (`Start-ServiceAbuse`, `Invoke-ServiceAbuse`) — the PowerShell
  automation for the ACL / binary vectors.
- **`sc` / `wmic service`** — manual enumeration and manipulation.
- **msiexec + a custom-action MSI** — the AlwaysInstallElevated payload.

## Red-team notes (OPSEC)

- **The unquoted-path write is your quietest win** — dropping a tiny binary at
  `C:\Program.exe` and restarting the service leaves a *plausible* file and a
  single service start. Prefer it over the MSI or the ACL-swap when available.
- **Restart timing matters** — an unquoted path only fires on the *next*
  service start/restart. `sc stop`/`sc start` (if you can) or wait for reboot.
- **AlwaysInstallElevated is loud if you leave the MSI** — install, grab the
  SYSTEM shell, then delete the `.msi` and any registry trace it wrote.
- **Clean the ACL/path you touched** — a service still pointing at `C:\temp\`
  is a forensic breadcrumb; restore the original `ImagePath` after you're done
  (or you've pivoted away).

## Detection

- **Event 7045** — a *new* service installed (the unquoted-path binary drop
  that's a service, or an MSI install).
- **Event 4697 / 7040** — service start / a service running as an unexpected
  account.
- **`sc sdshow` ACL change** — the service DACL gaining a low-priv SID with
  write (the weak-ACL vector, often pre-existing — the *use* is the tell).
- **msiexec as a non-admin producing a SYSTEM process** — the
  AlwaysInstallElevated signature (4688 parent `msiexec`, child SYSTEM, no
  admin logon).
- **A service executing a binary from a non-standard path** (`C:\Program.exe`,
  `%temp%\svc.exe`) — Sysmon 1 + 4688.

## Links

- [[windows-privilege-escalation]] — the hub
- [[winpeas]] — the enumeration that finds these
- [[powerupack]] — PowerUp automates the service vectors
- [[service-account]] — the accounts these services run under
- [[windows-local-persistence]] — a (mis)configured service is also persistence
