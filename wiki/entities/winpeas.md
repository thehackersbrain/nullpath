---
title: "WinPEAS (local privilege-escalation enumeration)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, privesc, windows, enumeration, red-team]
---

# WinPEAS

**WinPEAS** (Windows Privilege Escalation Awesome Scripting) — the de-facto
default **local privesc enumeration** tool. A single portable C++ binary, no
install, that sweeps the whole host for every
[[windows-privilege-escalation|local privesc vector]] and prints a menu of
what's exploitable. It's the "run this first, read the flags" step of local
privesc — the automated equivalent of the manual checks on the hub page.

## Usage

```bat
:: quick pass (fast, the common vectors) — the default first move
winpeas.exe -q

:: full pass (everything, slower)
winpeas.exe -all

:: 32-bit binary on a 64-bit box (run the matching arch, or use -i to pick)
winpeas.exe -i
```

WinPEAS is a **single exe per architecture** (`winpeas.exe` x64, plus an x86
build). Run it *from the foothold session* (it's a Windows binary), read the
output, and exfil/delete it.

## What it checks (the vectors you'll see flagged)

- **UAC** — which [[uac-bypass|UAC-bypass]] candidates are present
  (fodhelper, eventvwr, computerdefaults, …).
- **Services** — [[service-privesc|unquoted paths, weak ACLs, writable
  binaries, AlwaysInstallElevated]].
- **Scheduled tasks** — [[scheduled-task-abuse|writable tasks / task
  binaries]].
- **Environment** — [[environment-variable-attack|PATH/PATHEXT]] attack
  surface.
- **Token privileges** — whether your token holds `SeImpersonatePrivilege` /
  `SeAssignPrimaryTokenPrivilege` (→ [[potato-family]] /
  [[named-pipe-hijacking]]).
- **Kernel / OS build** — whether the box's build is in range for the
  [[potato-family|Coerced Pipe Impersonation]] family.
- **Local admin group, installed patches, current user token.**

## Red-team notes (OPSEC)

- **It's loud** — WinPEAS reads hundreds of registry keys / files / service
  entries in a tight window. Run it *after* the foothold is stable, not in the
  first minute, and not from a brand-new process that stands out.
- **Rename the binary** — `winpeas.exe` is a known name; drop it as
  `svchost.exe`-ish or a random name in `%temp%` (don't reuse a *real*
  system filename, which its own behaviour betrays).
- **Read the flags, don't spray** — the output is a *menu*. Pick the single
  cleanest vector (usually a service-path or task write) rather than trying
  every one.
- **Wipe it** — delete the exe and any `-all` output file when done.

## Detection

- **Event 4688** — process name `winpeas.exe` + the command line.
- **Sysmon 11/13/17 burst** — a non-admin process reading a large set of
  service/task/UAC registry keys in a short window (the enumeration *shape*).
- A freshly-dropped `.exe` in `%temp%`/`C:\Users\Public` that reads
  `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` + services + tasks.

## Links

- [[windows-privilege-escalation]] — the hub this tool enumerates for
- Seatbelt / sbtn, PrivescCheck — the same job, different coverage (run more
  than one; they flag different vectors)
- [[defense-evasion-ad]] — the EDR/ETW surface an enumeration tool lands in
- [[situational-awareness]] — the "what am I on" step this feeds
