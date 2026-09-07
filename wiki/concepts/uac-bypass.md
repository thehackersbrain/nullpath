---
title: "UAC Bypass"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, uac, integrity, local]
---

# UAC Bypass

**Running code at high integrity without an admin approving the consent
prompt.** Under UAC, even a member of the local `Administrators` group runs
in a **filtered, medium-integrity** token by default. The consent prompt (the
UAC wall) is what promotes a process to a full elevated token. A UAC bypass
lets you cross that wall *programmatically* — you don't need the admin to
click "Yes".

The payoff is **high integrity as the same admin user** — not SYSTEM, not a
different user. That's enough to write to protected registry keys, run
admin-only tooling, and set up many of the other
[[windows-privilege-escalation|local privesc]] chains. It's the first rung,
not the top.

## How it works: the white-listed binary

The core primitive: Windows keeps a list of binaries allowed to elevate
**without** a consent prompt ("auto-elevating" / trusted UIAccess-adjacent
helpers). If you can *make one of those trusted binaries load or run your
code* while it elevates, your code runs high-integrity.

The attack shape is always the same:

1. A **trusted, auto-elevating binary** is present on the box
   (`fodhelper.exe`, `eventvwr.exe`, `computerdefaults.exe`, `sdclt.exe`,
   `slui.exe`, `utilman.exe`, `MRT.exe`, …).
2. That binary, **at elevation time, reads a config location you can write to
   as a normal user** — usually a registry key under `HKCU` or a specific
   `HKLM` subkey you have write on.
3. You **plant your payload pointer** in that config (a DLL path, a `Run`
   value, a CLSID).
4. You **trigger the binary**; it elevates, reads your pointer, and runs/loads
   your code high-integrity.

The variation between "bypasses" is *which binary* and *which config knob*
you flip.

## The candidates you'll actually use

- **fodhelper** (the modern default, Win10/11) — `fodhelper.exe` reads
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced` →
  `DefaultValues` (a registry key *name*) at launch, and loads a DLL from the
  CLSID that key points at. If you can create that key / control the CLSID's
  InprocServer32, a planted DLL is `LoadLibrary`'d elevated.
- **eventvwr** — `eventvwr.exe` reads
  `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EventViewer`
  → `CategoryGUIDs`; point it at your CLSID/DLL.
- **computerdefaults** — write a `Run` value into
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` (if you
  have write on that key); the elevated helper runs your value.
- **slui / sdclt / MRT** — older / build-specific variants of the same idea.
- **utilman / oobe** — the lock-screen / setup helpers that run elevated before
  logon (different context — useful for pre-auth footholds).

`fodhelper` is the one to reach for on current Windows; the rest are fallbacks
when the build or the ACLs differ.

## Tooling

- **UACME** (harnessSECURITY) — enumerates which candidates are live on the
  box and drives the bypass; the standard companion to
  [[windows-privilege-escalation|privesc]] enumeration.
- Manual (the quiet way) — set the registry pointer yourself, launch the
  binary, observe the elevated child. More control over the footprint than a
  tool that drops its own helper.

## Red-team notes (OPSEC)

- **You're not admin yet** — UAC bypass gives high integrity *as the current
  user*. If that user isn't in `Administrators`, you've climbed the UAC wall
  but not gained admin rights. Check the group first; UAC bypass is for
  *admin users filtered by UAC*.
- **fodhelper is build-sensitive** — the `DefaultValues` knob changed across
  Win10/11 builds. Enumerate with UACME rather than assuming.
- **A planted DLL under a trusted name is a tell** — an `fodhelper.exe` loading
  a DLL from an odd path is exactly what the EDR is watching. Prefer the
  manual, minimal footprint (one registry write + one launch) over a tool that
  drops a staged helper.
- **Clean the pointer** — delete the registry key / `Run` value after you use
  it, or it fires (and gets noticed) on every elevation.

## Detection

- **Integrity-level jump** — a **medium-integrity** parent spawning a
  **high-integrity** child where no consent prompt should have fired (Sysmon 1
  `Source Integrity Level` vs the process integrity; Event 4688 parent/child).
- **Registry writes** — a user-context process writing the `fodhelper` /
  `EventViewer` / `Explorer` config keys (Sysmon 13).
- **The trusted binary loading your DLL** — `LoadLibrary` from a non-system
  path into `fodhelper.exe`/`eventvwr.exe` (Sysmon 1/7 + callback).
- **UACME / known-bypass tooling** on disk or in the 4688 command line.

## Links

- [[windows-privilege-escalation]] — the hub; UAC bypass is the first rung
- [[token-privilege-escalation]] — the next rung (the token model itself)
- [[defense-evasion-ad]] — the integrity/EDR surface this lands in
- [[situational-awareness]] — confirming you're actually an admin user first
