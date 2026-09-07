---
title: "DLL Hijacking & Sideloading"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, dll, sideloading, binary-load]
---

# DLL Hijacking & Sideloading

**Getting a *higher-privileged* process to load *your* DLL.** When a Windows
process loads a DLL by name (via the import table at start, or a runtime
`LoadLibrary`), it resolves the path through a **search order**. If you can
place a DLL of the right name in a directory that's *higher* in that order
than the real one — and that directory is writable by you — the privileged
process loads *your* code, running it at *its* privilege.

Two flavours:
- **Search-order hijack** — the target app is looking for a DLL that's *missing
  or resolvable elsewhere*; you put yours where it'll be found first.
- **Sideloading** — the target is a **trusted, signed** app; you drop a
  sidecar DLL next to it so the signed parent loads your (unsigned) DLL.
  Stronger against EDR because the *parent* is a known-good binary.

This is a [[windows-privilege-escalation|local privesc]] because the loader is
running higher than you (a service, an admin logon helper, a scheduled task's
app). It's also the payload-delivery layer of a lot of malware
([[pe-executable]], [[reverse-engineering-workflow]]) — a sidecar DLL is the
quasi-benign way to get code running under a trusted name.

## The DLL search order (the thing you're attacking)

For a process loading `foo.dll`, Windows checks, in order:

1. The directory the **executable** was launched from.
2. The **system** directory (`System32`).
3. The 16-bit system directory.
4. The **Windows** directory.
5. The **current** working directory.
6. The directories in the **`PATH`** environment variable.

The attack: find a target process whose *intended* `foo.dll` is **absent from
the higher-priority paths**, then place your `foo.dll` in the highest path you
can write to. The closer you are to #1/#5 (app dir / current dir), the more
reliable the hijack. (The modern default is *SafeDllSearchMode*, which reorders
current dir *after* system dirs — check it, don't assume.)

## Finding the hole (the recon)

The standard method is **Process Monitor**:

1. Filter ProcMon to the **target process** (the high-priv one).
2. Watch for DLL load attempts that return **`NAME NOT FOUND`** — those are the
   DLLs the app wants but can't find in the paths already checked.
3. For each `NAME NOT FOUND`, note the **search paths** Procmon shows and which
   of them **you can write to**.
4. Drop your `foo.dll` in the writable, highest-priority path. Trigger the app.

`DLLHijacker` automates the "find writable search-order spots" step; Procmon is
the manual truth. The tell you're hunting: a high-priv app that *fails* to find
a DLL in a path you control.

## Building the payload (the DLL you drop)

Your `foo.dll` needs to at minimum **load and run** when the app imports it —
the `DllMain` (or the exported functions the app calls) is your code path. For
a privesc you typically:
- build a DLL that, on load, spawns your shell / reverse-connects / drops your
  payload,
- or export the *specific functions* the app calls (so the app doesn't error
  out) and run your code in one of them.

See [[pe-executable]] (the import/export layout) and
[[reverse-engineering-workflow]] (building + testing the DLL). Keep it tiny — a
DLL that loads, fires, and exits is quieter than a DLL that links half the CRT.

## Sideloading specifically (the trusted-parent variant)

Here the target is a **signed, trusted** app you *can't* modify, but whose
directory (or a higher search path) you *can* write to, and which loads a DLL
by name you can supply. You place your DLL so the **signed parent** loads it:

- The EDR sees `C:\Program Files\TrustedApp\trusted.exe` (known-good, signed)
  load `...\TrustedApp\sidecar.dll` (yours) — the *parent* passes the
  allowlist, the child code is yours.
- This is the workhorse against **parent-whitelist / "is the parent signed?"**
  EDR logic, and it's how a lot of in-the-wild loaders get code running under
  a trusted name.

## Tooling

- **Procmon** — the recon (the `NAME NOT FOUND` + search-path truth).
- **DLLHijacker** — automate the writable-search-order discovery.
- **x64dbg** — breakpoint on the DLL load / the app's import to confirm *which*
  path resolves (the dynamic confirmation before you commit).
- **A tiny custom DLL** — the payload (build per [[pe-executable]]).

## Red-team notes (OPSEC)

- **The parent's trust is the point** — for sideloading, *pick* a parent that's
  genuinely trusted and signed on that box (not one the EDR already watches
  closely). A `svchost.exe`-adjacent loader is more believable than a fresh
  drop.
- **One load, then you're in** — the DLL fires on the app's next start. Time
  the trigger (logon, service start, your `schtasks /run`) and be ready to catch
  the shell.
- **Don't break the app** — if your DLL is missing an export the app *requires*,
  the app crashes (and the crash is a tell). Export what it calls, or hook only
  `DllMain`.
- **Clean the sidecar** — a stray `sidecar.dll` next to a trusted app is a
  persistence *and* a privesc breadcrumb; remove it after you've pivoted.

## Detection

- **A DLL loaded from a non-standard path into a privileged / signed process**
  (Sysmon 7 ImageLoad — `ImageLoaded` path not in `System32`/the app dir).
- **Signed parent + unsigned DLL** — the sideloading signature (the parent is
  known-good, the loaded module is not).
- **Procmon `NAME NOT FOUND` → later success from a different path** — the
  hijack sequence (the app failed to find the real DLL, then loaded yours).
- **The app-dir DLL that wasn't there before** — a new `*.dll` in
  `C:\Program Files\...` with a recent timestamp + a high-priv load.

## Links

- [[environment-variable-attack]] — the sibling (executables via PATH/PATHEXT, not DLLs)
- [[pe-executable]] — the DLL's import/export layout
- [[reverse-engineering-workflow]] — building + testing the sidecar DLL
- [[windows-privilege-escalation]] — the hub
- [[winpeas]] — flags the writable search-order spots
