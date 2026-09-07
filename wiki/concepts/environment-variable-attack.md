---
title: "Environment Variable Attack (PATH / PATHEXT)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, path, pathext, environment, local]
---

# Environment Variable Attack

**Making a *higher-privileged* process resolve and run *your* executable by
polluting the name-resolution it depends on: the `PATH` and `PATHEXT`
environment variables.** When an elevated shell (or a service, or a
[[scheduled-task-abuse|scheduled task]]) runs a command **without a full path**
— `net user`, `whoami`, `python script.py` — Windows finds the executable by
searching the directories in **`PATH`**, trying the extensions in **`PATHEXT`**
in order. If a directory you can **write to** appears in that search before the
real binary's directory, you drop a file of the same name and the elevated
context runs *your* code.

This is the **executable** sibling of [[dll-hijacking-sideloading]] (which is
the *DLL* search order). Same "right name in a writable, higher-priority
directory" idea; different variable, different file type.

## The two variables

- **`PATH`** — the ordered list of directories searched for an executable when
  a command has no directory component. **First match wins.** A writable
  directory early in `PATH` is the hole.
- **`PATHEXT`** — the ordered list of **extensions** tried when the command
  has none (default `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.CPL;…`).
  This is what lets a **`.bat`/`.cmd`** you drop satisfy a call to `net` — the
  shell tries `net.COM`, `net.EXE`, `net.BAT`, … and runs the first it finds.

## The classic: drop `net.exe` (or `net.bat`) where PATH looks first

The canonical demonstration, and still a real finding:

1. An elevated/admin context runs a bare command, e.g. `net localgroup` or
   `whoami` — resolved via `PATH`, not `C:\Windows\System32\net.exe`.
2. A **writable directory appears in `PATH`** before `System32` (e.g. `C:\`,
   `C:\Users\Public`, a user-writable folder an admin session inherits).
3. You drop **`net.bat`** (your payload, via the `PATHEXT` extension trick) or
   **`net.exe`** in that writable directory.
4. Next time the elevated context runs `net …`, it resolves **your** file first
   → **code execution at that elevated privilege.**

```bat
:: the recon — what will the elevated context actually resolve?
echo %PATH%
echo %PATHEXT%
:: find a writable dir in %PATH% that precedes System32, then:
echo <your command> > C:\Users\Public\net.bat
:: (or a real net.exe you compiled) — next elevated `net ...` runs it
```

The `PATHEXT` angle is the quiet one: a **`.bat`** needs no compiler and no
PE signature, and a `.bat`/`.cmd` executing in a high-integrity context is
*exactly* what the box's own admin scripts do, so it's easy to miss.

## Where the elevated context comes from

The attack needs a **higher-priv process that resolves bare commands**. Sources:
- An **admin's interactive/elevated shell** (UAC-elevated, or a remote admin).
- A **[[service-privesc|service]]** or **[[scheduled-task-abuse|task]]** whose
  action is a bare command / script (see the task page's "script/interpreter"
  vector — it leans directly on this).
- A **logon script / GPO-pushed command** that runs as a user with a polluted
  inherited `PATH`.

The environment-variable attack is the *mechanism*; the service/task/logon
script is the *elevated consumer* you're feeding.

## Tooling

- **[[winpeas]]** — flags `PATH`/`PATHEXT` attack surface (writable dir in
  `PATH`, the `PATHEXT` extension set).
- **PowerUp** (`Invoke-PathHijack` / the PATH checks) — the PowerShell audit +
  the drop.
- **Manual** — `echo %PATH%`, find the writable prefix, drop the file. The
  quietest (no tool name on disk).

## Red-team notes (OPSEC)

- **`.bat` over `.exe`** — a dropped `net.bat` leaves no PE, no hash, no
  signature question. Use it unless the consumer specifically wants an `.exe`.
- **Match the exact command the elevated context runs** — if it runs `net
  localgroup`, your file must be named `net.*`, not `netlocalgroup.*`. Get the
  *bare command name* from the consumer (the service/task action, the admin's
  habit), not a guess.
- **First-match is the whole game** — if `System32` precedes your writable
  dir in `PATH`, the real `net.exe` wins and your drop is inert. Confirm the
  *order*, not just membership.
- **It's a time bomb you arm** — your file sits there until the elevated context
  next runs the command. Know the trigger (logon, task schedule, the admin's
  next `net` call) or you'll wait.

## Detection

- **A high-integrity process running a `.bat`/`.cmd`** from a user-writable or
  non-system directory (Sysmon 1 `ImagePath` + the parent; 4688).
- **`PATH`/`PATHEXT` change** — an environment mutation that inserts a
  writable directory (Event 4688 command line / a process whose `PATH` differs
  from baseline).
- **The resolution anomaly** — an elevated `net`/`whoami`/`python` whose
  resolved `ImagePath` is *not* `System32` (the tell that a writable prefix
  won the search).
- **A new `*.bat`/`*.exe` in a `%PATH%` dir** with a recent timestamp that an
  elevated process then executes.

## Links

- [[dll-hijacking-sideloading]] — the DLL-search-order sibling
- [[service-privesc]] — an elevated service that resolves bare commands
- [[scheduled-task-abuse]] — a task action that's a bare script/command
- [[windows-privilege-escalation]] — the hub
- [[winpeas]] — the enumeration that flags this
