---
title: "AMSI (Antimalware Scan Interface) and its bypasses"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, malware, amsi, defense-evasion, edr]
---

# AMSI (Antimalware Scan Interface)

**The Windows API that lets a script engine (PowerShell) ask the
antimalware engine to scan a script *before* it runs.** `AmsiScanBuffer`
is the call: PowerShell (and .NET, and a few other engines) hands the
script text to AMSI, AMSI hands it to the AV/EDR, the engine returns
`Success`/`Detected`. It's the **scripting-language** layer of malware
detection — the reason a *PowerShell* payload gets caught even when the
*.exe* that launched it is clean. **Amsi bypass** is the art of making
`AmsiScanBuffer` return "clean" without the engine actually scanning.

## How AMSI works (the model)

1. **PowerShell compiles the script** into an AST (the `System.Management.Automation`
   pipeline), and **calls `AmsiScanBuffer`** with the script text *before*
   executing it.
2. **AMSI forwards to the registered AM-Provider** (the AV/EDR's AMSI
   provider — the one that does the actual scan).
3. **The provider returns a result** — `AMSI_RESULT_SUCCESS` (clean) or
   `AMSI_RESULT_DETECTED` (block). PowerShell *obey*s the result (it
   throws / doesn't run the script).

The key: **the scan is a *call* from PowerShell into a known function**
(`AmsiScanBuffer` in `amsi.dll`). The bypass is **intercepting that call**
— not hiding the script, not hiding the process, *making the call return
clean*.

## The standard bypasses (what you'll meet)

### The `AmsiScanBuffer` patch (the classic)
`amsi.dll`'s `AmsiScanBuffer` starts with a **`48 89 5C 24 08`** (a
`mov [rsp+8], rbx`) prologue, and its "clean" path jumps over the
"detect" path. The bypass: **find `AmsiScanBuffer` in memory**, **patch
the first bytes** to a `ret` (or to the "clean" return) so every scan
returns `Success`. The **specific bytes** matter (they change per Windows
build / per `amsi.dll` version) — that's why the bypass is **version-
specific** (a patch that works on Win10 21H2 breaks on Win11 23H2).

```c
// the shape (the actual bytes vary per build)
// find AmsiScanBuffer (export of amsi.dll)
// patch its entry to: 48 83 EC 28 EB xx ... (a "clean" prologue + ret)
```

### The `AmsiScanBuffer` hook (the robust one)
Instead of *patching* the function (fragile per version), **hook** it:
replace its entry with a jump to **your** function, which returns
`AMSI_RESULT_SUCCESS` immediately. The hook is **version-independent**
(you hook the *export*, not the *bytes*) — it survives a Windows update
that changes the prologue. The EDR counter is a **hook-integrity check**
(it checksums `amsi.dll`'s exports; a modified entry = a hook).

### The `AmsiUtils` / `AmsiInitialize` bypass (the .NET one)
For **.NET** payloads (the ones that don't go through PowerShell's
`AmsiScanBuffer` the same way), the bypass targets **`AmsiUtils`** (the
.NET AMSI helper) or the **`IAmsiScan`** COM interface — the same idea
(return "clean"), a different entry point. The .NET AMSI surface is
*separate* from the PowerShell one; a PowerShell-only bypass **misses the
.NET payload** (and vice versa).

### The "no AMSI" engines (the sidestep)
Some engines **don't call AMSI at all** — a **C# payload run via
`csc`/`dotnet`** (not PowerShell), a **WASM** payload, a **COM-based**
script host. If the engine doesn't call `AmsiScanBuffer`, there's nothing
to bypass — the payload just *doesn't go through AMSI*. The tell is the
**engine choice** (a `csc.exe`/`dotnet.exe` spawning a payload instead of
`powershell.exe`).

## The EDR counter (why the bypass is a *race*)

- **The `amsi.dll` integrity check** — the EDR **checksums `amsi.dll`'s
  exports** (`AmsiScanBuffer`, `AmsiInitialize`); a modified entry (a
  patch or a hook) is a tell. The bypass has to **patch in a way the
  checksum doesn't catch** (a *self-modifying* patch that restores the
  bytes after the call, or a *hook in a module the EDR doesn't checksum*).
- **The "clean result" anomaly** — a script that's *obviously* malicious
  (a `DownloadString` + `IEX` one-liner) that AMSI returns `Success` for
  is a **behavioral tell** (the engine *should* have caught it). The EDR
  correlates the "clean AMSI result" with the *subsequent* behavior (a
  process spawn, a network connect) — the clean result *plus* the
  suspicious behavior is the alert, not the clean result alone.
- **The `amsi.dll` load timing** — a process that loads `amsi.dll` *and*
  immediately patches it (a tight load→patch window) is a **patch-in-
  progress** tell; the EDR watches the load + the first write to
  `amsi.dll`'s text section.

## Red-team notes (OPSEC)

- **The bypass is *version-specific* unless you hook** — a *byte patch*
  breaks on every Windows update; a **hook on the export** is portable.
  For a payload that has to run on *many* hosts (a red-team op), the
  **hook is the default**; the byte patch is the *fast* one for a
  *known* target.
- **The PowerShell vs. .NET split is real** — a payload that's
  PowerShell *and* .NET (a `powershell -c` that runs a .NET assembly)
  needs **both** bypasses (the `AmsiScanBuffer` *and* the `AmsiUtils`);
  bypass one and the other engine still scans.
- **The sidestep is the quietest** — a payload that *doesn't go through
  AMSI* (a `dotnet`-run .NET, a COM script host) leaves no AMSI patch
  tell at all; the cost is the *engine choice* tell (a `dotnet.exe`
  spawning a payload is *less* expected than a `powershell.exe` one).
- **The *behavior* still shows** — AMSI bypass hides the *script scan*;
  it doesn't hide the *process spawn*, the *network connect*, the
  *file write*. The EDR's **behavioral** detection (the post-AMSI events)
  is what the bypass *doesn't* beat — see [[defense-evasion-ad]].

## Detection

- **The `amsi.dll` text-section write** — a **write to `amsi.dll`'s code
  section** (a patch) or a **modified export entry** (a hook) is the
  direct tell (Sysmon 4688/10 + a memory-write correlation).
- **The "clean AMSI + suspicious behavior" correlation** — a script that
  AMSI clears but that *then* spawns a process / connects to the network
  is the *behavioral* tell (the EDR knows the script *should* have been
  caught).
- **The AMSI result log** — some EDRs **log the AMSI result per script**;
  a `AMSI_RESULT_SUCCESS` for a high-risk script (an `IEX` + a
  `DownloadString` to an unusual domain) is a *logged* tell, even when
  the patch is clean.

## Links

- [[defense-evasion-ad]] — the EDR/AMSI/ETW evasion hub this belongs to
- [[etw]] — the *other* script-detection layer (ETW is the event side,
  AMSI is the scan side)
- [[reverse-engineering-workflow]] — where an AMSI bypass is *reversed* (the
  patch/hook is statically findable)
- [[beaconing]] — the C2 an AMSI-bypassed script often talks to
- [[windows-syscalls]] — the "skip the user-mode API" layer (the same
  evasion principle, a different API)
