---
title: "Anti-Debugging (malware checks for a debugger)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, malware, reverse-engineering, anti-debugging, analysis]
---

# Anti-Debugging

**Malware that checks whether it's being debugged, and behaves differently
(or hides its payload) if it is.** It's the analysis-side counterpart to
[[anti-analysis]] (which targets the *VM/sandbox*, not the *debugger*).
Understanding the checks is how you **defeat them in your debugger**;
knowing what they leave behind is how a **defender detects the malware**
either way.

## The standard checks (what you'll actually meet)

### PEB flags (the cheap ones)
- **`BeingDebugged`** — `PEB.BeingDebugged` (offset `0x2` on x64) is set
  when a debugger is attached. Malware reads it via `gs:[0x60]` and
  branches. **Defeat:** zero the byte in your debugger before you hit
  continue (it's just a flag — the debugger doesn't enforce it).
- **`NtGlobalFlag`** — `PEB.NtGlobalFlag` encodes
  `FLG_DISABLE_EXCEPTION_LOGON`/`FLG_HEAP_TERMINATE` etc.; a non-zero
  value under normal execution is a debug tell. **Defeat:** set it to `0`
  in your debugger.

### The API (the obvious one)
- **`IsDebuggerPresent()`** — reads `PEB.BeingDebugged`. Trivial to hook in
  your debugger (return `FALSE`), or to **inline-patch** the binary
  (find the call, NOP it). The malware *knows* you'll patch it, so it's
  usually **one of many** checks, not the only one.

### Timing (the classic)
- **`GetTickCount`/`QueryPerformanceCounter` diff** — call a fast function,
  measure the delta; a debugger (single-stepping, breakpoints) makes it
  slow. **Defeat:** don't single-step through it, or **patch the compare**
  to always take the "fast" branch. It's the check that's hardest to
  *spoof* and easiest to *branch past*.

### `Int 3` / `DbgBreakPoint` (the self-trap)
- The malware calls `__debugbreak`/`int 3` **on purpose** — if a debugger
  is attached, it catches the exception; if not, it's a (mostly) harmless
  exception the malware handles. **Defeat:** let your debugger catch it and
  continue, or **hook the exception handler**.

### `CheckRemoteDebuggerPresent` (the handle check)
- Passes `NtCurrentProcess` and a handle to `kernel32`; returns whether a
  remote debugger is attached. **Defeat:** hook it to return `FALSE`.

### The `LastError` trick (the subtle one)
- Call `GetCurrentProcess()` (which sets `LastError`), then
  `GetLastError()` — under a debugger the sequence can return a different
  value (a `0` vs non-`0` tell). **Defeat:** patch the `GetLastError`
  call or the compare.

## The *real* anti-debugging (what actually stops you)

- **The debugger *is* the input** — some malware doesn't just check for a
  debugger; it **reads your debugger's state** (is a breakpoint set at
  `X`? is single-stepping on?) and **changes its logic** — e.g. "if
  `IsDebuggerPresent` is patched, take the *other* path." The check is
  **about your *response***, not just the flag. This is why "zero the PEB
  flag" isn't enough: the malware verifies *how* you zeroed it.
- **Anti-anti-debugging** — the malware **checks that you *didn't* patch
  `IsDebuggerPresent`** (it calls it, and also reads the PEB directly; if
  the two disagree, you patched one and not the other → debugger). The
  defense is to **patch *all* the redundant checks consistently**, or to
  **not patch at all** and let it think it's clean (sometimes the "clean"
  path is the *interesting* one).
- **The `NtQueryInformationProcess` check** — query
  `ProcessDebugPort`/`ProcessDebugObjectType`; a non-`NULL` debug port
  means a debugger. **Defeat:** hook `NtQueryInformationProcess` to return
  `NULL`.

## How to *use* this (the analysis workflow)

1. **Static pass first** — find the checks in the disassembly
   ([[ghidra]]): `IsDebuggerPresent` imports, `gs:[0x60]` PEB reads,
   `GetTickCount` pairs, `int 3` / `cc` bytes, `NtQueryInformationProcess`
   with `ProcessDebugPort`.
2. **Set a breakpoint on the *branch*, not the call** — you want to see
   *which* path it takes, so break on the `jne`/`je` *after* the check.
3. **Defeat consistently** — if you patch `IsDebuggerPresent`, patch the
   PEB read too (or the anti-anti-debug catches the mismatch).
4. **If the "debugged" path is the boring one** — let it think it's
   debugged (do *nothing*) and see if the *other* path is the real payload.
   Sometimes the anti-debug **hides the payload** in the debugged branch.

## Red-team notes (dev side)

- **Redundancy beats cleverness** — one check is patchable; **five
  redundant, mutually-verifying checks** (PEB + API + timing + `NtQuery` +
  `LastError`) are a real cost to the analyst. The checks don't have to be
  *hard*, they have to be *many and cross-verifying*.
- **The timing check is your best cheap defense** — it's the hardest to
  spoof without a debugger plugin; most analysts just branch past it, which
  tells you *where* the payload is (the timing check guards the interesting
  code).
- **Don't over-invest** — anti-debugging buys you *time*, not *secrecy*; a
  determined analyst with a debugger and 30 minutes gets through the
  standard set. Spend the effort on [[anti-analysis]] (the VM/sandbox
  checks) instead, which is what keeps the *casual* analysis from finding
  the payload.

## Detection (defender side)

- **The checks are the tell** — a process calling
  `IsDebuggerPresent`/`NtQueryInformationProcess(ProcessDebugPort)`
  repeatedly, or reading `PEB.BeingDebugged`, is *checking for a debugger*
  (malware does this; normal apps usually don't).
- **The timing spike** — a `GetTickCount` pair with a large delta under
  normal (non-debugged) execution is a **timing anti-debug** firing — the
  malware is reacting to *something*.
- **The `int 3` in the wild** — a process that raises
  `EXCEPTION_BREAKPOINT` and *handles it* (doesn't crash) is running a
  self-trap.

## Links

- [[anti-analysis]] — the VM/sandbox-side counterpart
- [[packer-unpacking]] — packers and anti-debugging are often paired
- [[reverse-engineering-workflow]] — where these checks are defeated
- [[ghidra]] — finding the checks statically
- [[x64dbg]] — the debugger you're evading (and the tool that defeats it)
