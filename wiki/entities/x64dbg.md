---
title: "x64dbg (the Windows x64 debugger)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, reverse-engineering, debugger, dynamic-analysis]
---

# x64dbg

The **free, open-source x64 debugger** — the primary **dynamic-analysis**
tool in the [[reverse-engineering-workflow]]. Where [[ghidra]] is the
*static* pass (the *model* of the binary), x64dbg is the *dynamic* pass
(the *actual* execution: the *real* API calls, the *real* OEP, the *real*
memory). It's the tool you *step through* the [[packer-unpacking]] OEP,
*defeat* the [[anti-debugging]] checks, and *dump* the unpacked image.

## Why it's the default here

- **Free, x64-native, scriptable** — no license, a native x64 debugger
  (not a 32-bit debugger *emulating* x64), and a **scripting engine**
  (the *anti-debugging* defeats — the PEB zero, the timing-compare patch,
  the `NtQueryInformationProcess` hook — are *scripted*, not *manual*).
- **The *dump* is built-in** — the **memory dump** feature (the
  [[packer-unpacking]] step 2) is *native* (a right-click → dump → the
  unpacked PE). No *external* dumper needed (a *Scylla* is still better
  for the *header rebuild*; x64dbg's dump is the *raw* memory).
- **The *plugins*** — the **Scylla** plugin (the header rebuild), the
  **PEbief** plugin (the PEB view), the **API monitor** (the *actual* API
  calls) — the plugins are what make x64dbg a *malware* debugger, not a
  *crackme* debugger.

## The workflow (the dynamic pass)

1. **Load the sample** — x64dbg loads the PE (the *stub*, if packed). The
   **API monitor** starts logging the *actual* API calls (the *real*
   `VirtualAlloc`, the *real* `WriteProcessMemory`).
2. **The OEP find** — step through the stub; the **API monitor** shows the
   *point* where the IAT is *filled* (the [[packer-unpacking]] OEP
   marker). A **hardware breakpoint** on the OEP (the `jmp`/`ret` to the
   real code) stops the trace *exactly* at the OEP.
3. **The anti-debugging defeat** — the x64dbg **script** that zeroes the
   PEB `BeingDebugged`, patches the timing compare, hooks
   `NtQueryInformationProcess` — the [[anti-debugging]] defeat set,
   *scripted* (the *consistent* defeat, the anti-anti-debug doesn't catch
   the mismatch).
4. **The dump** — at the OEP, the **memory dump** → the *unpacked* image
   (the raw memory). A *Scylla* (the plugin) **rebuilds the headers** (the
   IAT, the section table, the OEP) into a *loadable* PE.
5. **The handoff** — the *unpacked* PE → [[ghidra]] (the *static* analysis
   of the *real* code, not the *stub*). The *dynamic* pass *feeds* the
   *static* pass.

## The *anti-anti-debugging* (the script's job)

The [[anti-debugging]] set is *defeated consistently* by the x64dbg
*script* — the *PEB zero* + the *timing-compare patch* + the
`NtQueryInformationProcess` hook *together* (the anti-anti-debug checks
that the *PEB* and the *API* agree; the script makes them *agree*). The
*manual* defeat (a *single* PEB zero) is *caught* by the anti-anti-debug
(the *mismatch*); the *scripted* defeat (the *consistent* set) is *not*.

## Red-team notes (the analyst's frame)

- **The *API monitor* is the *truth*** — the *disassembly* (the *static*)
  says what the binary *is*; the *API monitor* (the *dynamic*) says what
  the binary *does*. The *API monitor* is the *higher-fidelity* tell (the
  *actual* `NtWriteVirtualMemory` to `lsass.exe` is the *behavior*, not
  the *import*).
- **The *OEP* is the *gate*** — the [[packer-unpacking]] OEP is the *one*
  point where the *stub* ends and the *real* code begins; the *dynamic*
  pass *exists* to find that point (the *hardware breakpoint* on the OEP
  is the *precision* tool).
- **The *dump* is the *handoff*** — the x64dbg *dump* is the *bridge*
  between the *dynamic* (the *real* memory) and the *static* (the
  *analyzable* PE); the *Scylla* *header rebuild* is what makes the dump
  *analyzable* (a *raw* memory dump is *not* a *PE*).

## Links

- [[reverse-engineering-workflow]] — the dynamic pass this runs
- [[ghidra]] — the *static* counterpart (x64dbg is *dynamic*; Ghidra is
  *static*)
- [[packer-unpacking]] — the OEP find + the dump this does
- [[anti-debugging]] — the checks this defeats (the *scripted* defeat set)
- [[process-injection]] — the *injection* the API monitor *catches* (the
  *real* `NtWriteVirtualMemory`)
