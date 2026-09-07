---
title: "Process Injection (getting code to run in another process)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, malware, process-injection, post-exploitation]
---

# Process Injection

**Running your code in a process you don't own** — the core primitive of
Windows post-exploitation: dump LSASS from a trusted parent, hide in a
benign process's memory, escape a low-integrity sandbox, or run shellcode
with the *target's* token and loaded modules. Every technique answers the
same three questions: **how does the code get into the memory**, **how does
it start executing**, **what's the footprint**?

## The techniques (ranked by how often you meet them)

### CreateRemoteThread (the textbook)
`VirtualAllocEx` the payload → `WriteProcessMemory` → `CreateRemoteThread`
running `VirtualAlloc`/your function. Simple, **loud**: a new thread whose
entry point is in your allocated region, `NtWriteVirtualMemory` from you.
It's what `mimikatz`/`procdump`-style tools do when you don't care about
noise.

### APC injection (the quiet classic)
`NtQueueApcThread` an APC to a target thread **suspended at an alertable
wait** (`NtWaitForSingleObject`). The APC runs the payload **on the
thread's existing stack** — no new thread, no new thread object.
Footprint: `NtQueueApcThread` (an EDR watches it specifically). You need
the target to be *alertable* (or you wake it).

### Process Hollowing (the full swap)
Create the target **suspended** (`CREATE_SUSPENDED`) → unmap its initial
`.text` → write your PE's image in → patch the **OEP** in the context →
resume. The process is now *your* PE running under a *benign* name
(`explorer.exe` running your code). Loudest setup, best cover once running
— the on-disk file and the process name still look clean.

### Module Stomping (the EDR favorite)
Overwrite a **loaded module's** code section with your shellcode, then
return execution to that module's entry. No new allocation, no new thread,
no `VirtualAllocEx` — the code runs in a region that's *already* executable
and *already* trusted. EDRs alert on **module-integrity mismatch** (the
in-memory bytes ≠ the on-disk module), so it's a *trade*, not free.

### Thread Hijacking (reuse, don't create)
Suspend a **sleeping** thread, save its `rbp`/`rip`, point `rip` at your
code (in memory you allocated), run, then restore the context and resume.
No new thread object at all — the cleanest "start executing" step. The risk:
you share the thread's stack; corrupt it and the host thread dies.

### Callback Injection (hook the return path)
Hook a function the target calls (`EnumWindowsProc`, a COM callback,
`RtlUserThreadStart`) and run your code on the **return**. No memory write
to the target's code section; your code runs from *your* process's export
table (you export a function, the target calls into *you*). The most
sophisticated, the quietest.

## What the choice actually depends on

- **Do you need a new thread, or is reusing one enough?** — APC/hijack
  reuse; `CreateRemoteThread`/hollowing create.
- **Can you afford a memory-write tell?** — `WriteProcessMemory` (CRT) is
  the noisiest write; module stomping/callback avoid it.
- **Do you need the target's *identity* (token/modules), or just a
  trusted-parent footprint?** — hollowing/stomping give the full identity;
  CRT gives you your code under their name.
- **Is the target going to be inspected?** — if a defender looks at the
  process *while it's running*, hollowing/stomping are the ones that
  survive inspection (the name and the file are still plausible).

## Red-team notes (OPSEC)

- **Pick the target by *what it already is*** — inject into a process with
  the token/modules you need and a *plausible* name; `explorer.exe`/`svchost`
  running your code reads as "normal" longer than a random `cmd.exe`.
- **The write is usually the tell, not the exec** — `NtWriteVirtualMemory`
  from a low-priv process to a high-priv one is the classic alert;
  callback/stomping exist precisely to remove that write.
- **Preserve the host** — if you hijack/stomp a *critical* thread, the
  target crashes when you leave; pick a **sleeping, non-essential** thread,
  and restore the context *exactly* (the `rbp`/saved-`rip` dance).
- **It's a *transport*** — the payload is [[shellcode]]; the injection is
  just how it gets there. The two are analyzed separately: EDRs alert on
  the *injection shape* and the *shellcode shape* independently.

## Detection

- **`NtWriteVirtualMemory`** from an unusual source → the CRT/hollowing
  tell.
- **`NtQueueApcThread`** to a process that rarely takes APCs.
- **New thread in an allocated region** — a thread whose start address is in
  a `VirtualAlloc`'d block, not a module.
- **Module integrity mismatch** — in-memory bytes ≠ on-disk (hollowing /
  stomping).
- **Context switch anomaly** — a thread whose `rip` jumps into non-module
  code (hijack/callback).
- The **behavior after** (the payload dumping LSASS) is often the higher-
  fidelity alert — see [[credential-dumping]] / [[lsass]].

## Links

- [[shellcode]] — the payload being injected
- [[credential-dumping]] — the classic *reason* to inject (LSASS)
- [[lsass]] — the target of most injection
- [[windows-syscalls]] — the `Nt*` calls that are the actual footprint
- [[defense-evasion-ad]] — the EDR surface this lands in
- [[reverse-engineering-workflow]] — how a defender/analyst spots these
