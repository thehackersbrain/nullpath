---
title: "Shellcode (x86/x64 position-independent payloads)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, shellcode, malware, exploit, assembly]
---

# Shellcode

**Position-independent machine code** that runs wherever it's dropped —
stack, heap, `VirtualAlloc`'d memory, another process's space. It's the
payload end of [[process-injection]] and the primitive behind most
post-exploitation: you're handing a *context* (a register state, a stack,
maybe no stack at all) and the code has to **bootstrap everything** —
resolve APIs, allocate, then do the job.

## The x64 constraints that actually bite

- **No `main` to rely on** — no guaranteed stack. A shellcode thread via
  `CreateThread` gets a *small* stack (often 1 KB) that's **4KB-aligned,
  not 16B-aligned** — you must fix `rsp` before the first API call:
  ```asm
  ; align rsp to 16 bytes (calling convention requirement)
  push rsp
  and  rsp, 0FFFFFFFFFFFFFFF0h
  ```
- **The calling convention is mandatory** — Windows x64: args in
  `rcx, rdx, r8, r9`; **`rsp` 16-byte aligned on call**; `rcx` clobbered.
  Misalign and `memcpy`/`strlen` silently crash (they use SSE `movaps`).
- **`call [rip+disp32]` is the x64 sin** — a 32-bit relative call can't
  reach far; shellcode uses a register-indirect call
  (`mov rax, [GetProcAddress]` → `call rax`).
- **Position independence** — no absolute addresses. Resolve everything via
  the module's IAT/PEB or [[api-hashing]]; `LoadLibrary`/`GetProcAddress`
  from the module's own import table is the standard bootstrap.
- **Avoid null bytes** — when shellcode crosses a `strcpy`/`strcat`
  boundary, an embedded `\0` truncates it. (Matters less for
  `VirtualAllocEx`-style injection, critical for string-based overflows.)

## The canonical bootstrap (what every loader does)

1. Walk the **PEB** (`gs:[0x60]` on x64) → find the base of
   `kernel32.dll`/`ntdll.dll` in the loaded-module list (no `LoadLibrary`
   needed — the module is already mapped).
2. Read its **export directory** → resolve `GetProcAddress`,
   `VirtualAlloc`, `CreateThread`, etc. — either by name or by
   [[api-hashing]] (nameless = no strings in the payload).
3. `VirtualAlloc` the payload (if not already in memory), `CreateThread`
   (or APC/thread-hijack) to run it.

This is why **PEB-walking** shows up in nearly every x64 shellcode and why
it's a detection tell (repeated `gs:`-relative reads + export-walk pattern).

## x86 (32-bit) — the easy cousin

No stack-alignment requirement, `call [addr]` with a 32-bit absolute
address works, single `ecx`-style register conventions — 32-bit shellcode
is shorter and more forgiving; it's what most HTB/CTF Linux/Windows boxes
still hand you. MSVC x86: arg order right-to-left on the stack; GCC/clang:
`esi, edx, ecx, eax`.

## Red-team notes (OPSEC)

- **The bootstrap *is* your signature** — PEB walk + export walk +
  `CreateThread` is a known pattern; EDRs alert on it. Variants: resolve
  `ntdll!NtCreateThreadEx` directly ([[windows-syscalls]]), APC-inject
  instead of `CreateThread` (no new-thread 8-byte
  `Teb`-init footprint in some stacks), or **thread-hijack** a sleeping
  thread (reuse its stack — no alloc tell).
- **Stack you get is a stack you lose** — a `CreateThread` stack is *yours*
  to clobber; a hijacked thread's stack is *shared* — preserve `rbp`/saved
  `rip` or you kill the host thread on return.
- **Position-independent ≠ position-agnostic** — if you're injected into a
  specific process, that process's module list *is* your dependency; a
  shellcode that needs `user32.dll` fails in a service that never loaded it.
  Target the APIs of the *least-privileged* module set.
- **Nulls and bytes matter by transport** — string-based: no `\0`, often no
  `\n`/`\r` (line-based parsers); `VirtualAllocEx`: anything goes, keep it
  short.

## Detection

- **PEB/export-walk pattern** — the `gs:[0x60]` → module-list → export
  sequence (EDR code-signature on the *shape* of the instructions).
- **Memory + behavior** — `VirtualAlloc` `PAGE_EXECUTE_READWRITE` + a new
  thread running from it is the classic "shellcode in memory" tell
  (Sysmon 5/10 + a process whose `.text` doesn't match its on-disk PE).
- **Syscall mix** — a thread calling `NtCreateThreadEx`/`NtQueueApcThread`
  with no reason to.

## Links

- [[pe-executable]] — the module whose exports you walk
- [[api-hashing]] — nameless API resolution (no strings)
- [[process-injection]] — the transports that deliver shellcode
- [[windows-syscalls]] — direct `Nt*` resolution (EDR-quieter)
- [[ghidra]] — reading someone else's shellcode
- [[reverse-engineering-workflow]] — the analysis side
