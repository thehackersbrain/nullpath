---
title: "Windows Direct Syscalls (Nt* functions, unhooking)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, malware, syscalls, evasion, edr]
---

# Windows Direct Syscalls

**Call the kernel directly, skipping the user-mode API layer.** User-mode
APIs (`CreateFile`, `VirtualAlloc`) live in `kernel32`/`kernelbase` and
**tail-call** into the real kernel entry points — the `Nt*`/`Zw*`
functions in `ntdll`. An EDR **hooks the user-mode API** (a detour patch
at the function's start) to see every call; the kernel entry point itself
isn't hooked the same way. Calling `Nt*` **directly** — with your own
syscall stub — means the EDR's user-mode hook never fires.

## Why the API ≠ the syscall

```
your code
  └─> kernel32!CreateFileW        ← EDR hooks *here* (detour patch)
        └─> ntdll!NtCreateFile     ← the real kernel entry (syscall)
              └─> kernel
```

- `kernel32`/`kernelbase` functions are **thin wrappers** that just
  `jmp`/`call` into `ntdll!Nt*`. The *work* happens at the `Nt*` boundary.
- `ntdll!Nt*` ends with the **`syscall` instruction** (x64: `mov r10, rcx`
  → `syscall`), the actual transition to the kernel.
- An EDR that only patches the user-mode wrapper misses a caller that
  **jumps straight to the `syscall` instruction** (or to the `Nt*` function
  via a *self-resolved* pointer, bypassing the wrapper).

## The three direct-syscall styles

1. **`syscall` stub (inlined)** — your code resolves the `Nt*` function's
   address (PEB/export walk or [[api-hashing]]), then **copies the last
   instructions** (the `mov r10, rcx; syscall` pair, sometimes a short
   prologue) into your own code and jumps there. The EDR sees a `syscall`
   from *your* memory, not a call through `kernel32`.
2. **`Nt*` trampoline** — resolve `ntdll!NtReadVirtualMemory`'s address and
   `call` it directly (skipping the `kernel32` wrapper). Quieter than (1)
   in some stacks (you still go through `ntdll`, but not the hooked
   wrapper). Many EDRs also hook `ntdll!Nt*` — so this is *less* stealthy
   than (1) on modern stacks.
3. **Syscall number (the robust one)** — instead of resolving the function
   *by pointer* (which breaks if `ntdll` is patched), use the **syscall
   number** (a per-OS-version index into the kernel's syscall table). Your
   stub does `mov eax, <number>` → `syscall`. The number is stable and
   doesn't depend on `ntdll`'s in-memory state. This is the gold standard
   — and the one that breaks on every Windows update (the numbers
   renumber).

## Getting the syscall number / address (the fragile part)

- **Parse `ntdll`'s exports** — find `NtReadVirtualMemory`, read the bytes
  at the end of the function to extract the `syscall` stub (styles 1/2).
- **Brute the syscall table** — the kernel's syscall table isn't directly
  exportable; the number is usually **hardcoded per build** (a table in
  your malware, maintained per Windows version) or **discovered by
  fingerprinting** (call each number with canary args, see which one does
  what — slow, but self-updating).
- **The `mov r10, rcx` detail** — the x64 `syscall` convention moves the
  first arg into `r10`; a stub that skips it passes args wrong. This is
  the #1 "my direct syscall crashes" bug.

## Red-team notes (OPSEC)

- **It's a *race*, not a guarantee** — modern EDRs (the ones that matter)
  also **hook the `syscall` instruction** (a hardware breakpoint / a patch
  at the `ntdll` `Nt*` entry, or kernel-mode callbacks). Direct syscalls
  beat *user-mode-only* hooking; they don't beat a kernel-mode EDR.
  Decide what you're evading *before* you build the stub.
- **Match the target's Windows build** — a syscall number that's right on
  Win10 1903 is wrong on Win11 23H2. A payload that hardcodes one table
  breaks on the other; a PEB/export-walk that resolves by *name* is more
  portable but noisier.
- **Combine the layers** — the quietest modern payload: PEB walk → resolve
  `ntdll` → **api-hash** the `Nt*` you need → **syscall-number stub** →
  call. Each layer removes one fingerprint (no strings, no wrapper hook,
  no `ntdll` pointer dependency).
- **The *behavior* still shows** — a direct syscall to
  `NtReadVirtualMemory` on `lsass.exe` is detectable **in the kernel**
  (the kernel knows you read LSASS's memory); direct syscalls hide the
  *user-mode call*, not the *kernel event*.

## Detection

- **`syscall` from non-`ntdll` memory** — the `syscall` instruction
  executed in a `VirtualAlloc`'d region or your own module (not `ntdll`).
- **`ntdll` integrity** — the `Nt*` function's first/last bytes modified
  (a trampoline/hook) — EDRs checksum `ntdll`'s exports.
- **Kernel-side** — the syscall *itself* (a kernel callback sees
  `NtReadVirtualMemory` regardless of how you entered it).
- **The mismatch that gives it away** — a process making a syscall with an
  argument pattern its normal behavior never produces.

## Links

- [[shellcode]] — the payload that needs a syscall stub
- [[api-hashing]] — resolving the `Nt*` by name without strings
- [[process-injection]] — the `Nt*` calls that are the injection footprint
- [[defense-evasion-ad]] — the EDR surface this is built against
- [[pe-executable]] — the `ntdll` you're parsing
