---
title: "API Hashing (nameless API resolution)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, malware, shellcode, api, evasion]
---

# API Hashing

**Resolve imported functions without their names in the binary.** The
import table is the easiest static fingerprint a PE has
([[pe-executable]]); malware developers erase it by computing each API's
**hash** at runtime and matching it against the export table. No
`"GetProcAddress"` string in `.rdata` → the string-search detector finds
nothing.

## How it works

For each target API (`kernel32!VirtualAlloc`):

1. Precompute (build time) a hash of the **name** — the canonical
   **djb2** variant is the standard:
   ```c
   // djb2 (the one everyone uses)
   uint32_t hash = 5381;
   for (const char* c = "VirtualAlloc"; *c; c++)
       hash = ((hash << 5) + hash) + *c;   // hash*33 + c
   ```
2. At runtime, walk the module's **export directory**, hash each export
   name the same way, compare to the precomputed value → get the function
   pointer.

The hash is just a constant in the code (`0x...`), so the payload is
**string-free** — no `LoadLibraryA`/`"kernel32.dll"` to grep for (you walk
the **PEB** for the module instead — see [[shellcode]]).

## Variants you'll meet in the wild

- **djb2** — by far the most common (the hash above); tooling can compute
  it instantly from a function name, so "it's djb2" is a known quantity.
- **FNV-1a** — the other common one; also trivially computed.
- **Per-build salted hashes** — a unique salt per build defeats a static
  "known hash → API" DB; you have to *brute the exports* at analysis time
  (still fast: hash every export, compare).
- **Hash of (module + function)** — some malware hashes
  `kernel32.dll!VirtualAlloc` together (one hash per *import*, not per
  function name) — module lookup and function lookup collapse into one.
- **Double hashing / hashed-by-hash** — rare; the inner hash is recomputed
  in code (slower to reverse).

## Red-team notes (dev side)

- **djb2 is fine** — it's the de-facto standard and every RE tool decodes it;
  the value of the hash *isn't* the secret, the **absence of the string**
  is. Salt only matters against a *specific* DB, not against a human with
  Ghidra.
- **Hash the *resolved* export, not a guess** — a wrong hash = `GetProcAddress`
  returns `NULL` = silent crash on first call. Build-time test: dump the
  computed hash and verify it against the target's export table.
- **Combine with direct syscalls** — hashing kills the *name* fingerprint;
  calling through `ntdll`'s exports still leaves a `GetProcAddress`-style
  export walk. The quietest combo: PEB walk → resolve `ntdll` → hash-resolve
  the `Nt*` function you need → [[windows-syscalls]].
- **It's a *smell*, not a stealth** — analysts expect it; the real signal is
  **what you resolve and when** (a process resolving
  `NtReadVirtualMemory` is more interesting than the hashing technique).

## Detection

- **Export-walk + hash-compare pattern** — a loop hashing export names and
  comparing to constants (the *shape* is detectable even when the strings
  aren't).
- **Resolved API set** — what the process *actually* resolves at runtime
  (EDR call-backs on the export table, or a Sysmon 4688/10 correlation with
  the behavior).
- **The tell that matters** — a process resolving a *privileged* API
  (`NtWriteVirtualMemory`, `NtQueueApcThread`, `NtOpenProcess`) that its
  normal job never needs.

## Links

- [[shellcode]] — the payload this serves
- [[pe-executable]] — the export table being walked
- [[windows-syscalls]] — the next step: resolve the `Nt*` and call it direct
- [[anti-analysis]] — the broader "don't leave strings" game
- [[ghidra]] — where a human reverses the hash loop
