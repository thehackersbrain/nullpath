---
title: "PE Executable (Portable Executable format)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, reverse-engineering, malware, pe]
---

# PE Executable

The **Portable Executable** format — every Windows `.exe`/`.dll`. Reverse
engineering and malware analysis start by reading the PE structure, because
**where the imports, entry point, and sections live is what the malware
developer is trying to hide.** The whole anti-analysis game
([[anti-analysis]], [[packer-unpacking]]) is played against this format.

## The structure (what you actually use)

- **DOS header** → `e_lfanew` offset → **PE signature** (`0x4550`) →
  **COFF header** (machine `0x8664` = x64, section count) →
  **Optional header** (the important one):
  - **`ImageBase`** — preferred load address (the ASLR base; shellcode that
    calls the module resolves relative to this).
  - **`AddressOfEntryPoint` (OEP)** — where execution starts (`main`/`DllMain`
    after loader work). **A packer's OEP is the unpacking target**
    ([[packer-unpacking]]).
  - **Data directories** — most importantly the **Import Directory (IAT)**
    and **Export Directory** (for DLLs).
- **Sections** — `.text` (code), `.rdata` (read-only data: **import table**,
  strings), `.data`, `.rsrc` (resources: icons/version info — often the
  *unpacked* giveaway in a packed binary).

## The Import Table (the analysis pivot)

The **IAT** lists every imported function (`LoadLibrary`/`GetProcAddress`
calls the loader fills in). Reading it is step one of static analysis:

- **The import list is the malware's fingerprint** — `CreateRemoteThread` +
  `VirtualAllocEx` = injection ([[process-injection]]); `NtReadVirtualMemory`
  = LSASS theft; `IsDebuggerPresent` = [[anti-debugging]].
- **A *missing* or tiny import table is the red flag** — the binary resolves
  APIs **at runtime** instead: [[api-hashing]] / manual
  `GetProcAddress` loops / direct syscalls ([[windows-syscalls]]).
- Tools: **Ghidra**/IDA auto-resolve the IAT; `dumpbin /imports` for a quick
  look; `pefile` in Python.

## Red-team notes (OPSEC / dev side)

- **Overlays are free space** — data after the last section isn't parsed by
  the loader; shellcode and C2 config get hidden in overlays
  (detection: file size ≫ sum of section raw sizes).
- **Resource-section spoofing** — a normal icon/version resource makes the
  binary *look* benign in EDR previews; `.rsrc` is also where packers leave
  the original stub.
- **Section entropy tells the story** — uniform high entropy in `.text`
  (≈8.0) = packed/encrypted payload; a `.text` at 4–6 is real code
  ([[packer-unpacking]]).
- **For your own payloads** — a clean PE with a plausible import list and
  benign resources passes more file-reputation checks than a raw shellcode
  loader.

## Detection

- **Section anomalies** — RWX sections, high-entropy `.text`, huge overlays.
- **Import behavior** — suspicious API combos (injection/traversal APIs)
  without a reason to use them.
- **PE header sanity** — section count/alignment outside the normal
  distribution (the loader is lenient; malware uses that).

## Links

- [[shellcode]] — the payload a PE (or a raw loader) usually hides
- [[api-hashing]] — why the import table can be empty
- [[packer-unpacking]] — the OEP/entropy game
- [[anti-analysis]] — the checks a binary runs against its analyzer
- [[ghidra]] — the primary static-analysis tool
- [[reverse-engineering-workflow]] — where PE parsing sits in the flow
