---
title: "Packing & Unpacking (hiding the real code)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, malware, reverse-engineering, packer, pe]
---

# Packing & Unpacking

**A packer compresses/encrypts a PE's real code so the static analyst
sees a stub, not the payload.** The packed file is small, the real code is
hidden, and the **unpacking stub** (which runs at load, decrypts the
payload into memory, and jumps to the **OEP**) is all that's on disk.
**Unpacking** — recovering the *unpacked* in-memory image — is the
analyst's job and the malware dev's #1 static-analysis defense.

## How a packer works (the model)

1. **At build time** — the packer takes the original PE, **compresses or
   encrypts** the `.text` (and often `.rdata`/`.data`), and replaces the
   PE's entry point with an **unpacking stub**. The original
   `AddressOfEntryPoint` (the real OEP) is stored somewhere the stub can
   find it (a field in the packer's own header, or a constant in the stub).
2. **At load time** — the Windows loader runs the **stub** (the new entry
   point). The stub:
   - `VirtualAlloc`s a buffer,
   - **decrypts/decompresses** the payload into it,
   - **patches the IAT** (rebuilds the import table for the unpacked code),
   - **jumps to the OEP** (the real `main`/`DllMain`).
3. **In memory** — the process now runs the *unpacked* code; on disk it's
   still the packed stub. **The in-memory image ≠ the on-disk file** —
   that mismatch is the unpacking target.

## The classic packers (what you'll meet)

- **UPX** — the **open-source, well-known** packer. It's *bad* malware
  (every AV knows its signature) but *easy* to work with: it's
  **self-unpacking** (the stub is a known, documented algorithm), and
  `upx -d` *unpacks it back to the original PE* (UPX stores enough
  metadata to reverse the compression). It's the **reference** for
  learning the packing/unpacking model.
- **MSPack / FSG / ASPack / Petite** — the **commercial/obscure** packers;
  each has its own stub and algorithm (you have to reverse *that*
  packer's stub, not a documented one). **Petite** is the common one in
  the wild (it packs the `.text` and leaves a *small* stub).
- **Custom packers** — the malware dev writes their own stub (a
  `VirtualAlloc` + a XOR/RC4 decrypt loop + a jump). The stub is
  **unique to that malware** — you have to reverse *it*. This is the
  "real" packing you meet in analysis, not UPX.

## The unpacking workflow (the analyst's job)

1. **Find the OEP** — the point where the stub finishes unpacking and
   jumps to the real code. Techniques:
   - **The `ret`/`jmp` to a non-stub address** — the stub ends with a
     `jmp`/`ret` to the OEP; a dynamic trace (a single-step through the
     stub) finds the jump target.
   - **The IAT is filled** — the stub rebuilds the IAT right before the
     OEP; the moment the IAT is *complete*, you're at the OEP.
   - **The `Add2Memory` / `LoadLibrary`** — the stub calls
     `LoadLibrary`/`AddDllDirectory` (or a custom module-load) right
     before the OEP; that call is the marker.
2. **Dump the in-memory image** — at the OEP, the process's memory holds
   the *unpacked* PE. A **memory dumper** (a `minidump`, or a tool like
   **Scylla**/the x64dbg dump feature) writes the in-memory image to a
   file — the **unpacked PE**.
3. **Rebuild the PE headers** — the dumped memory is the *sections*, not a
   valid PE; a tool (**Scylla**, `pe-sieve`, `lief`) **rebuilds the
   headers** (the import table, the section table, the OEP) into a
   loadable, analyzable PE.
4. **Analyze the unpacked PE** — now the static analysis ([[ghidra]])
   works on the *real* code, not the stub.

## The *hard* unpacking (what actually stops you)

- **The anti-unpacking** — the packer **detects the dump** (it checks
  `BeingDebugged`, it measures the time between the stub start and the OEP
  — a dump takes time, a normal run doesn't) and **corrupts the in-memory
  image** (or exits) if it thinks it's being dumped. **Defeat:** **dump
  faster** (a hardware breakpoint on the OEP, a single-step with no
  timing), or **patch the anti-unpacking check** (find the
  `BeingDebugged`/timing check in the stub, branch past it).
- **The *repacking* (the re-encrypt)** — some packers **re-encrypt the
  payload on every run** (a per-run key derived from a timestamp or a
  process ID). The in-memory image is *different every run* — a static
  dump is only good for *that* run. **Defeat:** you don't need a *static*
  dump; you need to **analyze the *running* process** (a dynamic analysis,
  not a static one) — or **catch the key** (the per-run key is computed in
  the stub; reverse the key derivation, then decrypt the on-disk payload
  *yourself*).
- **The *stub is the payload*** — the packer **doesn't separate the stub
  and the payload**; the *whole* PE is the stub, and the "payload" is
  computed at runtime (a **code cave** that's filled in by the stub, not
  a stored blob). There's no "unpacked image" to dump — the real code is
  **assembled in memory** from pieces. **Defeat:** you have to **trace the
  assembly** (a dynamic trace that reconstructs the code as it's
  assembled), not dump a blob.

## Red-team notes (dev side)

- **UPX is for *learning*, not for *shipping*** — a UPX-packed sample is
  *identified as UPX in seconds* (the AV DB has it); a **custom stub**
  (a `VirtualAlloc` + a XOR decrypt + a jump) is the one that takes the
  analyst an hour. Spend the effort on the *custom stub*, not on UPX.
- **The OEP is your weakest point** — the stub's `jmp` to the OEP is the
  *one* instruction that gives the analyst the unpacked image. **Hide it**:
  compute the OEP at runtime (not a constant `jmp`), or **indirect it**
  (a `jmp [rax]` where `rax` is computed). The harder the OEP is to find,
  the harder the dump is.
- **Combine with the other checks** — a packer **alone** is defeated by a
  dump; a packer **+ [[anti-analysis]]** (the time-bomb, the VM check) +
  **[[anti-debugging]]** (the `BeingDebugged` check) is the "hard to
  analyze" trifecta. The packer hides the *code*; the other two hide the
  *behavior*; together they're a real cost.

## Detection (defender side)

- **The entropy tell** — a PE with a **high-entropy `.text`** (≈8.0) and a
  **small, low-entropy stub** at the entry point is **packed** (the
  payload is compressed/encrypted, the stub is real code). The
  **file-size vs. section-size mismatch** (the file is much smaller than
  the sum of the sections' *virtual* sizes) is the same tell.
- **The OEP-in-stub tell** — a PE whose entry point is in a **tiny
  section** (the stub) that's *disproportionately small* compared to the
  other sections is a packer (the real code is in the big, high-entropy
  section).
- **The in-memory vs. on-disk mismatch** — the **process's `.text` in
  memory ≠ the on-disk `.text`** (the packer decrypted in place) is the
  *runtime* tell; a process whose memory doesn't match its file is either
  packed or **hollowed** ([[process-injection]]).
- **The known-packer signature** — UPX and the common commercial packers
  have **known signatures** (a byte pattern at the entry point, a
  `UPX!`/`UPX0` string); the AV/EDR flags them by signature.

## Links

- [[pe-executable]] — the format the packer operates on (the OEP, the IAT)
- [[shellcode]] — the payload a packer often hides
- [[api-hashing]] — the unpacked code often resolves APIs by hash
- [[anti-analysis]] — the packer's *companion* defense (hides the behavior)
- [[anti-debugging]] — the packer's *other* companion defense
- [[ghidra]] — where the unpacked PE is analyzed
- [[upx]] — the reference open-source packer
- [[reverse-engineering-workflow]] — where unpacking sits in the flow
