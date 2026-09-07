---
title: "Ghidra (NSA reverse-engineering suite)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, reverse-engineering, decompiler, analysis]
---

# Ghidra

The NSA's open-source **reverse-engineering suite** — the primary
**static-analysis** tool in the [[reverse-engineering-workflow]]. It's a
**decompiler** (disassembly + a C-like decompile + the **cross-reference
map**), which is what makes a packed/malicious PE analyzable: you're
looking at the *functions* and *where they're called from* (the XREFs),
not just raw assembly.

## Why it's the default here

- **Free, open, headless** — no license, no per-seat cost, and a
  **headless mode** (`analyzeHeadless`) that makes it a *pipeline* tool
  (batch-analyze a folder of samples, export the results) — the
  difference between a "one analyst, one sample" tool and a "triage a
  thousand samples" tool.
- **The decompiler is the point** — IDA's decompiler is *better* in
  places, but it's *paid*; Ghidra's is *good enough* for 90% of malware
  (the control flow, the API calls, the string refs) and it's *free* —
  for a wiki/ops workflow the free headless tool wins.
- **The scripting (Jython / Java / Python 3)** — Ghidra's **scripting API**
  is how you automate the *boring* passes (find all the `gs:[0x60]` PEB
  reads, find all the `IsDebuggerPresent` calls, extract the API hashes) —
  the [[anti-debugging]]/[[api-hashing]] checks are *scripted finds*, not
  *manual* finds.

## The workflow (the static pass)

1. **Import the PE** — Ghidra's loader parses the [[pe-executable]]
   (the sections, the imports, the entry point). A *packed* PE imports as
   the *stub* (the real code is in memory — see [[packer-unpacking]]).
2. **The auto-analyze** — Ghidra's auto-analyzer finds the functions, the
   strings, the imports, the XREFs. You *review* the analysis (the
   auto-analyzer is *wrong* on obfuscated code — the function boundaries,
   the string decodes).
3. **The decompile pass** — the C-like decompile is where you *read* the
   malware (the control flow, the *what*, the *why*). The **XREFs** are
   the map: where is `CreateRemoteThread` *called from*, what does the
   *caller* do.
4. **The scripted finds** — the Ghidra **script** that finds the
   [[anti-debugging]] set (the PEB reads, the timing pairs), the
   [[api-hashing]] loop (the export-walk + hash-compare), the
   encryption keys (the constants in `.rdata`).
5. **The export** — the *model* (the functions, the checks, the secrets)
   out to a *note* (the [[reverse-engineering-workflow]] step 4) and a
   *Yara rule* (the static tell).

## The *headless* (the pipeline)

```bash
# batch-analyze a folder of samples, export the function/.string reports
ghidra/analyzeHeadless <project_dir> <project_name> \
  -import samples/ \
  -postScript ExportStrings.py \
  -scriptPath scripts/
```

The headless mode is the *triage* layer: a *thousand* samples in, a
*thousand* function/string/XREF reports out — the *manual* analysis is
only the *interesting* few.

## Red-team notes (the analyst's frame)

- **The *decompiler* is the *model*, the *XREFs* are the *map*** — you
  don't *read* the malware linearly; you *follow the XREFs* (the
  `CreateRemoteThread` caller → the *injection* → the *payload*). The
  XREF map is the *architecture* of the binary; the decompile is the
  *detail*.
- **The *scripted* finds beat the *manual* finds** — the
  [[anti-debugging]]/[[api-hashing]]/[[anti-analysis]] checks are *patterns*
  (a PEB read, an export-walk, a CPUID call) — a Ghidra *script* finds
  them *every time*; a *manual* find misses the *second* one. The script
  is the *consistency*; the manual is the *judgment*.
- **The *auto-analyzer is a starting point, not a truth*** — obfuscated
  code *breaks* the auto-analyzer (the function boundaries, the string
  decodes are *wrong*). You *review* the analysis — a *wrong* function
  boundary is a *wrong* model.

## Links

- [[reverse-engineering-workflow]] — the static pass this runs
- [[pe-executable]] — the format it parses
- [[packer-unpacking]] — the *unpacked* PE it analyzes (the *stub* it
  imports by default)
- [[anti-debugging]] / [[anti-analysis]] — the checks its scripts find
- [[api-hashing]] — the export-walk its scripts find
- [[x64dbg]] — the *dynamic* counterpart (Ghidra is *static*; x64dbg is
  *dynamic*)
