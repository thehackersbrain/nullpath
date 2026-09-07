---
title: "Reverse-Engineering Workflow (static + dynamic analysis)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, reverse-engineering, malware, methodology, analysis]
---

# Reverse-Engineering Workflow

**How a binary actually gets analyzed** — the operational arc from "here's
a sample" to "here's what it does and how it hides it." The
[[redteam-ad-methodology]] of the RE/malware domain: the individual
techniques ([[anti-debugging]], [[packer-unpacking]], [[api-hashing]],
[[windows-syscalls]]) are steps *in* this flow, not standalone.

## The arc

### 1. Triage (minutes, no disassembly)
- **Hash + metadata** — SHA256, file size, compile timestamp (the PE
  header's timestamp — often *wrong*, a dev tells), the **signing
  certificate** (a valid sig ≠ benign, but it's a context).
- **Strings** — the first real look: URLs, IPs, registry paths, API
  names, **language strings** (a C++ binary has different strings than
  Go/Rust/Python). A **C2 URL in plaintext** can end the analysis here.
- **The import table** — [[pe-executable]]: the API set is the
  *behavioral fingerprint* (injection APIs, LSASS APIs, VM-check APIs).
  **An empty/tiny import table = runtime resolution** ([[api-hashing]] /
  [[windows-syscalls]]) — that's the first "this is trying to hide" signal.
- **Entropy map** — a per-section entropy pass: high-entropy `.text` =
  packed ([[packer-unpacking]]); a huge overlay = hidden data.
- **Yara + known signatures** — run the sample through a Yara set / a
  signature DB; a known packer (UPX) or a known family short-circuits
  the deep work.

### 2. Static analysis (the disassembly pass)
- **[[ghidra]]** (or IDA) — the full decompile: the control flow, the
  *functions*, the **cross-references** (the XREFs are the map: where is
  `CreateRemoteThread` *called from*, what does the *caller* do).
- **Find the checks** — the [[anti-debugging]] set (the PEB reads, the
  `IsDebuggerPresent`, the timing pairs) and the [[anti-analysis]] set
  (the CPUID, the `GetTickCount` gates, the MAC/hostname reads) are all
  *statically findable* — you can see *what it checks* without running it.
- **Find the secrets** — the API hashes ([[api-hashing]]), the encryption
  keys (often a constant in `.rdata`), the C2 config (sometimes
  XOR-obfuscated but with a *recoverable* key).
- **The goal** — a **static model** of the binary: its stages, its
  checks, its secrets, its *intended* behavior. Static gets you 80% for a
  clean binary; the other 20% (what it *actually* does at runtime, the
  per-run keys, the C2 protocol) needs step 3.

### 3. Dynamic analysis (the run pass)
- **The sandbox / clean VM** — a **known-clean** Windows VM (snapshot
  before, restore after) with the *environment* spoofed (a real CPUID, a
  real MAC, an aged clock — the [[anti-analysis]] defeat set).
- **[[x64dbg]]** (or WinDbg) — the **dynamic** trace: step through the
  stub, **find the OEP** (the [[packer-unpacking]] target), watch the
  *actual* API calls (the call stack, the arguments, the *real* modules
  loaded).
- **Defeat the checks, consistently** — the [[anti-debugging]] set: zero
  the PEB flag, patch the timing compare, hook `NtQueryInformationProcess`
  — **all of them, or the anti-anti-debug catches the mismatch**.
- **Network capture** — a **proxy + a packet capture** on the analysis
  VM: the C2 beacon (the [[beaconing]] tell), the stage-2 fetch, the
  DNS. **The network is often where the real behavior is** (a multi-stage
  payload is "benign" locally; the C2 is the tell).
- **The memory dump** — at the OEP, dump the **unpacked image** (the
  [[packer-unpacking]] step 2) — now the static analysis works on the
  *real* code.

### 4. The synthesis (the write-up)
- **The model** — stages (what runs when), the checks (what it's hiding
  from), the secrets (keys, C2, hashes), the *behavior* (what it does to
  the host).
- **The detection** — the **high-fidelity tells** (the specific API
  sequence, the specific string, the specific C2 pattern) → a **Sigma**
  rule / a Yara rule. The *goal* of the analysis is the detection, not
  just the understanding.
- **The link back** — the RE findings feed the **AD wiki**: a malware that
  dumps LSASS is [[credential-dumping]]; a malware that injects into
  `svchost` is [[process-injection]]; a malware that beacons is
  [[beaconing]]. The RE page is the *mechanism*; the AD/ops pages are the
  *consequence*.

## The *order* is the point

- **Static before dynamic** — the static pass tells you *what to look for*
  in the dynamic pass (the checks, the OEP, the secrets); going dynamic
  first means you're *guessing* what the dynamic trace is showing you.
- **Dynamic to *confirm*, not to *discover*** — the dynamic pass confirms
  the static model (does the OEP match? do the API calls match the
  imports?) and finds the *static* misses (the per-run keys, the C2
  protocol). It's not where you *learn* what the binary is.
- **The environment is the *input*** — a dynamic analysis in a
  *sandbox-shaped* VM (a fresh boot, a VM MAC, a 60 s run) defeats the
  [[anti-analysis]] checks and shows you the *benign* path. The analysis
  VM has to *look like a real machine* or you're analyzing the
  anti-analysis, not the payload.

## Red-team notes (OPSEC / the analyst's frame)

- **The *first* 30 seconds are the malware's** — the triage (hash, strings,
  imports, entropy) is what a *defender's* automated pipeline does; the
  malware's [[anti-analysis]] time-bomb is set to *beat that pipeline*.
  Your dynamic pass has to run *longer* than the malware's patience.
- **A *clean* VM is a *known* state** — snapshot before, restore after;
  the analysis VM is a *lab*, not a *host*. Anything you learn from it is
  only as good as the *cleanliness* of the snapshot.
- **The *network* is the truth** — a binary that's "benign" on disk and in
  the VM but **beacons to an unusual C2** is *not* benign; the C2 is the
  behavior. The network capture is the highest-fidelity dynamic tell
  ([[beaconing]]).

## Detection (the output of the analysis)

- **The Yara rule** — the *static* tell (a string, a byte pattern, an
  import combo) → a file-based detection.
- **The Sigma rule** — the *behavioral* tell (the API sequence, the
  process/file/network event) → a log-based detection (the
  [[kerberos-event-ids]]-equivalent for host/process telemetry).
- **The high-fidelity principle** — the *specific* combination (this
  import + this string + this C2) beats the *generic* tell (a process
  calling `CreateRemoteThread`); the analysis is what gets you the
  *specific*.

## Links

- [[pe-executable]] — the format the static pass reads
- [[ghidra]] — the primary static-analysis tool
- [[x64dbg]] — the primary dynamic-analysis debugger
- [[packer-unpacking]] — the OEP/dump step of the dynamic pass
- [[anti-debugging]] / [[anti-analysis]] — the checks the dynamic pass defeats
- [[api-hashing]] / [[windows-syscalls]] — the runtime-resolution the static pass finds
- [[beaconing]] — the C2 the network capture catches
- [[redteam-ad-methodology]] — the AD-side analog of this arc
- [[credential-dumping]] / [[process-injection]] — the AD techniques the RE findings feed
