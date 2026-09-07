---
title: "Anti-Analysis (anti-VM / anti-sandbox checks)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, malware, reverse-engineering, anti-analysis, sandbox]
---

# Anti-Analysis

**Malware that checks whether it's running in a VM or a sandbox, and
sleeps/hides its payload if it is.** It's the *environment* counterpart to
[[anti-debugging]] (which targets the *debugger*). The goal isn't to be
*undetectable* — it's to **not pay off in the first 30 seconds of a
sandbox run**, which is when most automated analysis happens.

## The standard checks (what the sandbox is *telling* it)

### Hardware / CPU
- **CPUID vendor string** — a real CPU returns `"GenuineIntel"`/
  `"AuthenticAMD"`; a VM may return a different string or have a
  hypervisor bit set (`CPUID` leaf `1`, `ECX` bit 31). **Defeat:**
  **spoof the CPUID** in your analysis VM (most "malware analysis VMs"
  have a CPUID-spoof plugin).
- **`INVD` / `RDMSR`** — read a model-specific register; a VM may return a
  different value. **Defeat:** same CPUID/MSR-spoof layer.

### Timing / entropy
- **The "is this a fresh boot" check** — a sandbox boots the VM, runs the
  sample, and shuts it down in ~60–120 s. The malware checks
  **`GetTickCount`** (time since boot) or **the system uptime**; a value
  under ~5 minutes = sandbox. **Defeat:** let the analysis VM **boot and
  idle for 10+ minutes** before running the sample.
- **The high-entropy check** — some malware looks for **low disk entropy**
  (a fresh, empty sandbox drive has repetitive sectors); a real drive has
  high entropy. **Defeat:** **fill the analysis drive with random data**
  (or use a "used" disk image).

### The obvious environment tells
- **MAC address / OUI** — a VM's virtual NIC has a **known OUI**
  (VirtualBox, VMware, Hyper-V have vendor prefixes). **Defeat:** **set a
  random/real MAC** on the analysis VM's NIC.
- **The hostname / username** — a sandbox is often named
  `SANDBOX`/`VICTIM`/`VM001`, the user is `user`/`admin`. **Defeat:** give
  the analysis VM a **plausible hostname and username**.
- **The process list** — a sandbox runs a known set of processes
  (the sandbox's own agent, `sandboxagent.exe`, etc.). **Defeat:** **kill
  the sandbox's own processes** before running the sample (or run the
  sample in a *clean* VM with no sandbox agent).
- **The registry** — `HKLM\SYSTEM\...\CurrentControlSet\Control` has
  VM-specific keys; a real machine has more. **Defeat:** use a **real,
  "aged" Windows image** (a snapshot of a real machine, not a fresh
  install).

### The *behavioral* tells (the ones that matter)
- **The "do it in a hurry" check** — a sandbox **waits for the sample to
  "do something"** (a network connect, a file write) before it calls the
  run "done." The malware **does nothing for the first N seconds** (the
  sandbox's patience limit), then acts. **Defeat:** **let the analysis run
  longer** than the sample's patience (or the sandbox times out and
  reports "benign").
- **The "watch me" check** — the malware **does the interesting thing only
  when it's *being watched*** (a breakpoint, a trace, a specific API
  call) — the inverse of anti-debugging. **Defeat:** **trace it for
  longer** (the interesting code runs on a timer, not on a breakpoint).

## The *real* anti-analysis (what actually stops the sandbox)

- **The *multi-stage* payload** — the initial drop is **benign** (a
  `svchost` clone, a small loader); the *real* payload is fetched from C2
  **only after** the environment checks pass. The sandbox sees stage 1
  (benign), the real payload never runs in the sandbox. **Defeat:** you
  need to **catch the C2 beacon** (the network call) and **replay it** in
  your analysis (a network sandbox with a C2 emulator).
- **The *time-bomb*** — the payload waits a **fixed wall-clock time**
  (a specific date, or N hours after first run) before activating. The
  sandbox's 60 s run never reaches it. **Defeat:** **advance the VM's
  clock** (or the sample's "first run" marker) past the time-bomb.
- **The *count* check** — the payload activates only on the **Nth run**
  (it counts how many times it's been launched). The sandbox runs it once.
  **Defeat:** **run it N times** in the analysis VM (the count is usually
  in a registry key or a file — find and increment it).

## How to *use* this (the analysis workflow)

1. **Static pass first** — find the checks in the disassembly
   ([[ghidra]]): `CPUID` calls, `GetTickCount` pairs, MAC/hostname reads,
   the registry keys it queries, the process names it enumerates.
2. **Spoof the *environment*, not the *code*** — the fastest win is to
   **make the analysis VM look like a real machine** (CPUID-spoof, real
   MAC, aged clock, plausible hostname), *not* to patch every check in the
   binary (which is fragile and tells the malware you're analyzing it).
3. **Let it run *longer*** — most anti-analysis is a **patience game**;
   the sandbox's 60 s is the malware's friend. A 10-minute run with a
   "real" environment defeats the standard set.
4. **Catch the C2, replay it** — if the payload is multi-stage, the
   *network* is where the real behavior is; a **C2 emulator** (a fake C2
   server that answers the beacon) is what gets the stage-2 payload.

## Red-team notes (dev side)

- **The *time* check is your best cheap defense** — a 5-minute
  `GetTickCount` gate defeats a 60 s sandbox for free; it costs the
  analyst 5 minutes of patience, which most automated pipelines don't have.
- **The *multi-stage* payload is the real defense** — a single-stage
  sample is fully visible to the sandbox; a **stage-1 (benign) + C2-fetched
  stage-2** sample means the sandbox sees *nothing* unless it can emulate
  your C2. Spend the effort on the C2, not the checks.
- **Don't over-spoof** — a malware that checks for *too many* VM tells
  (CPUID + MAC + hostname + process list + registry + timing) is a
  malware that's **telling the analyst exactly what to look for**. Each
  check is a *fingerprint*; the fewer, the harder to reverse. The
  *behavioral* checks (time-bomb, multi-stage, count) are the ones that
  don't leave a static fingerprint.

## Detection (defender side)

- **The checks are the tell** — a process calling `CPUID` (the hypervisor
  bit), reading `GetTickCount` in a tight loop, or enumerating the process
  list *and* the registry is **checking its environment** (malware does
  this; normal apps usually don't).
- **The "nothing happens" tell** — a sample that runs for 60 s and does
  *nothing* (no network, no file, no process) is **either benign or
  anti-analysis**; the defender's job is to tell which (run it longer, in
  a "real" environment).
- **The C2 beacon is the real tell** — a sample that's "benign" locally
  but **beacons to an unusual IP/domain on a fixed interval** is the
  multi-stage payload talking to its C2 ([[beaconing]]).

## Links

- [[anti-debugging]] — the debugger-side counterpart
- [[packer-unpacking]] — packers + anti-analysis are the standard "hard to
  analyze" pair
- [[beaconing]] — the C2 that a multi-stage payload talks to
- [[reverse-engineering-workflow]] — where these checks are defeated
- [[ghidra]] — finding the checks statically
