---
title: "Defense Evasion for AD Tooling (EDR / AMSI / ETW)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [red-team, active-directory, defense-evasion, edr, opsec, malware-dev]
---

# Defense Evasion for AD Tooling

Running AD offensive tooling (Rubeus, Certipy, Mimikatz, SharpHound) against a
monitored estate means the tooling itself, not just its protocol footprint
([[opsec-ad-tradecraft]]), is what gets caught. This page covers the host-side
tradecraft for **authorized** engagements and the understanding needed for
detection engineering / adversary emulation.

## The three host sensors

- **AMSI** — scans script/.NET content at runtime (PowerShell, `Add-Type`,
  `execute-assembly`). Signatures catch known tool strings. Full mechanism
  and bypasses: [[amsi]].
- **ETW** — `Microsoft-Windows-DotNETRuntime` and threat-intel providers feed
  EDR with in-process telemetry (assembly loads, API calls). Full mechanism
  and evasion: [[etw]].
- **EDR user-mode hooks / kernel callbacks** — flag suspicious API sequences
  (LSASS access, remote thread injection, handle duplication). The
  "skip the hook" answer is [[windows-syscalls]]; the injection shapes
  themselves are [[process-injection]].

## Tradecraft principles

- **Prefer protocol abuse over host artefacts.** The quietest credential
  access on a hardened host is the one that never touches the host: pull
  secrets by *replication* ([[dcsync]]) or by *cracking a ticket*
  ([[kerberoasting]] / [[as-rep-roasting]]) rather than reading
  [[lsass]] memory. Choosing the technique *is* the evasion.
- **Run in memory, not on disk.** `execute-assembly` / reflective loading of
  .NET tools (Rubeus, Certify) avoids dropping binaries; on-disk Mimikatz is
  the most-signatured artefact in AD.
- **Reduce the LSASS touch.** If you must, prefer indirect dumping
  (comsvcs/`MiniDump` via a LOLBAS, or built-in ntdsutil for [[ntds-dit]]) and
  handle the dump offline, rather than live `sekurlsa` on the box.
- **LOLBAS over custom binaries** for movement/execution
  ([[remote-execution]]) — signed, expected binaries generate less telemetry
  than dropped tools.
- **Local privesc is quiet via files/registry, not memory.** A
  [[service-privesc|service-path write]], a [[scheduled-task-abuse|task
  update]], or a [[dll-hijacking-sideloading|sidecar DLL]] under a trusted
  parent leaves a *plausible-admin* footprint and is quieter than an in-memory
  token trick on a young EDR; [[uac-bypass]] and the
  [[environment-variable-attack|PATH/PATHEXT]] drop are the low-noise first
  rungs. See [[windows-privilege-escalation]].
- **Operate remotely.** Much AD tooling (Impacket, Certipy, bloodhound-python)
  runs from your Linux operator host over a tunnel
  ([[c2-and-pivoting-ad]]), so AMSI/ETW/EDR on the target never sees it — only
  the network protocol does.

## For the blue-team read

Each evasion above has a corresponding detection: AMSI/ETW bypass attempts,
`execute-assembly` CLR-load telemetry, anomalous LSASS handles, and the
protocol tells on the technique pages. This page is deliberately the mirror of
those detection sections — knowing the evasion is how you write the detection.

## See also

- [[redteam-ad-methodology]] — where evasion decisions sit in the flow
- [[opsec-ad-tradecraft]] — the network-side counterpart
- [[lsass]] — the artefact most of this avoids touching
- [[c2-and-pivoting-ad]] — keeping tooling off the target entirely
- [[remote-execution]] — LOLBAS-friendly movement
- [[amsi]] / [[etw]] — the two host sensors, in depth (mechanism + bypasses)
- [[windows-syscalls]] — calling the kernel direct, past the user-mode hook
- [[process-injection]] — the injection techniques the EDR shapes are built to catch
- [[beaconing]] — the C2 heartbeat this evasion exists to protect
- [[windows-privilege-escalation]] — the local-privesc vectors (UAC / DLL / service / task / Potato) and their footprints
