---
title: "Meterpreter (the post-exploitation payload)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, c2, post-exploitation, payload]
---

# Meterpreter

The **post-exploitation payload** — the *agent* that a C2 (Cobalt Strike,
Metasploit) *drops* on a compromised host to run the *host-side*
workflow (the *credential dump*, the *pivot*, the *privilege escalation*).
It's the *payload* the [[beaconing]] *beacon* *talks to* — the *beacon*
is the *C2's* *heartbeat*; the *Meterpreter* is the *C2's* *hands* on the
host.

## Why it's the reference payload

- **The *in-memory* payload** — Meterpreter is an *in-memory* payload (a
  *shellcode* that *loads* a *DLL*, or a *DLL* that *self-injects*) — no
  *file* on disk (the *fileless* *tell*, the [[shellcode]] /
  [[process-injection]] *model*). The *in-memory* *nature* is the *evasion*
  (no *file* to *hash*, no *file* to *AV-scan*).
- **The *post-exploitation* is *built-in*** — the *credential dump* (the
  *mimikatz* *loot*, the *LSASS* *dump*), the *privilege escalation* (the
  *UAC* *bypass*, the *token* *impersonation*), the *pivot* (the *socks*
  *proxy*, the *port* *forward*) are *native* *extensions* — not *scripts*,
  not *plugins*, the *core*.
- **The *stagers* / the *stages*** — the Meterpreter *payload* is a
  **stager** (a *small* *shellcode* that *fetches* the *stage* — the
  *full* *payload*) — the *two-stage* *model* (the [[packer-unpacking]]
  *multi-stage* *analogue*). The *stager* is the *foothold*; the *stage*
  is the *agent*.

## The *payload* model (the *two-stage*)

1. **The *stager*** — a *small* *shellcode* (a *few KB*) that *executes*
   in memory (a *process* *injection*, a *named pipe*, a *WebShell*).
   The *stager* *connects* to the *C2* and *fetches* the *stage*.
2. **The *stage*** — the *full* *Meterpreter* *payload* (a *DLL*, a
   *few MB*) that *loads* in memory (the *in-memory* *agent*). The *stage*
   *runs* the *post-exploitation* *workflow* (the *dump*, the *pivot*,
   the *privilege escalation*).

The *two-stage* *model* is the *C2's* *foothold* → the *C2's* *agent*:
the *stager* is the *foot* in the *door*; the *stage* is the *body* in
the *room*.

## The *post-exploitation* (the *built-in* *workflow*)

- **The *credential* *dump*** — the *mimikatz* *loot* (the *LSASS* *dump*,
  the *sekurlsa*) — the [[credential-dumping]] / [[lsass]] *workflow*,
  *from the* *Meterpreter*.
- **The *privilege* *escalation*** — the *UAC* *bypass*, the *token*
  *impersonation*, the *process* *injection* into a *high-priv* process —
  the [[process-injection]] *workflow*, *from the* *Meterpreter*.
- **The *pivot*** — the *socks* *proxy*, the *port* *forward* — the
  *C2's* *reach* into the *internal* *network* (the [[c2-and-pivoting-ad]]
  *point*).

## The *evasion* (the *payload's* *answer*)

- **The *in-memory* *nature*** — no *file* on disk (the *fileless* *tell*)
  — the [[shellcode]] / [[process-injection]] *evasion*.
- **The *direct* *syscall*** — the Meterpreter *stage* can *call* the
  kernel *directly* (the [[windows-syscalls]] *evasion*) — the *user-mode*
  *hook* is *skipped* (the *ETW* is *not*).
- **The *AMSI* *bypass*** — the Meterpreter *stage* (a *PowerShell*
  *payload*) can *bypass* AMSI (the [[amsi]] *evasion*) — the *script
  scan* is *skipped*.

## Red-team notes (OPSEC)

- **The *in-memory* is the *evasion*** — a *file* on disk is a *hash*, a
  *file* is a *AV-scan*; an *in-memory* *payload* is *neither* (the
  *fileless* *tell*). The *in-memory* *nature* is the *single* *biggest*
  *evasion* (the *file* is the *easiest* *tell*).
- **The *stager* is the *foothold*** — the *stager* is the *small*
  *shellcode* that *gets in*; the *stage* is the *full* *agent* that
  *stays*. The *stager* is the *one-shot* (the *foothold*); the *stage* is
  the *persistent* (the *agent*). The *detection* is the *stager* (the
  *small* *shellcode* is the *easiest* *tell*).
- **The *built-in* is the *workflow*** — the *dump*, the *pivot*, the
  *privilege escalation* are *native* (not *scripts*, not *plugins*) —
  the *C2's* *hands* on the *host*. The *workflow* is the *product*; the
  *evasion* is the *channel*.

## Links

- [[beaconing]] — the *C2's* *heartbeat* the *Meterpreter* *talks to*
- [[shellcode]] — the *stager* *is* a *shellcode* (the *in-memory*
  *payload*)
- [[process-injection]] — the *injection* the *Meterpreter* *uses* (the
  *in-memory* *load*)
- [[credential-dumping]] / [[lsass]] — the *dump* the *Meterpreter* *runs*
  (the *mimikatz* *loot*)
- [[windows-syscalls]] / [[amsi]] — the *evasion* the *Meterpreter* *uses*
  (the *direct* *syscall*, the *AMSI* *bypass*)
- [[c2-and-pivoting-ad]] — the C2/pivoting hub this belongs to
- [[cobalt-strike]] — the *C2* the *Meterpreter* *talks to* (the
  *beacon* + the *Meterpreter*)
