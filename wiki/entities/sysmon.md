---
title: "Sysmon (System Monitor — the host telemetry standard)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, detection, telemetry, sysmon, windows]
---

# Sysmon

**Sysmon** (Microsoft's **System Monitor**) — the **host-telemetry**
standard that the *detection* side of this wiki runs on. It's a
**kernel-driver + service** that logs the *low-level* Windows events the
*default* Windows Event Log *doesn't* (the **process access**, the
**file creation**, the **registry** sets, the **network** connections,
the **driver loads**) — the *events* the [[credential-dumping]] /
[[process-injection]] / [[beaconing]] *detection* sections *reference*.

## Why it's the detection baseline

- **The *low-level* events** — the *default* Windows Event Log (the
  **4624**/*4688*/*4769*) is the *high-level* (the *logon*, the *process
  create*, the *Kerberos*). Sysmon adds the *low-level* (the **10** =
  *Process Access* (the *LSASS* *dump* tell), the **11** = *File Create*,
  the **12/13/14* = *Registry*, the **3** = *Network Connect*, the **6** =
  *Driver Load*) — the *events* the *technique* *leaves* (the *LSASS*
  *Process Access* from a *non-LSA* *parent*, the *network* connect to a
  *CDN* *every 60 s*).
- **The *open* schema** — the Sysmon *events* have a *known*, *documented*
  *schema* (the *EventID*, the *fields*, the *meaning*) — the *Sigma*
  *rules* (the [[sigma]] *rules*) are *written against* the *Sysmon*
  *schema* (the *EventID 10* = *Process Access*, the *EventID 3* =
  *Network Connect*). The *Sysmon* *schema* is the *detection*
  *language*.
- **The *ETW* *source*** — Sysmon is an *ETW* *consumer* (it *reads* the
  *kernel's* *ETW* events — the *syscall*, the *registry*, the *network*)
  — the [[etw]] *page's* *consumer* (the *ETW* is the *source*; Sysmon is
  the *log*). The *ETW* *evasion* (the *session* *kill*) *defeats*
  *Sysmon* (the *log* is *gone*) — the *ETW* and *Sysmon* are the *same*
  *layer* (the *kernel's* *event* *bus*).

## The *events* (the *detection* *reference*)

- **Event 10 (Process Access)** — a *process* *accesses* *another*
  *process's* *memory* (the *LSASS* *dump* tell — a *non-LSA* *parent*
  *accessing* *lsass.exe*). The [[credential-dumping]] / [[lsass]]
  *detection*.
- **Event 11 (File Create)** — a *file* is *created* (the *.dmp* file,
  the *WebShell*, the *dropper*). The *file* *tell*.
- **Event 3 (Network Connect)** — a *network* *connection* (the *C2*
  *beacon*, the *lateral* *SMB*). The [[beaconing]] *detection* (the
  *network* *connect* to a *CDN* *every 60 s*).
- **Event 6 (Driver Load)** — a *driver* is *loaded* (the *EDR* *driver*,
  the *rootkit* *driver*). The *kernel* *tell*.
- **Event 12/13/14 (Registry)** — a *registry* *key* is *set* /
  *deleted* / *renamed* (the *persistence*, the *run key*, the
  *scheduled task*). The *persistence* *tell*.

## The *detection* (the *Sigma* *rules*)

The *Sysmon* *events* are the *input* to the [[sigma]] *rules* (the
*detection* *language*):
- A **Sigma** *rule* on *EventID 10* (a *non-LSA* *parent* *accessing*
  *lsass.exe*) = the *LSASS* *dump* *detection*.
- A **Sigma** *rule* on *EventID 3* (a *network* connect to a *CDN*
  *every 60 s*) = the *beacon* *detection*.
- A **Sigma** *rule* on *EventID 11* (a *.dmp* file *created* under
  *C:\*) = the *dump* *file* *detection*.

The *Sysmon* *schema* is the *detection* *language*; the *Sigma* *rule*
is the *detection* *logic*; the *Sysmon* *event* is the *detection*
*input*.

## Red-team notes (OPSEC / the *attack* *side*)

- **The *Event 10* is the *LSASS* *tell*** — a *non-LSA* *parent*
  *accessing* *lsass.exe* is the *LSASS* *dump* *tell* (the
  [[procdump]] / [[mimikatz]] *detection*). The *evasion* is the
  *comsvcs* / *named-pipe* *dump* (the *Process Access* is *from* a
  *plausible* *parent*, not a *cmd*/*powershell*).
- **The *Event 3* is the *beacon* *tell*** — a *network* connect to a
  *CDN* *every 60 s* is the *beacon* *tell* (the [[beaconing]]
  *detection*). The *evasion* is the *channel* (a *CDN* over *TLS*, a
  *valid* *cert*) + the *jitter* (a *random* ±% to the *interval*).
- **The *Sysmon* is the *ETW* *consumer*** — the [[etw]] *evasion* (the
  *session* *kill*, the *provider* *disable*) *defeats* *Sysmon* (the
  *log* is *gone*). The *ETW* and *Sysmon* are the *same* *layer* (the
  *kernel's* *event* *bus*) — the *ETW* *evasion* is the *Sysmon*
  *evasion*.

## Detection (the *defender's* *frame*)

- **The *Event 10* correlation** — a *non-LSA* *parent* *accessing*
  *lsass.exe* + a *.dmp* file *created* (the *Event 11*) = the *LSASS*
  *dump* (the *high-fidelity* *tell*).
- **The *Event 3* periodicity** — a *network* connect to a *single*
  *destination* on a *fixed* (jittered) *interval* = the *beacon* (the
  *timing* *tell*).
- **The *Event 6* anomaly** — a *driver* *load* from an *unusual* *path*
  (a *Temp* *folder*, a *non-system32* *path*) = the *rootkit* / *EDR*
  *tell* (the *kernel* *tell*).

## Links

- [[etw]] — the *kernel's* *event* *bus* Sysmon *reads* (the *source*;
  Sysmon is the *log*)
- [[sigma]] — the *detection* *language* written against the *Sysmon*
  *schema*
- [[credential-dumping]] / [[lsass]] — the *LSASS* *dump* the *Event 10*
  *catches*
- [[beaconing]] — the *C2* *heartbeat* the *Event 3* *catches*
- [[defense-evasion-ad]] — the *evasion* hub (the *ETW* *evasion* defeats
  Sysmon)
- [[procdump]] / [[mimikatz]] — the *tools* the *Event 10* *catches* (the
  *LSASS* *dump*)
