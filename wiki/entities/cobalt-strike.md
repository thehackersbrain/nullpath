---
title: "Cobalt Strike (the red-team C2 framework)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, c2, red-team, post-exploitation]
---

# Cobalt Strike

The **commercial red-team C2 framework** — the *de-facto* standard for
**[[beaconing]]**, **[[process-injection]]**, and the *host-side*
post-exploitation (the *credential dump*, the *lateral*, the *pivot*). It
is the *C2* the [[beaconing]] page's *detection* section is built around
(the *known-C2* signature, the *JA3/JA4*, the *beacon + lateral*
correlation all *reference* Cobalt Strike's *default* behavior).

## Why it's the reference C2

- **The *beacon* is the *product*** — Cobalt Strike's core is the
  **beacon** (the *agent* that *checks in* on a schedule, *jittered*, to
  the *team server*). The *beacon* is the [[beaconing]] model *made* — the
  *periodicity*, the *jitter*, the *small-request/command-response* are
  *Cobalt Strike's* *default* *shape*.
- **The *post-exploitation* is *built-in*** — the *credential dump*
  (the *mimikatz* *loot*, the *LSASS* *dump*), the *lateral* (the *SMB*,
  the *WMI*, the *WinRM*), the *pivot* (the *socks* *proxy*, the *port*
  *forward*) are *native* *features* — not *scripts*, not *plugins*, the
  *core*. The *beacon* + the *post-exploitation* is the *red-team*
  *workflow* (the [[redteam-ad-methodology]] *C2* layer).
- **The *signature* is *known*** — a Cobalt Strike beacon has a *known*
  *signature* (a *specific* TLS *fingerprint* — the *JA3/JA4*, a
  *specific* *request* *path*, a *specific* *cert* *pattern*). The
  *detection* is the *signature* (the [[beaconing]] *C2-specific* *tell*).

## The *beacon* (the *product's* core)

The Cobalt Strike **beacon** is the [[beaconing]] *model*:
- **The *periodicity*** — the *beacon* *checks in* on a *fixed* interval
  (the *team server's* *sleep* *setting*).
- **The *jitter*** — the *beacon* adds *jitter* (a *random* ±% to the
  interval) to *avoid* a *perfect* *period*.
- **The *small-request / command-response*** — the *beacon* sends a
  *tiny* *request* (an *agent* ID, a *timestamp*) and gets a *command*
  (a *"run this"*, a *"dump this"*).

The *beacon* is the *C2's* *heartbeat* — the *definitive* tell of a
compromised host that's *still* *under* *control* (the [[beaconing]]
*point*).

## The *post-exploitation* (the *built-in* *workflow*)

- **The *credential* *dump*** — the *beacon* *runs* a *mimikatz* *loot*
  (the *LSASS* *dump*, the *sekurlsa*) — the [[credential-dumping]] /
  [[lsass]] *workflow*, *from the* *beacon*.
- **The *lateral*** — the *beacon* *spawns* a *new* *beacon* on a *new*
  host (the *SMB* *exec*, the *WMI* *exec*, the *WinRM* *exec*) — the
  [[process-injection]] / [[remote-execution]] *workflow*, *from the*
  *beacon*.
- **The *pivot*** — the *team server* *proxies* the *beacon's* *traffic*
  (the *socks* *proxy*, the *port* *forward*) — the *C2's* *reach* into
  the *internal* *network* (the [[c2-and-pivoting-ad]] *point*).

## The *evasion* (the *C2's* *answer*)

- **The *jitter* + the *channel*** — the *beacon's* *jitter* (the
  [[beaconing]] *evasion*) + the *channel* (a *CDN* over *TLS*, a *valid*
  *cert*) — the *timing-only* *tell* (the *harder* *tell*).
- **The *malleable* *profile*** — the *Cobalt Strike* *malleable* *profile*
  (a *custom* *beacon* *profile* — a *custom* *request* *path*, a *custom*
  *header*, a *custom* *TLS*) — the *C2-specific* *tell* is *defeated*
  (the *JA3/JA4* is *custom*, the *request* *path* is *custom*).
- **The *sleep* + the *on-demand*** — the *beacon* *sleeps* a *long* time
  (an *hour*, a *day*) and only wakes *on a trigger* — the *long,
  irregular* *period* (the *behavioral* *tell*, not the *timing* *tell*).

## Red-team notes (OPSEC)

- **The *default* is the *tell*** — a *default* Cobalt Strike beacon
  (the *default* *JA3/JA4*, the *default* *request* *path*, the *default*
  *cert*) is the *easiest* *C2* to *detect* (the *known-C2* *signature*).
  The *malleable* *profile* (the *custom* *JA3/JA4*, the *custom*
  *request* *path*) is the *evasion* — the *default* is the *tell*, the
  *malleable* is the *hide*.
- **The *lateral* is the *intent*** — a *beacon* *alone* is *"the host is
  held"*; a *beacon* + a *lateral* is *"the attacker is moving"* — the
  [[beaconing]] *highest-fidelity* *tell*. The *lateral* is the *action*
  that means *something* is *happening* *right now*.
- **The *channel* is the *biggest* *evasion*** — a *beacon* to a *bare IP*
  or a *no-TLS* *endpoint* is a *content* *tell*; a *beacon* to a *CDN*
  over *TLS* (with a *valid* *cert*) is a *timing-only* *tell* (much
  *harder*). The *channel* *choice* is the *biggest* *single* *evasion*.

## Links

- [[beaconing]] — the *C2's* *heartbeat* this *is* (the *known-C2* the
  *detection* *references*)
- [[c2-and-pivoting-ad]] — the C2/pivoting hub this belongs to
- [[process-injection]] — the *host* *action* the *beacon* *triggers* (the
  *SMB* *exec*, the *WMI* *exec*)
- [[credential-dumping]] / [[lsass]] — the *dump* the *beacon* *runs* (the
  *mimikatz* *loot*)
- [[defense-evasion-ad]] — the *evasion* hub (the *malleable* *profile*,
  the *channel*, the *sleep*)
- [[meterpreter]] — the *payload* the *beacon* *drops* (the *post-exploitation*
  *agent*)
- [[modern-c2-frameworks]] — the open-source C2 alternatives (Sliver, Mythic, Havoc)
