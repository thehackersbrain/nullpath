---
title: "Sigma (the vendor-agnostic detection rule language)"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, detection, sigma, rules, telemetry]
---

# Sigma

**Sigma** — the **vendor-agnostic detection-rule language**. A Sigma rule
is a *YAML* *description* of a *detection* (the *event*, the *field*, the
*value*, the *logic*) that is *translated* into a *vendor-specific*
*detection* (a **Splunk** *SPL*, a **Elastic** *query*, a **Sysmon**
*alert*) by a *Sigma-to-X* *converter*. It's the *detection* *language*
the [[reverse-engineering-workflow]] *step 4* (the *synthesis*) *outputs*
— the *Yara* *rule* (the *static* *tell*) and the *Sigma* *rule* (the
*behavioral* *tell*) are the *two* *detection* *outputs* of the
*analysis*.

## Why it's the detection language

- **The *vendor-agnostic*** — a Sigma *rule* is *not* a *Splunk* *SPL* or
  an *Elastic* *query*; it's a *description* of the *detection* (the
  *event*, the *field*, the *value*, the *logic*) that is *translated*
  into the *vendor-specific* *detection* by a *converter*. The *rule* is
  *written once*, *deployed* *everywhere* (the *Splunk*, the *Elastic*,
  the *Sysmon* *alert*).
- **The *open* *community*** — the Sigma *rules* are *open* (a *GitHub*
  *repo* of *thousands* of *rules*) — the *community* *writes* the
  *rules* (the *LSASS* *dump*, the *beacon*, the *Kerberoasting*), the
  *defender* *deploys* them. The *community* is the *detection*
  *pipeline*.
- **The *Sysmon* *schema*** — the Sigma *rules* are *written against* the
  [[sysmon]] *schema* (the *EventID 10* = *Process Access*, the
  *EventID 3* = *Network Connect*) — the *Sysmon* *schema* is the
  *detection* *language*; the *Sigma* *rule* is the *detection* *logic*.

## The *rule* (the *detection* *description*)

A Sigma *rule* is a *YAML* *file*:
```yaml
title: LSASS Access from Non-LSA Parent
status: stable
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    SourceImage|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection
level: high
```

The *rule* *describes* the *detection* (the *event* = *Sysmon* *EventID
10*, the *field* = *TargetImage* / *SourceImage*, the *value* = *lsass.exe*
/ *cmd.exe*, the *logic* = *selection*). The *converter* *translates* it
into the *vendor-specific* *detection* (a *Splunk* *SPL*, an *Elastic*
*query*).

## The *workflow* (the *detection* *pipeline*)

1. **The *analysis*** — the [[reverse-engineering-workflow]] *step 4*
   (the *synthesis*) — the *model* of the *binary* (the *stages*, the
   *checks*, the *secrets*, the *behavior*).
2. **The *high-fidelity* *tell*** — the *specific* *combination* (this
   *import* + this *string* + this *C2*) — the *Yara* *rule* (the
   *static* *tell*) and the *Sigma* *rule* (the *behavioral* *tell*).
3. **The *rule* *write*** — the *Yara* *rule* (the *static* *tell* — a
   *string*, a *byte* *pattern*, an *import* *combo*) and the *Sigma*
   *rule* (the *behavioral* *tell* — the *API* *sequence*, the
   *process/file/network* *event*).
4. **The *deploy*** — the *Sigma* *rule* is *translated* into the
   *vendor-specific* *detection* (the *Splunk*, the *Elastic*, the
   *Sysmon* *alert*) and *deployed* (the *defender's* *pipeline*).

## The *Yara* vs. the *Sigma* (the *two* *outputs*)

- **The *Yara* *rule*** — the *static* *tell* (a *string*, a *byte*
  *pattern*, an *import* *combo*) — the *file-based* *detection* (the
  *sample* on disk).
- **The *Sigma* *rule*** — the *behavioral* *tell* (the *API* *sequence*,
  the *process/file/network* *event*) — the *log-based* *detection* (the
  *host* *telemetry*).

The *two* *outputs* are the *two* *detection* *layers*: the *Yara*
*catches* the *sample* (the *file*); the *Sigma* *catches* the *behavior*
(the *host*). The *sample* is the *past*; the *behavior* is the *present*.

## Red-team notes (OPSEC / the *attack* *side*)

- **The *high-fidelity* is the *goal*** — the *specific* *combination*
  (this *import* + this *string* + this *C2*) beats the *generic* *tell*
  (a *process* calling *CreateRemoteThread*) — the *analysis* is what
  gets you the *specific*. The *high-fidelity* *rule* is the *low-false-
  positive* *rule* (the *defender* *trusts* it, the *attacker* *evades*
  it).
- **The *Yara* is the *file*, the *Sigma* is the *host*** — the *Yara*
  *rule* *catches* the *sample* (the *file* on disk); the *Sigma* *rule*
  *catches* the *behavior* (the *host* *telemetry*). The *fileless*
  *payload* (the [[meterpreter]] *in-memory* *load*) *evades* the *Yara*
  (no *file*) but *not* the *Sigma* (the *behavior* is *still* there).
- **The *community* is the *pipeline*** — the Sigma *rules* are *open*
  (a *GitHub* *repo* of *thousands* of *rules*) — the *community*
  *writes* the *rules*, the *defender* *deploys* them. The *attacker's*
  *evasion* is the *community's* *next* *rule* (the *cat-and-mouse*).

## Detection (the *defender's* *frame*)

- **The *rule* is the *detection*** — the *Sigma* *rule* is the
  *detection* (the *event*, the *field*, the *value*, the *logic*); the
  *converter* is the *translation* (the *vendor-specific* *detection*);
  the *deploy* is the *pipeline* (the *defender's* *system*).
- **The *high-fidelity* is the *low-false-positive*** — the *specific*
  *combination* (the *high-fidelity* *tell*) is the *low-false-positive*
  *rule* (the *defender* *trusts* it); the *generic* *tell* (a *process*
  calling *CreateRemoteThread*) is the *high-false-positive* *rule* (the
  *defender* *ignores* it).
- **The *behavior* is the *present*** — the *Sigma* *rule* *catches* the
  *behavior* (the *host* *telemetry*) — the *present* (the *host* is
  *still* *compromised*); the *Yara* *rule* *catches* the *sample* (the
  *file*) — the *past* (the *sample* was *dropped*).

## Links

- [[sysmon]] — the *host* *telemetry* the *Sigma* *rules* are *written
  against* (the *schema*)
- [[etw]] — the *kernel's* *event* *bus* the *Sigma* *rules* (the
  *Sysmon* *events*) *read*
- [[reverse-engineering-workflow]] — the *step 4* (the *synthesis*) that
  *outputs* the *Sigma* *rule*
- [[beaconing]] — the *C2* *heartbeat* a *Sigma* *rule* *catches* (the
  *Event 3* *periodicity*)
- [[credential-dumping]] / [[lsass]] — the *LSASS* *dump* a *Sigma*
  *rule* *catches* (the *Event 10* *Process Access*)
- [[defense-evasion-ad]] — the *evasion* hub (the *attacker's* answer to
  the *Sigma* *rule*)
