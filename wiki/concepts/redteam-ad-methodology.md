---
title: "Red-Team AD Methodology (the operational kill-chain)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [red-team, active-directory, methodology, opsec, tradecraft]
---

# Red-Team AD Methodology (the operational kill-chain)

The **operational arc** of an authorized AD engagement — how the individual
technique pages in this wiki string together into a repeatable flow, and where
the OPSEC decisions live. The technique pages answer *what/how*; this page
answers *in what order, and how to operate quietly*. It's the hub for the
[[opsec-ad-tradecraft]], [[bloodhound-opsec]], [[defense-evasion-ad]],
[[c2-and-pivoting-ad]] and [[ticket-and-credential-opsec]] pages.

The governing rule is the wiki's recurring one: **enumerate before you
exploit.** Most of the chain is reconnaissance; the exploit is usually one
command once the path is known.

## Phases

### 1. Recon & situational awareness
Map the domain before touching anything sensitive. Passive/low-noise LDAP and
DNS enumeration, then graph the attack surface. See
[[situational-awareness]] for the on-host checks and [[bloodhound-opsec]] for
collection tradecraft. Primary building blocks: [[ldap]], [[smb]],
[[service-principal-name]], [[ad-structure]], [[ad-tier-model]].

### 2. Foothold / initial access
First domain credential or shell. Often from a captured hash
([[ntlm-relay-coercion]], [[mitm6-ipv6-relay]]), a sprayed/guessed password
([[password-spraying]] via [[kerbrute]]), or a pre-auth-less account
([[as-rep-roasting]]). Remote enum to find the targets is [[ad-enumeration]]. On the
foothold box itself the immediate next step is **local** privesc —
[[windows-privilege-escalation]] — because local admin is what unlocks
[[credential-dumping]] and, downstream, the coercion and lateral phases below.

### 3. Credential access
Turn a foothold into more identities: [[kerberoasting]], [[as-rep-roasting]],
[[dcsync]] (when rights allow), [[shadow-credentials]],
[[pkinit-unpac-the-hash]]. OPSEC here is mostly about **request volume and
enctype** — see [[opsec-ad-tradecraft]].

### 4. Lateral movement
Reuse identity material without cracking: [[pass-the-hash-and-ticket]],
[[pass-the-key]], [[overpass-the-hash]], then execute via
[[remote-execution]] (mind the [[kerberos-double-hop]]). Move through the
environment over C2 — [[c2-and-pivoting-ad]], built on [[pivoting-and-tunneling]].

### 5. Privilege escalation
Walk the graph to Tier 0: [[acl-abuse]], [[gpo-abuse]],
[[kerberos-delegation]] / [[resource-based-constrained-delegation]],
[[ad-cs-esc-attacks]], [[sccm-abuse]], trust hops ([[ad-trust-attacks]]).

### 6. Domain dominance
Own the domain secret: [[dcsync]] the [[krbtgt]], then forge
[[golden-silver-tickets]] / [[diamond-ticket]] as needed.

### 7. Persistence (only if in scope)
[[ad-persistence]], [[dcshadow]], [[skeleton-key]], [[sid-history]]. Most
engagements demonstrate, not deploy — confirm scope first.

### 8. Cleanup & reporting
Purge tickets and staged tooling ([[ticket-and-credential-opsec]]), collect
the evidence each phase produced, and map findings to remediation — the
defender's view lives in [[ad-tiering-and-hardening]] and [[honeytokens]].

## The offense/defense mirror

Every phase above has a detection footprint documented on its technique page.
[[ad-tiering-and-hardening]] is the structural counterpart to this
methodology: the tiering model is precisely what breaks phases 4–6, and this
flow doubles as the checklist for validating that hardening.

## See also

- [[opsec-ad-tradecraft]] — operating without lighting up the SOC
- [[bloodhound-opsec]] — collection tradecraft
- [[defense-evasion-ad]] — running tooling against EDR/AMSI/ETW
- [[c2-and-pivoting-ad]] — tunnelling AD tooling from an operator host
- [[ticket-and-credential-opsec]] — handling tickets and loot
- [[reverse-engineering-workflow]] — the RE/malware-domain analog of this arc (static → dynamic → detection)
- [[windows-privilege-escalation]] — the local (on-box) privesc step that runs between foothold and the domain phases above
- [[foothold-playbook]] — the condensed "you hold X → do Y next" version of these phases
- [[ad-error-decoder]] — when a step throws an error, decode it (the failure is the hint)
- [[ticket-manipulation]] — the kirbi/ccache/PtT plumbing the lateral phases lean on
