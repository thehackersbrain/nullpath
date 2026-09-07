---
title: "OPSEC Tradecraft for AD Ops (operating without tripping the SOC)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [red-team, active-directory, opsec, detection, tradecraft]
---

# OPSEC Tradecraft for AD Ops

Every AD technique in this wiki has a **detection footprint** section. This
page is the offensive read of those: for each noisy primitive, what the SOC
sees and how to blend. It is the connective tissue of the
[[redteam-ad-methodology]] flow.

The core principle: **the exploit is one request; the noise is in the
enumeration and the volume.** Enumerate deliberately, act narrowly.

## The noise/blend table

| Technique | What fires | Blend tactic |
| --- | --- | --- |
| [[kerberoasting]] | 4769 burst, RC4 (`0x17`) TGS | Roast the *2–3* accounts you actually want, not all SPNs; space requests; request AES where the account supports it to avoid the RC4 tell |
| [[as-rep-roasting]] | 4768 type-0 burst | Target known pre-auth-less accounts from LDAP first; don't spray the whole forest |
| [[dcsync]] | 4662 with replication GUIDs from a non-DC | Pull only the accounts you need (`-just-dc-user krbtgt`), from a host/context that looks plausible |
| LDAP recon | 1644 (if verbose logging), huge queries | Page results, filter server-side, avoid `(objectClass=*)` sweeps — see [[bloodhound-opsec]] |
| Session hunting | 4624/net-session sweeps | Use `DCOnly` collection; skip live session enumeration unless needed |
| [[ntlm-relay-coercion]] | coercion RPC + relayed auth | Coerce one target, relay to one service; don't spray coercion |

## Enctype as a signal

RC4 (`0x17`) tickets crack fastest, but **RC4 on an AES domain is the single
highest-signal Kerberos tell** ([[kerberos-encryption-types]]). On a mature
target, requesting AES and cracking slower is often the better trade than
lighting up a `0x17` alert. Decide per-engagement based on the domain's
enforced enctypes.

## Volume, timing, targeting

- **Batch size** — a single principal requesting many distinct SPNs/accounts
  in a short window is the classic burst signature. Cap it.
- **Timing** — blend with business hours; automated tooling at 03:00 stands
  out.
- **Targeting over spraying** — pull the graph ([[bloodhound-opsec]]), pick
  the path, then act on the specific objects on it.
- **Minimize DC touches** — prefer the primitive that needs fewer DC
  interactions; e.g. [[dcsync]] one account vs an [[ntds-dit]] dump when you
  only need `krbtgt`.

## Honeytokens

Assume [[honeytokens]] exist: honey SPNs, canary accounts with replication
rights, decoy admin objects. A request for one is malicious *by definition*,
so validate targets against real usage (logon history, description fields)
before roasting or DCSyncing them.

## See also

- [[redteam-ad-methodology]] — the operational flow this supports
- [[bloodhound-opsec]] — quiet collection
- [[defense-evasion-ad]] — host-level evasion when running tooling
- [[honeytokens]] — the tripwires to avoid
- [[ad-tiering-and-hardening]] — the defender's side of every row above
