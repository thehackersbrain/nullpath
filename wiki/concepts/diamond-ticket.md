---
title: Diamond Ticket
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [kerberos, active-directory, ticket-forgery, privilege-escalation]
---

# Diamond Ticket

A **Diamond Ticket** is a stealthier cousin of the
[[golden-silver-tickets|Golden Ticket]]: instead of **forging a TGT from
scratch**, you **request a *real* TGT from the KDC, decrypt it with the
`krbtgt` key, modify its PAC** (e.g. add the Domain Admins SID), and
**re-encrypt/re-sign it** with the same key. The result is a forged TGT built on
a **genuine, KDC-issued ticket** — correct lifetime, correct structure, a
real-looking PAC — which defeats the anomaly detections that catch Golden
Tickets minted entirely offline.

> **Correction (2026-09-07):** an earlier version of this page framed a Diamond
> Ticket as an *AES128 downgrade forgery*. That was inaccurate. The enctype is
> **orthogonal** — a Diamond can be built with whatever `krbtgt` key you hold
> (RC4/AES128/AES256). The defining property is **modifying a real TGT** rather
> than the key size. **Golden = forge from nothing; Diamond = modify a real
> TGT's PAC; [[sapphire-ticket|Sapphire]] = Diamond, but inject a *real*
> privileged PAC pulled via S4U2self.**

## Why it's stealthier than a Golden Ticket

Golden Tickets are minted offline, so they tend to carry tells: a **default /
over-long lifetime**, a **hand-built PAC** with only the required fields or an
odd group list, timestamps that don't line up with a real logon. A Diamond
Ticket starts from a **legitimately issued TGT**, so:

- The **ticket times and structure are what the KDC actually produces** — no
  "10-year TGT" anomaly.
- The **PAC is a real one you edited**, not a fabricated shell — fewer
  size/field anomalies (though the *edit* itself, the injected SID, is still the
  thing detection can look for).
- There is a matching **4768 (AS-REQ)** on the DC, because you *did* request a
  real TGT — a Golden has no corresponding AS-REQ.

## Prerequisites

- The **`krbtgt` key** (RC4 hash or AES128/AES256) — from [[dcsync]] or an
  offline [[ntds-dit]] dump.
- **Valid domain credentials** for *some* account (you need to request the real
  TGT that you then modify) — a low-priv user is fine.
- The domain SID and the target user/group SIDs to inject.

## Commands

```powershell
# Rubeus has a dedicated `diamond` action: request a real TGT as a low-priv
# user, decrypt with the krbtgt key, rewrite the PAC to Administrator + DA, re-sign.
Rubeus.exe diamond /krbkey:<krbtgt-aes256-key> /enctype:aes ^
  /user:lowpriv /password:'LowPass' /domain:corp.local ^
  /ticketuser:Administrator /ticketuserid:500 /groups:512 /ptt
```

```bash
# Impacket ticketer with -request builds the same idea: it requests a real TGT
# first, then modifies it (vs. a pure offline forge without -request):
ticketer.py -request -user lowpriv -password 'LowPass' \
  -nthash <krbtgt-nthash> -domain-sid S-1-5-21-... -domain corp.local Administrator
```

**Verify:** `Rubeus.exe triage` / `klist` shows the TGT; `whoami /all` lists
`corp.local\Administrator` plus the injected `512` (Domain Admins) group SID.

## Where it sits among the forgeries

- **[[golden-silver-tickets|Golden]]** — TGT forged from scratch with `krbtgt`.
  Most flexible, most anomalous.
- **Diamond** — a *real* TGT with an edited PAC. Stealthier structure/lifetime.
- **[[sapphire-ticket|Sapphire]]** — a Diamond whose injected PAC is a **real
  privileged user's PAC** obtained via S4U2self — the least detectable, since the
  PAC itself is genuine.

All three need the `krbtgt` key and are **post-DA persistence/impersonation**
primitives, not privilege escalations.

## Detection

- The **injected SID is the tell**, not the ticket shape: a TGT/PAC for an
  account that now claims Domain Admins (or another group it isn't really in) —
  correlate group membership in the PAC against the real directory.
- **Behavioral**: a DA-privileged ticket in use from a non-Tier-0 host; a
  low-priv account that requested a normal TGT (4768) then suddenly wields
  DA rights.
- Diamond deliberately **avoids the lifetime/structure anomalies** used against
  Golden, so lean on the SID/behavioral signals and on the **`krbtgt`
  acquisition** ([[dcsync]] / offline [[ntds-dit]] dump) that had to precede it.

## Mitigations

- **Rotate `krbtgt` twice** ([[krbtgt]]) — invalidates all tickets signed with
  the compromised key, Diamond included.
- **Disable RC4** and enforce AES ([[kerberos-encryption-types]]) — narrows the
  keys an attacker can forge with and makes an RC4 build stand out.
- Detect and alert on the **replication (DCSync)** that grabs `krbtgt` in the
  first place — the acquisition is the loud, catchable step.

## Links

- [[golden-silver-tickets]] — the base forgery Diamond refines (forge-from-scratch)
- [[sapphire-ticket]] — the stealthier sibling (injects a *real* PAC via S4U2self)
- [[krbtgt]] — the key used to decrypt/re-sign the real TGT
- [[kerberos-encryption-types]] — enctypes (orthogonal to Diamond, contra the old framing)
- [[dcsync]] — how you obtain the `krbtgt` key
- [[kerberos-pac]] — the PAC you edit inside the real ticket

## References

- [SpecterOps: The Diamond Ticket](https://posts.specterops.io/the-diamond-ticket-e38455777635)
- [Rubeus (GhostPack) — diamond](https://github.com/GhostPack/Rubeus)
- [ired.team: Kerberos ticket forging](https://www.ired.team/active-directory-kerberos-abuse/kerberos-attacks)
