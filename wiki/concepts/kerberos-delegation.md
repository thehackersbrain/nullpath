---
title: "Kerberos Delegation (Unconstrained / Constrained / RBCD)"
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [kerberos, delegation, s4u, rbcd, impersonation, privilege-escalation]
---

# Kerberos Delegation (Unconstrained / Constrained / RBCD)

**Kerberos delegation** is the family of mechanisms that let **one service
act as a user on another service** (so the user's credentials aren't
re-sent in the clear). Done wrong, it's one of the highest-leverage AD
privesc/impersonation surfaces in this wiki: an attacker who controls (or
can coerce a user into) a machine with the *right* delegation attribute can
**impersonate any user to a target service** — often straight to a Tier-0
box or a DCSync-capable identity. The protocol mechanics (S4U2Self/S4U2Proxy)
live in [[s4u2self-s4u2proxy]]; the RBCD attribute deep-dive lives in
[[resource-based-constrained-delegation]]; the raw source summary lives in
[[kerberos-delegation-abuse]] (sources). This page is the **hub**: what each
of the three is, the attributes that carry it, and how to detect/harden it.

## The three flavors

| | **Unconstrained (UDE)** | **Constrained (CDE)** | **Resource-Based (RBCD)** |
|---|---|---|---|
| Attribute | `TrustedForDelegation` (a UAC bit, **on the machine account**) | `msDS-AllowedToDelegateTo` (**on the service**, a list of target SPNs) | `msDS-AllowedToActOnBehalfOfOtherIdentity` (**on the target resource**) |
| Set by | the *machine* (or whoever owns it) | the *service's* owner (a domain admin) | the **target resource** (a machine account — self-grantable) |
| Effect | the machine can obtain a TGS **for the user, to any service**, carrying the user's TGT | the service can obtain a TGS for the user **only to the listed SPNs** | the machine can **S4U2Self** any user to itself (impersonate any user *on that machine*) |
| Classic abuse | coerce a **high-priv user's TGT** onto the machine → impersonate them **anywhere** (incl. the DC → DCSync) | the service's target list is the blast radius | **any user → that machine** (credential-less via [[mitm6-ipv6-relay]]) |
| End-to-end | [[path-unconstrained-delegation-to-domain-admin]] | [[path-constrained-delegation-to-domain-admin]] | [[path-mitm6-rbcd-to-local-admin]], [[path-rbcd-to-domain-admin]] |

## The attributes (the attack surface)

- **`TrustedForDelegation`** — a **UAC bit on the machine account**. Any
  machine with this bit can "forward" a user's TGT to obtain TGSs for that
  user to *any* service. This is the **UDE** switch. **A machine with
  `TrustedForDelegation` + a way to pull a victim's TGT = UDE.** Who writes
  this attribute (or who controls a machine that has it) is the [[acl-abuse]]
  target. See [[service-account]] (machine accounts) and
  [[ad-tiering-and-hardening]] (why Tier-0 machines shouldn't have it).
- **`msDS-AllowedToDelegateTo`** — a **multi-valued attribute on the service
  (a computer account)** listing the SPNs it may delegate *to*. This is the
  **CDE** list. A writable CDE list (a low-priv principal with
  `GenericWrite`/`WriteDacl` on the service object — [[acl-abuse]]) can add
  the SPN of a **high-value target** (e.g. the DC, a SQL box, AD CS) to the
  list, turning that machine into a delegation pivot to that target.
- **`msDS-AllowedToActOnBehalfOfOtherIdentity`** — a **multi-valued attribute
  on the target resource (a computer account)** listing who may **act on
  behalf of others** on it. This is the **RBCD** switch. The killer property:
  it's written **on the target**, so a **machine account can grant *itself*
  the right to act on behalf of any user** — and a **low-priv user who can
  write this attribute** on a Tier-0 box can too. Full deep-dive:
  [[resource-based-constrained-delegation]].

## How the impersonation actually happens

- **UDE**: the machine holds (or you coerce onto it) a **victim's TGT**; the
  machine's S4U2Proxy requests TGSs *for the victim* to any service → the
  service authenticates *the victim* → you're the victim on that service.
  Point it at the **DC** and you're doing **DCSync as a high-priv user** —
  see [[path-unconstrained-delegation-to-domain-admin]].
- **CDE**: same, but the TGS is only valid for the **SPNs in
  `msDS-AllowedToDelegateTo`** — so the pivot is only as good as the target
  list (which is why *adding* a high-value SPN to the list is the abuse).
- **RBCD**: the machine **S4U2Self**-s *any* user to *itself* (it's in its
  own `msDS-AllowedToActOnBehalfOfOtherIdentity`) → impersonate that user
  *on that machine*. Combine with [[mitm6-ipv6-relay]] (coerce the user's TGT
  credential-less) and you need **no password** — see
  [[path-mitm6-rbcd-to-local-admin]].
- The protocol under all three is **S4U2Self / S4U2Proxy** — see
  [[s4u2self-s4u2proxy]].

## Red-team notes (OPSEC)

- **Enumerate the three attributes first** (`TrustedForDelegation`,
  `msDS-AllowedToDelegateTo`, `msDS-AllowedToActOnBehalfOfOtherIdentity`) via
  LDAP / [[bloodhound]] — the abuse is one attribute write or one coerced TGT,
  so know the exact edge before you touch anything.
- **UDE**: coerce **one** DC to the delegating host ([[printer-bug]] /
  [[ntlm-relay-coercion]]) and capture its TGT — don't spray coercion; one
  target, one capture.
- **RBCD needs a controlled SPN.** If `MachineAccountQuota > 0` you can add a
  computer to own one; otherwise use a host you already control. `MAQ = 0` is
  the common blocker — check it before planning the path.
- **Make the one write, then revert it.** Delegation-attribute writes fire
  5136/4662; do it once, run S4U, and clean the attribute back.
- **Run remotely.** `rbcd.py`, `getST.py`, `findDelegation.py` from Linux over
  the tunnel; `Rubeus.exe s4u` on-host. The 4769 `R0` still lands on the DC.

## Detection

- **Event 4769 with the `R0` (canonical name / "forwarded") flag** — a
  TGS request that's *forwarded* (carrying a prior TGT) is the delegation
  tell; correlate the requesting machine + the target SPN + the client.
- **Event 5136 / 4662 (attribute write)** on `TrustedForDelegation`,
  `msDS-AllowedToDelegateTo`, or `msDS-AllowedToActOnBehalfOfOtherIdentity` —
  a *change* to a delegation attribute is a high-fidelity signal (especially
  a low-priv principal writing it, or a machine granting itself RBCD).
- **A TGS to a DC** (`krbtgt`/the DC SPN) from a workstation — a UDE-to-DC
  pattern (see [[path-unconstrained-delegation-to-domain-admin]]).
- **BloodHound edges** — `GenericAll`/`WriteDacl`/`GenericWrite` onto a
  machine with `TrustedForDelegation`, or `AllowedToAct` (RBCD) edges, are
  the graph tells. See [[bloodhound]].

## Mitigations

- **Prune `TrustedForDelegation`** from machines that don't need it (the UDE
  switch is the most over-granted); especially **no `TrustedForDelegation` on
  Tier-0 / DC-adjacent boxes** ([[ad-tier-model]]).
- **Scope CDE lists** — `msDS-AllowedToDelegateTo` should list *only* the
  specific target SPNs the service needs (not `*/`).
- **Guard RBCD** — audit `msDS-AllowedToActOnBehalfOfOtherIdentity` writers;
  a machine should only list the principals that legitimately act on its
  behalf ([[resource-based-constrained-delegation]]).
- **ACL the attributes** — `GenericWrite`/`WriteDacl` on the delegation
  attributes is the pivot-in (see [[acl-abuse]]).
- **Alert on** 4769 `R0` and on 5136/4662 delegation-attribute writes.
- See [[ad-tiering-and-hardening]] for the delegation section of the baseline.

## Links

- [[s4u2self-s4u2proxy]] — the S4U protocol mechanics under all three
- [[resource-based-constrained-delegation]] — the RBCD attribute deep-dive
- [[kerberos-delegation-abuse]] — the raw source summary (source page)
- [[kerberos-authentication]] — the TGT/TGS flow delegation rides
- [[tgt-tgs]] — the tickets the S4U requests
- [[acl-abuse]] — the attribute-write pivot (GenericAll/WriteDacl/GenericWrite)
- [[mitm6-ipv6-relay]] — the credential-less TGT coercion that fuels RBCD
- [[dcsync]] — the high-value *target* of a UDE-to-DC pivot
- [[path-unconstrained-delegation-to-domain-admin]] — the UDE end-to-end chain
- [[path-constrained-delegation-to-domain-admin]] — the CDE end-to-end chain
- [[path-mitm6-rbcd-to-local-admin]] — the credential-less RBCD chain
- [[path-rbcd-to-domain-admin]] — the RBCD-on-DC → DCSync chain
- [[ad-tiering-and-hardening]] — the delegation hardening baseline
