---
title: Service Accounts vs Machine Accounts
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, accounts, service-account, machine-account, gmsa, kerberoasting]
---

# Service Accounts vs Machine Accounts

AD principals come in a few flavors, and **which one an account is decides
which attack applies to it**. The three that matter: **user accounts**,
**service accounts**, and **machine (computer) accounts**. Get the distinction
right and you know immediately whether to [[kerberoasting|Kerberoast]] it,
[[resource-based-constrained-delegation|RBCD]] to it, forge a
[[golden-silver-tickets|Silver Ticket]] for its SPN, or coerce it as a
[[petitpotam|PetitPotam]] target. This page is the taxonomy the rest of the
wiki assumes. See [[gmsa]] for the modern managed-service-account variant and
[[service-principal-name]] for the SPN that ties an account to a service.

## The three types

### User accounts
Interactive / non-service logon accounts. Normal password policy applies
(pre-auth on, crackable). Attacked via **AS-REP roast**
([[as-rep-roasting]]), **LSASS/SAM dump** ([[lsass]], [[sam-database]]), or
being the *target* of a delegation/ACL edge.

### Service accounts
Accounts that run a **service** (SQL, IIS, a line-of-business app) and are
typically granted a **service principal name** (SPN) so clients can Kerberos-auth
to that service. These are the [[kerberoasting]] targets: anyone can request a
TGS for the SPN and crack the **service account's password**. A service
account with a *good* password (or a gMSA) resists this; a service account with
a weak/static password is a standing lateral-movement credential. See
[[service-principal-name]] for the SPN and [[kerberos-authentication]] for why
the SPN → service-account mapping matters.

**Why service accounts are high-value:**
- They often run with **local admin** or **machine-context** rights on the
  host that runs the service.
- They're frequently **static passwords** set once and never rotated — a
  durable credential.
- A cracked service password → [[pass-the-hash-and-ticket|PtH]] lateral, or
  (if the account is privileged) a direct privesc.

### Machine (computer) accounts
The `HOST$` account for each domain-joined computer. Not something a human
"logs in as" in the normal sense — it's the computer's own identity, used for
**machine-to-DC** and **machine-to-service** Kerberos. Machine accounts are
the linchpin of several attacks:

- **The RBCD target** — you write `msDS-AllowedToActOnBehalfOfOtherIdentity`
  **on the computer object** and mint a TGS *to that machine*
  ([[resource-based-constrained-delegation]]).
- **The Silver Ticket secret** — a Silver Ticket forges a TGS using the
  *machine account's* key + the service SPN (e.g. `cifs/<host>`), scoped to
  that host ([[golden-silver-tickets]]).
- **The coercion target** — [[petitpotam]]/coercion forces a machine (often a
  **DC**) to NTLM-auth to the attacker; a **DC's machine account** then yields
  DCSync ([[dcsync]]).
- **The AD CS machine cert** — ESC8 relays to AD CS to mint a **machine
  certificate** for the coerced machine, authenticating *as the machine*
  ([[esc8-ntlm-relay-adcs]]).

**Why machine accounts are high-value:** a domain-joined machine's account
often has **local admin on itself**, and a DC's machine account has **DCSync
rights** — so "become the machine" frequently *is* "become admin on that box"
or "replicate the whole domain."

## gMSA — the managed service account

A **Group Managed Service Account** is a service account whose **password is
auto-rotated by AD** (via a Key Distribution Service). This breaks the static
password that [[kerberoasting]] relies on — you still get a TGS, but the key
rotates, so a cracked key goes stale fast. gMSA is the recommended replacement
for static service accounts. See [[gmsa]] for the mechanics and why it's the
recurring mitigation across this wiki.

## Quick "which attack, which account" table

| Account type | Primary attack | Why |
| --- | --- | --- |
| User (preauth off) | [[as-rep-roasting]] | AS-REP encryptable with the user hash |
| User (privileged) | ACL / [[sid-history]] / [[shadow-credentials]] | write an attribute to become the account |
| Service (SPN) | [[kerberoasting]] | TGS for the SPN cracks the service password |
| Service (static pw) | [[pass-the-hash-and-ticket\|PtH]] lateral | a durable, crackable credential |
| Service (gMSA) | (resists roast) | auto-rotating key ([[gmsa]]) |
| Machine (computer) | [[resource-based-constrained-delegation]], [[golden-silver-tickets\|Silver Ticket]], coercion | become the machine / DCSync / machine cert |
| Machine (DC) | [[dcsync]] via coercion | the DC's account replicates the domain |

## Detection

- **Service account logons** — a service account authenticating from an
  unexpected host/time (it should only appear where its service runs).
- **Machine account DCSync** — 4662 from a `HOST$` account (a machine
  replicating) — a strong tell ([[dcsync]]).
- **Machine cert issuance** — AD CS 4886 for a machine account at an odd time
  ([[esc8-ntlm-relay-adcs]]).
- **SPN TGS requests** — 4769 bursts for service SPNs (Kerberoast).
- **Account age / password history** — a static service password (no rotation)
  is itself a finding.

## Mitigations

- **Use gMSA** (or at least rotate) for service accounts — kills the static
  password ([[gmsa]]).
- **Least-privilege service accounts** — don't give a service account domain
  admin or DCSync rights.
- **Protect machine accounts** — Tier-0 machines (DCs) are Tier-0 principals;
  their `HOST$` should not hold excess rights ([[ad-tiering-and-hardening]]).
- **Alert on machine-account DCSync** and machine-cert issuance.

## Links

- [[service-principal-name]] — the SPN that makes a service account roastable
- [[gmsa]] — the managed (auto-rotating) service account
- [[kerberoasting]] — the service-account attack
- [[as-rep-roasting]] — the user-account attack
- [[resource-based-constrained-delegation]] — the machine-account (computer object) attack
- [[golden-silver-tickets]] — the Silver Ticket (machine secret)
- [[dcsync]] — the DC machine-account payoff
- [[esc8-ntlm-relay-adcs]] — the AD CS machine-cert path
- [[ad-tiering-and-hardening]] — the account-tiering controls

## References

- [Microsoft: managed service accounts](https://learn.microsoft.com/en-us/windows-server/identity/kerberos/managed-service-accounts)
- [Microsoft: computer accounts](https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/computer-account)
- [ired.team: AD accounts](https://www.ired.team/)
