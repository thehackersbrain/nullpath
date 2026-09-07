---
title: Honeytokens / Honey SPNs / Canary Accounts
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [detection, active-directory, canary, blue-team]
---

# Honeytokens / Honey SPNs / Canary Accounts

**Honeytokens** are deliberately planted credentials, objects, or SPNs that
should *never* be legitimately used. Any interaction with one is high-fidelity
detection — low false-positive by construction, because a real admin or
service has no reason to touch them. They're the recurring cheap, high-signal
detection pattern referenced across nearly every attack page in this wiki.

## Types

- **Honey SPN** — an SPN registered on an account that has no real service.
  A [[kerberoasting]] request for it fires a **4769** (TGS requested) for a
  principal nobody requests in normal operation. Highest-signal Kerberos
  canary.
- **Honey account (canary account)** — a real AD user object that looks
  legitimate but is used by no one. Any logon (4624), password reset, DCSync
  (4662/4768), or delegation to it is an alert. Cheapest high-fidelity
  domain canary.
- **Honey group** — a group like `Domain Admins`-adjacent or a
  `Tier1-Canary` group with a honey account as the only member; membership
  changes or auth as a member alert.
- **Honey computer** — a computer object with a honey LAPS password or a
  honey SPN; auth from/to it alerts.
- **Honey GPO / honey ACE** — a GPO or object with a watchful ACE; a
  4670/5136 on it (someone granting themselves rights) alerts.
- **Honeyticket / honey PAC signer** — a canary in the
  "Kerberos pac signer" set; a ticket it signs that isn't expected alerts.
  (See [[kerberos-pac]].)

## Why they're high-fidelity

- **Baseline is zero.** No legitimate principal uses a honey SPN/account, so
  the alert threshold is "any use" — no noisy statistical modeling.
- **Catch the technique, not the tool.** A honey SPN catches *any*
  Kerberoaster (Rubeus, Mimikatz, Impacket, manual) because they all request
  the TGS the same way.
- **Cheap to deploy and audit.** Create the object, wire the event alert,
  done.

## Implementation (sketch)

```powershell
# Create a honey account (canary)
New-ADUser -Name "svc.canary01" -SamAccountName "svc.canary01" -Enabled `
  -Path "OU=Services,DC=corp,DC=local"
# Register a honey SPN on it
Set-ADUser svc.canary01 -ServicePrincipalName "CANARY/canary01.corp.local"

# (Optional) put a honey LAPS password and a honey ACE on a canary computer

# Alerting: fire on ANY of these involving the canary principal
#   4624 (logon)          — anyone authenticated as/for it
#   4769 (TGS requested)  — anyone requested its SPN  (honey SPN)
#   4768 (TGT requested)  — it requested a TGT
#   4662/4768             — it (or on its behalf) DCSync'd
#   5136 / 4670           — its ACL/attributes were modified
```

```bash
# Or deploy a set of honey SPNs across service accounts and alert on 4769
# for any SPN in the canary set. Canarytokens / custom AD modules automate
# the "plant + alert" pair.
```

## Operational notes

- **Don't let the honey look lazy.** Give it a plausible name and location;
  a canary named `test` in `Default OU` is easy to spot and skip.
- **Rotate/replace** if one is consumed (an attacker who catches a honey may
  note it and avoid similar ones).
- **Pair with the mitigation** — a honey SPN on a [[gmsa]]-protected account,
  a honey account in Protected Users, so the canary is realistic and the
  alert is clean.

## Links

- [[kerberos-authentication]] — "Honey accounts / honey SPNs / honeytokens" is
  listed as a cross-technique detection pattern here
- [[kerberoasting]] — honey SPNs are the primary Kerberoast detector
- [[as-rep-roasting]] — a honey account with preauth disabled catches AS-REP
  harvesting
- [[dcsync]] — a honey account that DCSyncs (4662) is a canary
- [[ad-tiering-and-hardening]] — where honeytokens sit in the hardening baseline

## References

- [SpecterOps: Honeytokens for AD](https://posts.specterops.io/)
- [ired.team: Detection (honeytokens)](https://www.ired.team/)
- [Canarytokens](https://canarytokens.org/)
