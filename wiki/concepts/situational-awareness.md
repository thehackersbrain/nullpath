---
title: "Situational Awareness (post-foothold AD recon)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [red-team, active-directory, enumeration, opsec, recon]
---

# Situational Awareness (post-foothold AD recon)

The first thing to do on a new foothold, and the cheapest: understand **who
you are, what you can reach, and where you sit** before making any noisy move.
This is phase 1 of the [[redteam-ad-methodology]] and the low-noise
counterpart to [[bloodhound-opsec]] — most of it is local or single-query
LDAP, not estate-wide sweeps.

## On-host: who am I

```powershell
whoami /all            # user, groups, privileges, integrity level
klist                  # cached Kerberos tickets (see [[ticket-and-credential-opsec]])
whoami /priv           # SeImpersonate / SeBackup / etc. — local privesc primitives
```

Key questions: local admin? which groups (any that map to a Tier-0 path)?
which privileges (SeImpersonate → [[potato-family]]; SeBackup →
[[ntds-dit]])? what integrity/AMSI/EDR context (feeds
[[defense-evasion-ad]])? Then run the local-privesc sweep ([[winpeas]]
`-q`) to see which [[windows-privilege-escalation|local privesc]] vectors the
box actually exposes before you pick your next move.

## The domain, quietly

Prefer a few targeted LDAP queries over broad sweeps. Native, low-noise:

```powershell
# domain + trust shape without external tooling
nltest /dclist:corp.local
nltest /domain_trusts /all_trusts        # trusts -> [[ad-trust-attacks]]
Get-ADDomain ; Get-ADForest              # if RSAT present

# high-value targets from LDAP (single scoped queries)
Get-ADUser -Filter 'AdminCount -eq 1'    # protected / Tier-0 principals
Get-ADUser -Filter 'ServicePrincipalName -like "*"'   # roastable -> [[kerberoasting]]
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true'  # -> [[as-rep-roasting]]
```

## Map yourself onto the tier model

Work out which tier your context sits in ([[ad-tier-model]]): a Tier-2
workstation admin is a different game from a Tier-1 server admin. The goal of
SA is to pick the **shortest path that stays in scope**, then hand off to
[[bloodhound-opsec]] for the graph and [[opsec-ad-tradecraft]] for how loudly
to walk it.

## What to note for the report

Domain/forest functional level, enforced Kerberos enctypes
([[kerberos-encryption-types]]), presence of LAPS/gMSA
([[laps]] / [[gmsa]]), and any obvious misconfig surfaced in passing — these
become findings regardless of whether you exploit them.

## See also

- [[redteam-ad-methodology]] — the flow this opens
- [[bloodhound-opsec]] — the graph-collection step after SA
- [[opsec-ad-tradecraft]] — how loudly to act on what you find
- [[ad-tier-model]] — where your context sits
- [[windows-privilege-escalation]] — the local-privesc sweep the on-host SA feeds into
- [[winpeas]] — the enumeration tool for that sweep
