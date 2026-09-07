---
title: "Foreign Security Principals (cross-trust group membership abuse)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, trusts, forest, acl, enumeration, opsec]
---

# Foreign Security Principals

When a principal from a **trusted** domain/forest is added to a group (or ACL) in
*this* domain, AD represents that external SID as a **Foreign Security Principal
(FSP)** object under `CN=ForeignSecurityPrincipals,DC=...`. FSPs are how
cross-trust access is granted — and they're a **quiet** attack path: if you
already control a principal in forest A that is a member of a privileged group
(or holds an ACL) in forest B, you just **use** that access. No trust-key forging
([[trust-key-abuse]]), no SID-filtering fight — it's legitimate authentication,
so it's low-signal. This is the first thing to check across any trust
([[ad-trusts]]).

## The abuse

- A user/group/computer in your forest is a **member of a group in the target
  forest** (Domain Admins is rare but Server Operators, Backup Operators,
  helpdesk, or a custom admin group is common), or is granted an **ACL edge**
  (GenericAll/WriteDacl → [[acl-abuse]]) on a target-forest object.
- SID filtering doesn't stop this: you're a *real* member, presenting a *real*
  SID that belongs to your (trusted) forest — exactly the SIDs cross-forest
  trusts honor.
- Also check **password/hash reuse** across forests (admins reuse), and
  **foreign-controlled service accounts / delegation**.

## Enumeration

```powershell
# PowerView — who from OUTSIDE is in this domain's groups, and vice versa
Get-DomainForeignGroupMember -Domain target.forestb.local
Find-ForeignGroup -Domain corp.local            # your principals in foreign groups
Get-DomainObject -Identity 'CN=ForeignSecurityPrincipals,...' # raw FSP container
```

```bash
# BloodHound is the right tool — collect BOTH forests and query cross-domain edges:
#   "shortest path from <owned principal in forest A> to <target in forest B>"
bloodhound-python -d forestb.local -u user@foresta.local -p pass -c All -ns <dc-b>
```

BloodHound's cross-domain edges (`MemberOf`, `AdminTo`, ACL edges spanning a
trust) are the cleanest view — the FSP is the node where the trust is crossed.

## Red-team notes (OPSEC)

- **This is the stealthy cross-forest path.** You authenticate as a genuine
  member — the target sees a normal cross-trust logon (4624/4769), not a forged
  ticket or a coercion. Prefer it over [[trust-key-abuse]] when a foreign
  membership already exists.
- **Collect both forests before deciding.** The path is invisible from one side;
  you need BloodHound data from the target forest (via your foreign principal's
  read access) to see that your account is privileged there.
- Watch for **stale FSPs** (a deleted foreign account leaving an orphaned SID in a
  group) — reclaimable in some scenarios.

## Detection

- **Cross-trust logons** (4624/4768/4769) from a foreign domain SID to sensitive
  resources — legitimate-looking, so detection leans on *baselining* which
  foreign principals should touch what.
- Periodic audit of **foreign group memberships** in privileged groups and
  cross-forest ACLs (the misconfig itself).

## Links

- [[ad-trusts]] — the trust context that makes FSPs possible
- [[trust-key-abuse]] — the loud alternative when no foreign membership exists
- [[acl-abuse]] — foreign-held ACL edges are exploited the same way as local ones
- [[ad-trust-attacks]] — SID-filtering weaknesses for the harder cross-forest cases
- [[bloodhound]] — cross-domain edge queries
