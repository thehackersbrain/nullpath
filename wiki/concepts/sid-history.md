---
title: SID History Abuse
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, privilege-escalation, forest-trust, acl-abuse]
---

# SID History Abuse

The `sidHistory` attribute on an AD user or group lets it **carry extra SIDs**
in its Kerberos **[[kerberos-pac|PAC]]**. When the account authenticates, the
PAC includes every SID in `sidHistory`, and AD grants the memberships those
SIDs imply. Writing a privileged SID into `sidHistory` (you need
**GenericWrite** on that attribute — an [[acl-abuse]] play) is a direct
privilege-escalation and **cross-forest pivot** primitive.

## How it grants access

- **Same domain** — add a high-priv group SID (e.g. `Domain Admins`'s
  `S-1-5-21-...-512`) to a user's `sidHistory`. Next auth, the user's PAC
  claims Domain Admins membership → they *are* a Domain Admin, with no group
  membership object changed.
- **Cross-forest** — add a **foreign forest's** privileged group SID (e.g.
  the parent forest's **Enterprise Admins** SID) to a user in the child
  forest. Over the forest trust, that SID is honored → the user is Enterprise
  Admin in the *other* forest. This is the classic cross-forest trust pivot
  and the core of [[ad-forest-trust-attacks]] / [[ad-trust-attacks]].

## The SID filtering catch (and its bypass)

By default, at a forest trust, **SID filtering** strips SIDs from *other*
domains/forests out of the PAC — so a foreign SID in `sidHistory` gets removed
and the pivot fails. The bypass: the foreign SID must be "trusted" across the
boundary, which happens when:

- The account (or a group it's in) is a member of the **"External Access"**
  group (`S-1-22-1-1`, `EXTERNAL_ACCESS`), **or**
- The trust is configured to **not** filter (TREAT_AS_EXTERNAL off / the
  `SID_HISTORY` trust direction), **or**
- You write the foreign SID into a **group** that is itself a member of
  External Access / has the cross-trust attribute.

So the practical chain is: GenericWrite on a user/group → write the foreign
privileged SID (or the External Access group membership) → the SID survives
the trust → pivot. See [[ad-trust-attacks]] for the trust-side controls
(TREAT_AS_EXTERNAL, SID filtering) this interacts with.

## Commands

```powershell
# Enumerate — who has sidHistory entries (PowerView)
Get-DomainUser -Properties sidhistory | Where-Object {$_.sidhistory}
Get-DomainGroup -Properties sidhistory | Where-Object {$_.sidhistory}

# Write a SID into a user's sidHistory (need GenericWrite on the attr)
# Example: add the Domain Admins SID (S-1-5-21-...-512) to 'attacker'
Set-DomainObject -Identity attacker -Set @{'sidHistory'='S-1-5-21-0000000000-0000000000-0000000000-512'}

# Cross-forest: add the parent forest's Enterprise Admins SID
Set-DomainObject -Identity attacker -Set @{'sidHistory'='S-1-5-21-PARENTFOREST-...-519'}
```

```bash
# Impacket / ldapmodify — write sidHistory directly (need the write right)
#   ldapmodify: replace sidHistory with the target SID
# Then force a re-auth (logon) so the PAC picks up the new SID.
```

## Detection

- **Event 5136** — directory object modified; specifically a change to the
  `sidHistory` attribute (GUID `f9a1bc4a-...`) is the high-fidelity tell.
- A PAC (4768/4769) that **suddenly contains** a high-priv or foreign SID for
  an account that never had it.
- `sidHistory` entries at all on Tier-0 / privileged accounts (config audit —
  they should be rare and intentional).
- A foreign (cross-forest) SID appearing in a PAC — the pivot in action.

## Mitigations

- **Least privilege on `sidHistory`** — few objects should have write access
  to it; audit with BloodHound / `Get-DomainObjectAcl`.
- **Keep SID filtering on** forest trusts + use **TREAT_AS_EXTERNAL** and the
  **External Access** group deliberately ([[ad-trust-attacks]]).
- **Alert on 5136** for `sidHistory` changes and on PACs containing foreign SIDs.
- [[ad-tiering-and-hardening]] — don't let low-tier principals hold
  `sidHistory` write on Tier-0 objects.

## Links

- [[kerberos-pac]] — the PAC is what carries the sidHistory SIDs at auth
- [[acl-abuse]] — GenericWrite on `sidHistory` is the access primitive
- [[ad-trusts]] — trust fundamentals (why intra-forest SIDs aren't filtered)
- [[trust-key-abuse]] — injecting these SIDs into a forged inter-realm/trust ticket
- [[ad-trust-attacks]], [[ad-forest-trust-attacks]] — the cross-forest trust controls (SID filtering, TREAT_AS_EXTERNAL)
- [[krb5pac]] — the PAC manipulation that injects the privileged SID
- [[dcshadow]] — a stealthier delivery for sidHistory writes (via MS-DRSR replication)
- [[path-cross-forest-trust-pivot]] — the full cross-forest attack path
- [[ad-tiering-and-hardening]] — the structural mitigation

## References

- [MS-ADTS: sidHistory](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts)
- [SpecterOps / ired.team: SID History](https://www.ired.team/)
- [BloodHound (SidHistory edge)](https://bloodhound.specterops.io/resources/edges/)
