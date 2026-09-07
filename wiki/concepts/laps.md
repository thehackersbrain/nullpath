---
title: LAPS (Local Administrator Password Solution)
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [active-directory, local-admins, lateral-movement, hardening]
---

# LAPS (Local Administrator Password Solution)

**LAPS** (now "Local Administrator Password Solution" / Microsoft LAPS) sets
a **unique local admin password per computer** and stores it in AD (on the
computer object), replacing the old "one domain-wide local admin password"
anti-pattern. It's both a **mitigation** (defeats lateral movement via a
reused local admin password) and an **attack surface** (if you can *read* the
LAPS password attribute, you have local admin on that host).

## The attributes (what's stored where)

- `ms-MCS-ADMPassword` (or the older `ms-MCS-ADMPassword`) — the LAPS local
  admin **password** (plaintext), on the computer object.
- `ms-MCS-ADMPasswordExpirationTime` — when it next rotates.
- The local `Administrator` hash in [[sam-database]] *is* the LAPS password's
  hash — so reading LAPS = reading the local admin password.

## LAPS as a mitigation

- **Unique per host** — compromise one host's local admin and you only have
  that host, not the whole domain.
- **Auto-rotating** — the password changes on a schedule, so a captured one
  is short-lived.
- **Least-priv read** — only accounts with the LAPS read right (or Tier-0
  admins) can see it, so it's not world-readable.
- This is a core part of [[ad-tiering-and-hardening]]'s local-admin story.

## LAPS as an attack

If you hold the right to **read** a computer's LAPS password (a specific ACE /
the "LAPS" right, `GenericAll`/`GenericRead` over the computer object, or
membership in the LAPS reader group), you recover the local admin password
and get **local admin on that machine** — a lateral/privesc pivot.

```powershell
# Read a computer's LAPS password (PowerView) — need the LAPS read right
Get-DomainComputer targetpc -Properties ms-mcs-admpassword
# or by name
Get-DomainComputer -Identity targetpc -Properties ms-MCS-ADMPassword |
  Select-Object ms-MCS-ADMPassword
```

```bash
# Impacket / BloodHound — the "HasLAPS" edge
# BloodHound: a HasLAPS edge from your principal to a computer = you can read its LAPS pw
# Then: recover the pw, use it as local admin:
psexec.py DOMAIN/<laps-pw-user>:<laps-pw>@targetpc
# or
wmiexec.py -hashes <lm>:<nt-of-laps-pw> DOMAIN/Administrator@targetpc
```

## How the "can read LAPS" right is obtained

- A **direct ACE** granting the LAPS read right on the computer object.
- **GenericAll / GenericRead** over the computer object ([[acl-abuse]]) —
  reading `ms-MCS-ADMPassword` is included.
- **Membership** in the group that LAPS is configured to let read passwords
  (often the local admins group or a dedicated "LAPS readers" group).
- **AdminSDHolder / SDProp** stamping a read ACE onto a Tier-0 computer
  ([[ad-persistence]]).

## Detection

- **4662** on a computer object's `ms-MCS-ADMPassword` attribute (the read).
- A **4624 Type 3/10** to a computer as the LAPS admin account from an
  unusual source.
- BloodHound `HasLAPS` edges on Tier-0 computers that a low-priv principal
  holds (config audit).

## Mitigations

- **Least-priv LAPS read** — only Tier-0 / the intended group can read
  `ms-MCS-ADMPassword`; audit who can.
- **Unique + rotating** passwords (LAPS defaults) — keep the rotation tight.
- **BloodHound sweeps** — find unexpected `HasLAPS` edges to Tier-0 hosts.
- [[ad-tiering-and-hardening]] — the overarching local-admin model.

## Links

- [[sam-database]] — the local admin hash it backs
- [[acl-abuse]] — GenericAll/Read over the computer object is the common way to read it
- [[ad-persistence]] — AdminSDHolder stamping a LAPS-read ACE
- [[ad-tiering-and-hardening]] — the local-admin hardening baseline
- [[bloodhound]] — the `HasLAPS` edge that visualizes this
- [[path-laps-to-domain-admin]] — the end-to-end chain

## References

- [Microsoft: LAPS documentation](https://learn.microsoft.com/en-us/azure/azure-ad/devices-lapstool-download)
- [PowerView Get-DomainComputerLAPSPassword](https://github.com/PowerSploit/PowerView)
- [BloodHound edges (HasLAPS)](https://bloodhound.specterops.io/resources/edges/)
