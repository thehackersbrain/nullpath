---
title: DASync
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, dcsync, active-directory, python, replication]
---

# DASync

**DASync** (by vlad) is a Python **DCSync** implementation — an alternative to
Impacket's `secretsdump.py` for abusing MS-DRSR replication rights to dump
account **password hashes and AES keys**. It connects to a DC's DRSUAPI,
performs the replication, and stores the results in a **local database**
rather than just printing — useful for iterative work (query the dump, re-dump
a specific user, diff over time). It's the dedicated DCSync tool; see
[[dcsync]] for the technique and [[impacket]] for the `secretsdump.py`
counterpart.

## How it works

1. Authenticate to a DC with an account holding
   **`GetChanges`/`GetChangesAll`** (the DCSync right — confirm via
   BloodHound / `Get-ADReplicationPartners`).
2. Drive **MS-DRSR** (`IDsrApi`) replication for the target user(s) — DASync
   walks the directory partition and pulls each object's
   `uSNCreated`/secrets.
3. Store the **NT hashes + AES keys** (RC4/AES128/AES256) in a local SQLite
   DB — queryable offline.

## Common invocations

```bash
# Full DCSync to a local DB (as a DCSync-capable account)
python dasync.py -u <dcsync-user> -p <pw> -dc dc01.corp.local -d corp.local

# Targeted: just krbtgt (the Golden Ticket secret)
python dasync.py -u <dcsync-user> -p <pw> -dc dc01.corp.local -d corp.local --user krbtgt

# Kerberos (ticket) auth
python dasync.py -u <dcsync-user> -k -dc dc01.corp.local -d corp.local
```

## Why use it over secretsdump.py

- **Local DB** — the dump is queryable/iterative (re-pull one user, search
  history) instead of one-shot stdout.
- **Lighter footprint** in some setups — a targeted DRSUAPI session vs a full
  `secretsdump`.
- Same end goal: NT hashes + AES keys for any account (incl. `krbtgt`).

## Detection

- **4662** on the domain object (GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`,
  props `GetChanges`/`GetChangesAll`) — the canonical DCSync tell
  ([[dcsync]]).
- **4662 on specific user objects** — a targeted user dump.
- **Unusual DRSUAPI source** — replication from a non-DC host.

## Mitigations

- **Restrict the DCSync right** (`GetChanges`/`GetChangesAll`) to DCs and the
  minimal set — the primary control ([[dcsync]]).
- **Alert on 4662** with the DCSync GUID from non-DC sources.
- See [[dcsync]] / [[krbtgt]] for the broader controls.

## Links

- [[dcsync]] — the technique DASync implements
- [[impacket]] — the `secretsdump.py` counterpart
- [[krbtgt]] — the `-just-dc-user krbtgt` target (Golden Ticket)
- [[bloodhound]] — how you confirm the DCSync right first
- [[golden-silver-tickets]] — what a `krbtgt` dump enables

## References

- [DASync (GitHub)](https://github.com/vladmaldita/dasync)
- [ired.team: DCSync](https://www.ired.team/active-directory-kerberos-abuse/dc-sync)
- [dcsync (this wiki)](dcsync)
