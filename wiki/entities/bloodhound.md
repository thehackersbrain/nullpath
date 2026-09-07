---
title: BloodHound
type: entity
created: 2026-09-06
updated: 2026-09-07
tags: [tool, active-directory, graph, enumeration, specterops]
---

# BloodHound

**BloodHound** (SpecterOps; original by Rob King) is a **graph-based AD
attack-path analyzer**. It ingests the domain (via a collector — SharpHound,
BloodHound.py, or [[rusthound]] — see that page for choosing one), builds a Neo4j graph of principals, objects, and
**edges** (the abuse relationships), and lets you query *shortest paths* from
your current context to Domain/Enterprise Admins. It's how you turn raw
ACL/group data into an exploitable plan — the backbone of
[[acl-abuse]]-driven privesc and every attack-path note in this wiki.

## Edges (what it models)

- **Object control** — `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`,
  `WriteProperty` ([[acl-abuse]]).
- **Membership / admin** — `MemberOf`, `AdminTo` (local admin on a host),
  `HasSession`.
- **Delegation** — `AllowedToAct` (RBCD), `HasSIDHistory`, `CanPSRemote`,
  `GFPT` (Generic... ), `Dcsync` (`GetChanges`/`GetChangesAll` on the domain
  object → [[dcsync]]).
- **LAPS** — `HasLAPS` (can read the computer's LAPS password →
  [[laps]]).
- **Computer / service** — `CanRDP`, `GoldenTicket`, `ABACs`.

These edges are exactly the abusable relationships described across
[[acl-abuse]], [[kerberos-delegation-abuse]], [[laps]], [[dcsync]],
[[sid-history]], and the AD CS [[ad-cs-esc-attacks]].

## Workflow

```bash
# 1. Collect (from a host with domain read access). Pick a collector:
SharpHound.exe -c All,GPOLinked,LocalAdmin                       # C# (Windows)
python3 bloodhound.py -d corp.local -u user -p pass -ns -dc <dc> -c All   # Python
rusthound-ce -d corp.local -u user@corp.local -p pass -i <dc> -z          # Rust, single static binary ([[rusthound]])

# 2. Ingest into Neo4j (BloodHound ingests the .zip)
# 3. Query — the canonical one:
#    "shortest path from <you> to Domain Admins / Enterprise Admins"
#    "shortest path to an object with GetChangesAll (DCSync)"
#    "shortest path to a computer with HasLAPS"
```

## Cypher examples (the queries that matter)

```cypher
// Shortest path from me to Domain Admins
MATCH (a:User {name:"attacker"}), (b:Group {name:"Domain Admins"})
MATCH p = shortestPath((a)-[*1..15]-(b))
RETURN p;

// Who can DCSync (GetChangesAll on the domain object)
MATCH (a)-[:AllAttributes|GetChangesAll]->(b:Domain)
RETURN a, b;

// Where can I read LAPS passwords?
MATCH (a:User {name:"attacker"})-[:HasLAPS*1..5]->(c:Computer)
RETURN a, c;
```

## Why it's the planner

- **Paths, not ACLs** — a single `GenericWrite` looks unremarkable; the *chain*
  `you → GenericWrite → user → member of → group → GetChangesAll → domain`
  is the exploit. BloodHound surfaces the chain.
- **Fast triage** — answer "what's my shortest route to DA?" in seconds
  instead of hours of `Get-DomainObjectAcl`.
- **Repeatable** — re-run after changes to see if a path opened/closed.

## Collection OPSEC (running it quietly)

The analysis is offline and silent — **all** the noise is in collection:

- **`-c DCOnly`** is the quiet baseline: objects, ACLs, trusts, GPOs and
  SPN/cert data straight from the DC over LDAP, with **no host touch and no
  session sweep**. It yields most attack-path edges ([[acl-abuse]],
  [[kerberos-delegation]], [[ad-cs-esc-attacks]]) on its own.
- **Avoid the session sweep** (`Session`/`LoggedOn`) unless you specifically
  need a session edge — it's estate-wide 4624/net-session noise and the
  loudest method by far. Run it against a small, targeted host set only.
- **`--stealth`**, **`--throttle`** and **`--jitter`** spread and shrink the
  LDAP/connection footprint; scope with `--ldapfilter` instead of pulling the
  whole forest.
- **Collect once, iterate offline.** Re-running multiplies the footprint;
  refine queries on the graph rather than re-collecting.
- **Run it over the tunnel** — `bloodhound-python -c DCOnly` from a Linux
  operator host keeps the collector off the endpoint entirely.

## Detection / limitations

- The **collection** is itself a loud enumeration burst (lots of LDAP reads);
  run it from a trusted host and consider the 4662/5136 noise.
- It models what you *can* see; hidden (ABAC) or dynamic paths may be missing.
- Stale data if you don't re-collect after the domain changes.

## Links

- [[acl-abuse]] — the object-control edges it visualizes
- [[dcsync]], [[laps]], [[sid-history]], [[kerberos-delegation-abuse]] — the DCSync/HasLAPS/SIDHistory/AllowedToAct edges
- [[ad-cs-esc-attacks]] — cert template edges (via the CS collector)
- [[netexec]] — the companion for exec/scanning (with native BH2 ingest)
- [[ad-tiering-and-hardening]] — the structural fix for the paths it finds
- [[adrecon]] — the broad object+rights recon dump (wide-net complement)

## References

- [BloodHound (SpecterOps)](https://www.bloodhound.readthedocs.io/)
- [[rusthound]] — the Rust collector (single static binary; no .NET/Python)
- [SharpHound / BloodHound.py](https://github.com/SpecterOps/BloodHound)
- [SpecterOps: BloodHound documentation](https://bloodhound.specterops.io/)
