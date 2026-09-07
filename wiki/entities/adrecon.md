---
title: ADRecon (.NET Active Directory reconnaissance)
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, active-directory, enumeration, recon, dotnet]
---

# ADRecon (.NET Active Directory reconnaissance)

**ADRecon** is a **.NET** Active Directory **reconnaissance** tool: it queries
the domain over **LDAP/SAMR/DS-REPLO** and dumps a broad, structured view of
the directory — users, groups, ACLs, GPOs, trusts, computers, and the
**replication (DCSync) rights** — in a form you can grep or load into a graph.
It's the "wide-net first-pass" recon that complements
**[[bloodhound]]** (relationship/graph-focused) and **[[powerview]]**
(Per-obj PowerShell). Think of it as a fast, single-binary "what's in this
domain + who can do what" snapshot.

## What it does

- **Enumerates** the core AD objects — users, groups, computers, OUs, GPOs,
  domain/forest **trusts** — over **LDAP**.
- **Pulls ACLs / privileges** — who has what rights on what (the
  `GenericAll`/`WriteDacl`/`GenericWrite`/`DCSync` surface that
  [[acl-abuse]] and [[path-genericwrite-to-dcsync]] exploit).
- **Checks replication rights** — which accounts can **DCSync**
  (`Get-Changes`/`Get-ChangesAll`), i.e. who can pull `krbtgt`. See [[dcsync]].
- **Trusts / forest** — the cross-forest surface in [[ad-trust-attacks]].
- **Outputs** structured recon (CSV/JSON/graph) for triage.

## Typical invocations

```bash
# Authenticate (Kerberos or NTLM) and run the recon
ADRecon.exe -u <user> -p '<pass>' -d corp.local
# (Kerberos / hash variants depending on build)
# Output: users/groups/ACLs/GPOs/trusts/replication-rights -> triage for
#   DCSync-able accounts, writable ACLs, delegation, trusts
```
**Verify:** a recon dump that names the **DCSync-able accounts**, the
**writable ACLs**, the **delegation** holders, and the **trusts** — the input
to picking an attack path. See [[bloodhound]] for the graph counterpart.

## Why it's here

- **Wide-net recon** — before you pick a path, you need the *map*: who holds
  DCSync, who holds delegation, what's writable, what trusts exist. ADRecon
  is one of the tools that produces that map fast.
- **.NET single binary** — runs on Windows without a Python runtime; a
  different footprint than certipy/impacket (Python) or Rubeus.
- **Complements, not replaces, [[bloodhound]]** — BloodHound is the
  relationship/attack-path graph; ADRecon is the broad object+rights dump. Use
  both: ADRecon for "what exists / who can what," BloodHound for "what's the
  shortest path to DA."

## Detection / notes

- **LDAP reads** — ADRecon is *read-only* (no writes), so its tell is a
  **burst of LDAP queries** (4661/4662/5136 in the DC) from a single host,
  often pulling a large number of objects/ACLs at once.
- A **SAMR/DS-REPLO** query for replication rights is a specific tell (a host
  enumerating who can DCSync).
- **Lower-noise than exploitation** — recon is usually the *quiet* phase; the
  high-fidelity alerts come when the recon output is *acted on* (the DCSync,
  the ACL write).

## Links

- [[bloodhound]] — the graph/attack-path counterpart
- [[powerview]] — the per-object PowerShell recon
- [[ldap]] — the protocol ADRecon reads over
- [[acl-abuse]] — the writable-ACL surface it surfaces
- [[dcsync]] — the replication rights it checks
- [[ad-trust-attacks]] — the trusts it enumerates
- [[ad-tier-model]] — the recon output mapped to tiers
- [[kerberos-authentication]] — the auth ADRecon uses to query
