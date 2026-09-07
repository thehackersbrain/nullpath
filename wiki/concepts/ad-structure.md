---
title: "Active Directory Structure (objects, OUs, domains, trees, forests, sites)"
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [active-directory, structure, architecture, forest, domain, site]
---

# Active Directory Structure (objects, OUs, domains, trees, forests, sites)

The AD data model and the **hierarchy it's organized into**. Most attack
pages in this wiki assume you know how a domain sits inside a tree inside a
forest, where an object's **Distinguished Name (DN)** comes from, and what a
**site** is. This is the foundational glossary. The *relationships and
rights* between objects (ACLs, trusts, delegation) are covered by
[[acl-abuse]], [[ad-trust-attacks]], and [[kerberos-delegation-abuse]]; this
page is the *static structure* those relationships hang off.

## The object model

AD is a **directory of objects** (LDAP — see [[ldap]]). Every object is an
instance of an **object class** defined by the **schema** (the
[[domain-controller|Schema Master]] FSMO role guards the schema). Each object
has:
- A set of **attributes** (e.g. `sAMAccountName`, `userPrincipalName`,
  `objectSID`, `member`, `msDS-KeyCredentialLink` ([[shadow-credentials]]),
  `msDS-AllowedToActOnBehalfOfOtherIdentity`
  ([[resource-based-constrained-delegation]]), `sidHistory`
  ([[sid-history]])).
- A **Distinguished Name (DN)** — its position in the tree, e.g.
  `CN=Bob,OU=Users,DC=corp,DC=local`.
- An **objectSID** — a security identifier (`S-1-5-21-<domain>-<RID>`).
- **ACLs** — which principals can read/write which attributes (the surface
  [[acl-abuse]] exploits: `GenericAll`/`WriteDacl`/`WriteOwner`/
  `GenericWrite`).

Common object classes: **user**, **group** (security/distribution,
global/universal/local), **computer** (machine account — see
[[service-account]]), **OU**, **contact**, **GPO** ([[gpo-abuse]]), **trust**.

## The hierarchy (small → large)

```
Object (user/computer/GPO/...)
  └── OU (Organizational Unit)          — container, GPO scoping, admin delegation
        └── Domain (corp.local)         — a security boundary; Kerberos realm + SID namespace
              └── Tree                  — a contiguous set of domains in a single DNS namespace
                    └── Forest          — the top boundary; shares a schema + global catalog; the trust root
                          └── (Site)    — a *physical/network* grouping (not a security boundary)
```

- **OU (Organizational Unit)** — a *container* for grouping objects. OUs are
  where you **scope GPOs** and **delegate admin rights** (so a writable OU or
  GPO-linked OU is a [[gpo-abuse]] / [[acl-abuse]] target). An OU is *not* a
  security boundary — it's an administrative one.
- **Domain** — the core **security boundary**. It has:
  - its own **SID namespace** (the `S-1-5-21-<domain>` prefix on every object
    SID in it),
  - its own **Kerberos realm** (the domain name is the Kerberos realm; the
    `krbtgt` key is *per-domain*, [[krbtgt]]),
  - its own set of **[[domain-controller|Domain Controllers]]** and
    **FSMO roles**.
  - Domains **trust** each other (see [[ad-trust-attacks]]). A trust is what
    lets one domain's Kerberos realm resolve/accept another's — and the
    **SID-history / trust-pivot** attacks ([[sid-history]],
    [[path-cross-forest-trust-pivot]]) live on those trust edges.
- **Tree** — one or more domains that share a **contiguous DNS namespace**
  (e.g. `corp.local` + `child.corp.local`). Domains in a tree are in a
  **parent/child** trust relationship by default.
- **Forest** — the **top-level boundary**. A forest is one or more trees that:
  - share a single **schema** and a single **Global Catalog**,
  - are connected by **inter-forest trusts** (the trust edges exploited in
    [[ad-trust-attacks]] and the **Enterprise Admin** scope),
  - have **Enterprise Admins** (a forest-wide group, above Domain Admins).
  - "Getting to Enterprise Admin" = winning the whole forest
    ([[path-sid-history-to-enterprise-admin]]).
- **Site** — a **physical/network-location** grouping (by subnet), *not* a
  security boundary. Sites control **replication traffic** (intra-site vs
  inter-site replication) and **which DC a client authenticates to**
  (site-aware). Attack-relevant: an attacker who controls a **site/subnet**
  can position for **relay/coercion** ([[mitm6-ipv6-relay]], [[wpad]],
  [[ntlm-relay-coercion]]) and influence DC selection.

## Why the structure matters for attacks

- **The SID namespace is per-domain** — that's why a **SID history** pivot
  needs a *trust* to cross domains/forests ([[sid-history]],
  [[ad-trust-attacks]]).
- **`krbtgt` is per-domain** — a Golden Ticket in domain A doesn't work in
  domain B; you need a **forest-trust pivot** or a **cross-realm** TGT
  ([[golden-silver-tickets]], [[ad-trust-attacks]]).
- **The Enterprise Admin is forest-scoped** — the top of the mountain
  ([[path-sid-history-to-enterprise-admin]]).
- **GPOs and delegation are OU-scoped** — so the *writable OU / GPO* is the
  lateral surface ([[gpo-abuse]], [[acl-abuse]]).
- **Sites are the network-position surface** — relay/coercion depends on
  being in the right *site/subnet* ([[mitm6-ipv6-relay]]).

## Enumerating the structure

```powershell
# PowerShell (PowerView / AD module)
Get-ADForest                      # forest: trees, domains, trust, Enterprise Admins
Get-ADDomain                      # domain: SID, DCs, FSMO holders
Get-ADOrganizationalUnit -Filter * -Properties distinguishedname
Get-ADTrust -Domain corp.local    # trust edges (one-way/two-way, SID-filtering)
Get-ADObject -LDAPFilter "*" -SearchBase "DC=corp,DC=local"   # raw LDAP walk
```
Or over raw **LDAP** ([[ldap]]) / **[[adrecon]]** / **[[bloodhound]]** for the
full object+rights+trust map. See [[ldap]] for the wire protocol.

## Links

- [[ldap]] — the protocol the directory is served over
- [[domain-controller]] — the servers that host a domain + FSMO roles
- [[ad-trust-attacks]] — the trust edges between domains/forests
- [[sid-history]] — the cross-forest SID pivot (needs a trust)
- [[acl-abuse]] — the object-level rights the structure carries
- [[gpo-abuse]] — OU/GPO-scoped policy abuse
- [[ad-tier-model]] — the trust model mapped onto this hierarchy
- [[krbtgt]] — the per-domain key that makes a domain a Kerberos realm
- [[bloodhound]], [[adrecon]], [[powerview]] — the tools that map this
