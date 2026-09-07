---
title: "BloodHound Collection OPSEC (quiet SharpHound tradecraft)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [red-team, active-directory, bloodhound, opsec, enumeration]
---

# BloodHound Collection OPSEC

[[bloodhound]] is the map for the whole [[redteam-ad-methodology]] flow, but
its collectors (SharpHound / bloodhound-python) are also one of the loudest
things you can do in a domain. This page is about collecting the graph
**quietly** — the analysis in BloodHound itself is offline and silent; the
noise is entirely in collection.

## Where the noise comes from

- **LDAP queries** to the DC — the object/ACL/trust data. Large or unfiltered
  queries are the tell; verbose Directory Services logging records them.
- **Session enumeration** — the `Session`/`LoggedOn` methods sweep hosts for
  who's logged in (SMB / remote-registry / net-session). This is host-wide
  4624/network-session noise across the estate and the loudest collection
  method by far.
- **Computer connectivity** — the collector touches many hosts to resolve
  sessions/local-admins, which lights up network telemetry.

## Quieter collection

- **`--collectionmethods DCOnly`** — pulls objects, ACLs, trusts, GPOs, and
  SPN/cert data from the **DC via LDAP only**, with **no host touch and no
  session sweep**. This alone gives most attack-path edges
  ([[acl-abuse]], [[kerberos-delegation]], [[ad-cs-esc-attacks]]) and is the
  default quiet baseline.
- **Add session data selectively** — only run `Session`/`LoggedOn` against a
  small, targeted host set when you actually need a session edge to a
  specific principal.
- **`--stealth`** — touches only hosts the current user would normally reach,
  reducing the connection fan-out.
- **Throttle / jitter** — `--throttle` and `--jitter` spread LDAP requests so
  they don't arrive as one burst.
- **Server-side filtering** — scope the query (`--ldapfilter`, a single OU/
  domain) instead of pulling the whole forest.

```bash
# bloodhound-python (Linux, over a tunnel) — DC-only, no host touch
bloodhound-python -u user -p 'Pass' -d corp.local -ns 10.0.0.10 -c DCOnly

# SharpHound (Windows) — DC-only with jitter
SharpHound.exe -c DCOnly --throttle 1000 --jitter 30
```

## Operating the data

- Collect once, quietly; iterate on the graph **offline** rather than
  re-collecting. Re-runs multiply the footprint.
- Run collection from your foothold context through the tunnel
  ([[c2-and-pivoting-ad]]); import the ZIP into a BloodHound CE instance on
  your operator host.
- Prefer LDAP-derived edges ([[acl-abuse]], SPNs, delegation, cert templates)
  over session-derived ones when planning a path — they cost nothing extra
  beyond the DCOnly pull.

## See also

- [[bloodhound]] — the tool and edge model
- [[redteam-ad-methodology]] — where collection sits in the flow
- [[opsec-ad-tradecraft]] — the broader noise/blend picture
- [[situational-awareness]] — the on-host recon that complements the graph
- [[ldap]] — the protocol most collection rides on
