---
title: "RustHound / RustHound-CE — Rust BloodHound collector"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, rust, active-directory, bloodhound, enumeration, collector]
---

# RustHound / RustHound-CE

**RustHound** (by g0h4n / OPENCYBER) is a **BloodHound collector written in
Rust** — a fast, dependency-free alternative to SharpHound (C#) and
BloodHound.py (Python). It walks the domain over LDAP/LDAPS, builds the same
principals/objects/edges graph, and outputs the ingestible ZIP. It's the
collector to reach for when you want **a single static binary with no runtime**
— no .NET, no Python interpreter — that runs the same on Windows, Linux, and
macOS, on-host *or* from the Linux operator host over a tunnel. Feeds
[[bloodhound]]; the collection tradecraft is [[bloodhound-opsec]].

## RustHound vs RustHound-CE (pick the right one)

BloodHound split its data model at the **Community Edition (CE)** rewrite, and
the collectors split with it — **match the collector to your BloodHound
version or the ingest silently fails**:

- **RustHound** (`OPENCYBER-FR/RustHound`) — original; emits **legacy
  BloodHound (v4.x)** JSON.
- **RustHound-CE** (`g0h4n/RustHound-CE`) — emits **BloodHound CE** format
  (the current BloodHound / BHCE). This is the one you want for a modern
  BloodHound CE / `bloodhound-ce` deployment.

Same tool family, different output schema. `nxc ldap --bloodhound` and
BloodHound.py also come in legacy vs CE flavors — keep the whole pipeline on
one side of the split.

## Why it's worth carrying

- **Single static binary, zero dependencies.** No .NET assembly to load, no
  Python to stage. On a Windows foothold this **sidesteps the AMSI / .NET
  assembly-load telemetry** that SharpHound (a C# assembly) trips —
  see [[amsi]] / [[etw]] / [[defense-evasion-ad]]. Just a binary that makes
  LDAP queries.
- **Fast.** Concurrent LDAP; large domains collect quickly.
- **Cross-platform & tunnel-friendly.** Runs cleanly from the Linux operator
  host through the pivot ([[pivoting-and-tunneling]]), so tooling stays off the
  endpoint entirely.
- **AD CS aware** — collects certificate-template/CA data for the ESC surface
  ([[ad-cs-esc-attacks]]) in versions that support it.

## Usage

```bash
# RustHound-CE, LDAP simple bind (user/pass), zip the output for ingest
rusthound-ce -d corp.local -u user@corp.local -p 'Password1' -i 10.0.0.10 -z

# By DC FQDN (needed for LDAPS / Kerberos SPN binding) instead of IP
rusthound-ce -d corp.local -u user@corp.local -p 'Password1' -f dc01.corp.local -z

# Kerberos ticket auth (ccache in $KRB5CCNAME) — pairs with PtT
KRB5CCNAME=user.ccache rusthound-ce -d corp.local -f dc01.corp.local -k -z

# Write to a specific output dir
rusthound-ce -d corp.local -u user@corp.local -p 'Password1' -i 10.0.0.10 -z -o ./loot/
```

Auth surface is password (LDAP bind) or Kerberos (`-k` + ccache); check
`rusthound-ce --help` for the exact flags your build ships (hash auth, LDAPS,
FQDN resolver, ADCS module) — like the rest of this toolchain, **pin the
version** and confirm flags before the engagement. Ingest the resulting ZIP
into BloodHound and query shortest paths as usual ([[bloodhound]]).

## OPSEC

- **The collector is quiet; the collection is not.** RustHound avoids the
  *on-host* .NET/AMSI footprint of SharpHound, but the **LDAP query volume is
  the same** — a full collection is still a broad directory sweep the DC sees.
  All of [[bloodhound-opsec]] applies: prefer a scoped/lighter pass first,
  add jitter where the collector supports it, and don't re-collect
  needlessly.
- **No on-disk .NET / interpreter** means less for host EDR to hook, but LDAP
  telemetry (1644 / directory-service query auditing) on the DC is unchanged.
- Running it **over the tunnel from Linux** ([[pivoting-and-tunneling]]) keeps
  even the binary off the endpoint — the DC just sees LDAP from an internal
  host.

## Links

- [[bloodhound]] — the graph this feeds (SharpHound / BloodHound.py are the
  siblings)
- [[bloodhound-opsec]] — quiet collection tradecraft (collector-agnostic)
- [[ad-enumeration]] — where collection sits in the remote enum flow
- [[pivoting-and-tunneling]] — running it over the operator tunnel
- [[amsi]] / [[etw]] / [[defense-evasion-ad]] — the on-host telemetry it avoids
- [[netexec]] — `nxc ldap --bloodhound` is the other no-SharpHound collector
- [[ad-cs-esc-attacks]] — the AD CS data it can also collect

## References

- [RustHound-CE (GitHub)](https://github.com/g0h4n/RustHound-CE)
- [RustHound (legacy, GitHub)](https://github.com/OPENCYBER-FR/RustHound)
