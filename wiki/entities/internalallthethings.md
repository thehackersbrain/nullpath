---
title: InternalAllTheThings (swisskyrepo)
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [organization, reference, active-directory, offensive]
---

# InternalAllTheThings (swisskyrepo)

**InternalAllTheThings** (swisskyrepo.github.io, by Swisskyrepo / Swissky) is
a comprehensive, actively maintained **AD / internal offensive security
reference** — the other primary cite across this wiki (with [[ired-team]]).
It's organized as a "pentest notebook" of techniques with concrete commands,
and is the go-to for the hands-on "how do I actually run this" layer.

## Coverage referenced in this wiki

- **AD CS ESC attacks** — [[ad-cs-esc-attacks]] (the page's primary reference).
- **Kerberos / delegation** — [[kerberos-delegation-abuse]],
  [[s4u2self-s4u2proxy]], [[kerberoasting]], [[as-rep-roasting]].
- **NTLM relay / mitm6 / RBCD** — [[mitm6-ipv6-relay]],
  [[rbcd-via-ntlm-relay]], [[ntlm-relay-coercion]].
- **SCCM / WDS** — [[sccm-abuse]], [[wds-mdt-discovery]].
- **General AD privesc / lateral** — [[acl-abuse]], [[laps]], [[dcsync]].

## Why it matters for this wiki

- It is the **hands-on technique reference** — the "step-by-step with real
  commands" layer that complements ired.team's attack+detection framing.
- Its SCCM/WDS coverage is the source for the
  [[sccm-abuse]] / [[wds-mdt-discovery]] pages.

## Links

- [[ad-cs-esc-attacks]] — the primary AD CS reference
- [[sccm-abuse]], [[wds-mdt-discovery]] — the SCCM/WDS source
- [[mitm6-ipv6-relay]] — the mitm6/RBCD reference
- [[ired-team]] — the companion reference

## References

- [InternalAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/)
- [swisskyrepo (GitHub)](https://github.com/swisskyrepo)
