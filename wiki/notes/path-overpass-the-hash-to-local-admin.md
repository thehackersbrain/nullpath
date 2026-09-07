---
title: "Attack Path: Overpass the Hash → local admin on a target"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, overpass-the-hash, local-admin, lateral-movement]
---

# Attack Path: Overpass the Hash → local admin on a target

The **[[overpass-the-hash]]** play: you hold a user's **NT hash** (not their
password, not `krbtgt`), and you want a **Kerberos** foothold as a **local
admin** on a specific target. Overpass turns the NT hash into a **real,
KDC-minted TGT** (an RC4 AS-REQ with the hash as the key), then you request a
TGS for the target and log on. This is the "hash → local admin" chain — it
needs **no `krbtgt`** (unlike a [[golden-silver-tickets|Golden Ticket]]) and
**no NTLM acceptance on the target** (unlike plain [[pass-the-hash-and-ticket|PtH]]).
See [[overpass-the-hash]] for the mechanics and the PtH/PtK/Overpass/Golden
comparison table.

## Why overpass here (vs the alternatives)

- **vs plain PtH (NTLM)** — the target must accept NTLM; overpass gives a
  **Kerberos** logon (works where NTLM is restricted), and the ticket is
  **real** (KDC-minted, normal lifetime) — no forged-lifetime tell.
- **vs Golden Ticket** — overpass needs only the **user's NT hash**, not
  `krbtgt` (so no [[dcsync]] right / DC access required to *forge*); you get
  a TGT for *that user* (not any user).
- **vs Pass-the-Key** — PtK reuses an already-captured AES/RC4 *key*; overpass
  is the path when all you have is the **NT hash** (the most common dump
  output).

## Chain

```
You (a foothold: an LSASS/SAM dump, or a DCSync right for one user)
  --capture the NT hash of a user who is local-admin on <target>-->
  --Overpass (Rubeus asktgt /rc4 <nthash>)--> a REAL TGT for that user (KDC-minted)
  --TGS for cifs/<target> (or WSMAN/WinRM)--> Kerberos logon
  --> local admin on <target>
  --> (privesc / pivot / next box)
```

## Prerequisites / what signals this path exists

- **The NT hash of a user who is a local admin on the target** — sources:
  - a [[lsass]] dump on a host where that admin has logged on (their hash is
    in LSASS), or a [[sam-database]] read of the target (the local admin's
    hash, if it's a local account), or
  - a [[dcsync]] `-just-dc-user <user>` for a domain account that's a local
    admin on the target (the common case: a domain service/admin account).
- **The target accepts Kerberos** (it's a domain-joined Windows host — it
  will; the *cifs* SPN is `cifs/<host>`).

Confirm the local-admin relationship first (BloodHound `localAdmin` edges, or
`Get-DomainComputer -Unconstrained`/LAPS — see [[laps]] if the local admin is
LAPS-rotated, in which case you need the *current* LAPS password, not a stale
hash).

## Step 1 — Capture the NT hash

```bash
# If you have a DCSync right — pull just that user's hash
secretsdump.py -k -no-pass corp.local/<dcsync-user>@dc01 -just-dc-user <user>
# output:  rc4_hmac_nt : <nt-hash>
# or a local LSASS/SAM dump on a host they used (see [[lsass]])
```
**Verify:** you have the `rc4_hmac_nt` value for a user who is a **local
admin on the target** (confirm the `localAdmin` edge before overpassing —
overpassing a user who isn't local-admin on the target gets you a normal user
there, not admin).

## Step 2 — Overpass (NT hash → real TGT)

```powershell
Rubeus.exe asktgt /user:<user> /domain:corp.local /rc4:<nt-hash> /ptt
Rubeus.exe triage        # a fresh, KDC-minted TGT for <user>, etype rc4
```
**Verify:** `Rubeus.exe triage` shows a **TGT for `<user>`** with a *normal*
lifetime (a few hours — the tell that it's real, unlike a years-long Golden).

### Failure modes & fallbacks
- **4768 rejected / KDC error** — wrong hash/user/domain, or the account is
  disabled/locked; re-check the hash source and account state.
- **Domain forces AES256 for TGTs** — an RC4 AS-REQ may be rejected on a
  strict domain; in that case overpass is out — fall back to **PtH (NTLM)**
  (if the target accepts NTLM) or capture the **AES key** ([[pass-the-key]]).
- **The user isn't local-admin on the target** — you'll land as a normal user;
  you still have a foothold (privesc locally), but it's not the "local admin"
  end-state.

## Step 3 — Log on to the target (local admin)

```bash
# Kerberos to the target's cifs/WSMAN SPN with the injected TGT
psexec.py   -k -no-pass corp.local/<user>@<target>
wmiexec.py  -k -no-pass corp.local/<user>@<target>
winrm.py    -k -no-pass corp.local/<user>@<target>
# (or RDP as <user> — see [[remote-execution]] for the transport choice)
whoami /all   # local admin on <target>
```
**Verify:** a working session on the target as the local admin. From here it's
local privesc / lateral / the next hop (see [[remote-execution]],
[[ad-tier-model]] for where a Tier-1 box takes you).

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (hash capture) | Sysmon 10 (LSASS) / 4662 DCSync / SAM read | the usual capture tells |
| 2 (overpass) | **4768 TGT request with RC4** for the user | an RC4 TGT (a Kerberos-AES domain normally doesn't see RC4 TGTs) |
| 3 (logon) | 4769 TGS for `cifs/<target>` + **4624 type 3/10** for the user on the target | a normal Kerberos logon (no NTLM, no forgery tells) |

The **4768 RC4** at step 2 is the overpass tell — a real TGT, but minted with
the weak RC4 enctype.

## Cleanup notes
- The **TGT is memory-only** (dies at session end / ticket expiry ~10h) — no
  AD object to remove.
- The **overpass 4768-RC4** is the main on-DC trail; the target-side logon
  (step 3) looks like an ordinary Kerberos logon (no NTLM, no forgery).
- If the local-admin hash was from **LAPS**, it's **single-machine** — a
  rotation (or your own LAPS read) orphans it; see [[laps]].
- Nothing persistent is planted by overpass itself — pair with
  [[remote-execution]] persistence if you need to stay.

## Related
- [[overpass-the-hash]] — the primitive (step 2) + the PtH/PtK/Overpass/Golden table
- [[pass-the-hash-and-ticket]] — the NTLM (PtH) and ticket (PtT) siblings
- [[pass-the-key]] — the AES/RC4-key variant (when you have the key, not just the hash)
- [[golden-silver-tickets]] — the krbtgt-required forgery contrast
- [[dcsync]], [[lsass]], [[sam-database]] — the hash sources (step 1)
- [[laps]] — if the local admin is LAPS-rotated (the hash must be current)
- [[remote-execution]] — the step-3 transports
- [[path-pass-the-hash-to-domain-admin]] — the PtH→Tier-0→DA sibling chain
