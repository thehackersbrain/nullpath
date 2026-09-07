---
title: "Attack Path: Shadow Credentials (GenericWrite → msDS-KeyCredentialLink) → PKINIT → UnPAC the NT hash → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, shadow-credentials, pkinit, privilege-escalation]
---

# Attack Path: Shadow Credentials (GenericWrite → PKINIT → UnPAC the hash) → Domain Admin

The **[[shadow-credentials]]** kill-chain: when you hold **GenericWrite** on a
privileged account (a DA, or even `krbtgt`), plant an attacker-controlled
**X.509 certificate** on that account's `msDS-KeyCredentialLink` attribute,
**authenticate to the DC with that cert via PKINIT**, and **recover the
account's NT hash** directly from the TGT PAC ("UnPAC the hash"). No password,
no DCSync right needed — the GenericWrite edge *is* the privesc. See
[[shadow-credentials]] for the mechanics and [[pkinit-unpac-the-hash]] for the
PKINIT → hash-recovery step. The tool is **[[whisker]]**.

## Chain

```
You (GenericWrite on target account A)
  --whisker plant--> write msDS-KeyCredentialLink (your cert) on A
  --Rubeus asktgt /certificate:--> PKINIT auth as A -> TGT for A
  --UnPAC the hash--> A's NT hash (from the TGT PAC)
  --Golden Ticket / DCSync--> Domain Admin
```

## Prerequisites / what signals this path exists

- **GenericWrite** (or WriteDacl → then GenericWrite) on the **target account
  `A`** — the account you want to take over. Confirm with BloodHound /
  `Get-DomainObjectAcl -Identity A`. See [[acl-abuse]].
- `A` is **worth taking over** — a DA, a Domain Admins member, or an account
  with a high-value edge (DCSync, AdminTo, etc.). Taking over a low-priv
  account via shadow creds is usually not worth the artifact.
- The domain **allows key trust** (PKINIT) — the CA must issue certs for
  key-cred links (most domains do by default). See [[shadow-credentials]].

```powershell
# Confirm the GenericWrite edge
Get-DomainObjectAcl -Identity A -Properties WriteDacl,WriteProperty,GenericWrite
# BloodHound: you --GenericWrite--> A
```

## Step 1 — Plant the shadow credential

```bash
whisker plant -t A -u you -d corp.local -ip <dc-ip>
```
**Verify:** `whisker list` shows your cert now on `A`'s
`msDS-KeyCredentialLink`. This writes the attribute on `A` — the single
durable artifact of the whole chain. See [[shadow-credentials]].

### Failure modes & fallbacks
- **`A` is locked / the CA is down** — the plant writes to AD; the PKINIT
  (step 2) is what needs the CA. Plant can succeed even if you can't PKINIT
  yet.
- **No GenericWrite, only WriteDacl** — first set GenericWrite via
  [[acl-abuse]], then plant. See [[path-genericwrite-to-dcsync]] for the
  analogous WriteDacl→GenericWrite pivot.

## Step 2 — Authenticate as `A` via PKINIT (UnPAC the hash)

```powershell
Rubeus.exe asktgt /certificate:<your-cert> /domain:corp.local /dc:<dc> /ptt
# -> TGT for A. The PAC in that TGT contains A's NT hash.
Rubeus.exe ptt /ticket:<A-TGT>    # (if not -ptt'd already)
```
The **TGT's PAC** carries the account's NT hash — reading it back out is
"UnPAC the hash." See [[pkinit-unpac-the-hash]] for the mechanism.
**Verify:** you hold a TGT for `A`.

### Failure modes & fallbacks
- **PKINIT fails (CA / EKU / key trust)** — the cert must be usable for
  Smart Card Logon; confirm the CA issued it correctly. See
  [[shadow-credentials]] / [[pkinit-unpac-the-hash]].
- **`A`'s TGT has no readable PAC hash** — rare; ensure the PKINIT path
  returned a standard TGT (not a PAC-less ticket).

## Step 3 — Recover `A`'s NT hash (UnPAC)

```powershell
# Read the NT hash out of the TGT PAC (UnPAC the hash)
Rubeus.exe ... /hash:<A-TGT>   # -> A's NT hash
```
**Verify:** `A`'s NT hash is printed. See [[pkinit-unpac-the-hash]].

### Failure modes & fallbacks
- **The PAC hash field is empty** — the domain may disable the PAC NT-hash
  field for some accounts; fall back to using the **TGT directly** (step 4)
  instead of the hash.

## Step 4 — Domain dominance

```powershell
# If A is a DA: just use the TGT / NT hash and you're in
whoami /all   # -> A (a Domain Admin)

# If A isn't itself a DA but holds a DCSync right:
secretsdump.py -hashes :<A-nthash> corp.local/A@<dc> -just-dc-user krbtgt
# -> krbtgt -> Golden Ticket -> Administrator
```
See [[golden-silver-tickets]], [[dcsync]]. **Verify:** `whoami /all` shows
Domain Admins membership (or you've dumped `krbtgt`).

### Failure modes & fallbacks
- **`A` is a DA already** — you're done; the TGT/NT hash is Domain Admin.
- **`A` holds DCSync** — dump `krbtgt` as above.
- **`A` holds neither** — you've taken over a mid-priv account; re-evaluate
  the graph from `A` (AdminTo, other GenericWrite edges).

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (plant) | **5136** attribute write to `A` (`msDS-KeyCredentialLink`) | a cert written onto a privileged account |
| 2 (PKINIT) | **4768** AS-REQ from a non-CA client; a new cert issued by the CA | an unexpected PKINIT auth as `A` |
| 3 (UnPAC) | *(no separate event — reading the PAC you already hold)* | the 4768 in step 2 is the tell |
| 4 (DCSync/Golden) | **4662** (if DCSync) / 4624 for the elevated account | a DA/DCSync artifact |

## Cleanup notes
- The **`msDS-KeyCredentialLink` cert is the durable artifact** — remove it
  (`whisker remove`) when done, or it's a standing backdoor on `A`. See
  [[ad-persistence]] (it *is* a persistence primitive).
- The **4768 PKINIT** and **5136** are the loud events; the UnPAC itself is
  silent (local).
- If caught, expect `A`'s password + the key-cred link to be reset.

## Related
- [[shadow-credentials]] — the technique this chain implements
- [[pkinit-unpac-the-hash]] — the PKINIT → NT-hash recovery (steps 2-3)
- [[whisker]] — the plant/auth tool
- [[acl-abuse]] — the GenericWrite edge the chain starts from
- [[golden-silver-tickets]], [[dcsync]] — step 4
- [[pass-the-cert]] — the related cert-auth technique (no key-cred link needed)
- [[path-genericwrite-to-dcsync]] — the analogous GenericWrite→DCSync chain
