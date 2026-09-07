---
title: GPO Abuse
type: concept
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, privilege-escalation, lateral-movement, gpo]
---

# GPO Abuse

Group Policy Objects (GPOs) push security settings, scripts, and scheduled
tasks to every machine/user in their linked scope (OU > Domain > Site >
Local precedence). A principal with edit rights on a GPO — `GenericWrite`,
`WriteDacl`, `WriteOwner` (a [[acl-abuse]] edge) — can use that GPO as a
domain-wide code execution primitive. See [[gpo-abuse]] (source) for full
tooling commands.

## Storage & refresh

GPOs live in SYSVOL:
`\\<domain>\SYSVOL\<domain>\Policies\<GPOName>\` (`Machine\` / `User\`
subfolders; scheduled tasks under `Machine\Preferences\ScheduledTasks`).
Clients refresh every 90 min ± 0-30 min, or immediately via `gpupdate
/force`.

## Enumeration

- **PowerView** `Get-DomainObjectAcl -ResolveGUIDs` filtered for abusable
  rights on GPOs.
- **GPOHound** — offline dump/analysis of GPO contents (scripts, scheduled
  tasks, preferences) for credential/payload hunting.

## Abuse primitives (all achieve similar outcomes via different tooling)

- **Local admin grant**: add a user/group to local Administrators via the
  GPO's restricted groups / GPP.
- **User Rights Assignment**: grant privileges like `SeDebugPrivilege`,
  `SeTakeOwnershipPrivilege` to a controlled principal.
- **Logon scripts**: user or computer startup scripts.
- **Immediate scheduled tasks**: run-once-per-refresh tasks — the most
  common code-exec vector (SharpGPOAbuse `--AddComputerTask`, PowerView
  `New-GPOImmediateTask`, StandIn `--tasktype`).

Tools: SharpGPOAbuse (.NET), PowerGPOAbuse (PowerShell), pyGPOAbuse
(cross-platform), StandIn, Synacktiv's GroupPolicyBackdoor (stateful, with
cleanup).

## Relation to other techniques

- Same root cause as [[acl-abuse]] (excessive write rights on an AD
  object) — GPOs are just a particularly high-blast-radius object class
  because of their scope.
- A linked GPO applying to Domain Controllers' OU is effectively a
  domain-dominance primitive on par with [[dcsync]]/[[golden-silver-tickets]].

## Detection

- Audit non-default ACEs on GPO objects, especially GPOs linked to
  high-value OUs (Domain Controllers, Tier 0).
- Monitor SYSVOL writes to GPO folders (especially `ScheduledTasks\` and
  script directories) outside of normal change-management windows.
