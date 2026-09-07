---
title: "Scheduled Task Abuse"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, privesc, scheduled-task, local, persistence]
---

# Scheduled Task Abuse

**Abusing a Windows *scheduled task* to run code as the account the task runs
under** — frequently `SYSTEM` or a local admin. Like
[[service-privesc|services]], scheduled tasks are long-lived, run at a
privilege above the user you're on, and are routinely writable by low-priv
accounts. The flip side: a task is also a
[[windows-local-persistence|persistence]] mechanism, so "abuse it to privesc"
and "drop one to persist" are the same surface.

## The vectors

### Writable task (the DACL is the door)

Each task has a **principal** (who it runs as) and an **action** (what it
runs). If a low-priv user can **modify the task** (write on the task object),
you can:

- **Change the action** to your binary: `schtasks /change /tn "<task>" /tr "C:\temp\evil.exe"`.
- **Change the principal** to a higher account (if the task's ACL allows it).
- **Change the trigger** so it fires on your schedule.

Enumerate the tasks and find the writable ones:

```bat
schtasks /query /fo LIST /v        :: every task, its principal + action + ACL
:: look for tasks whose Action points at a writable path, or whose principal
:: is SYSTEM/admin and whose ACL your user can write
```

PowerUp / [[winpeas]] flag "writable scheduled task" + "task binary is
writable" automatically.

### Writable task binary (replace the file)

If the task's action runs a binary you can **write on disk**, replace that
binary with your payload. Next time the task fires (or you trigger it with
`schtasks /run`), it runs *your* code as the task's principal. This is the
task-analog of the [[service-privesc|writable service binary]].

### Task that runs a script / interpreter you can redirect

A task whose action is `cmd /c C:\scripts\x.bat`, `powershell -File ...`, or
`wscript C:\...\x.vbs` — if you can write the script, or the
`PATHEXT`/`PATH` the task inherits ([[environment-variable-attack]]), the task
executes your code as its (high) principal.

## Lateral-movement overlap (the atexec side)

The *same* primitive is how you **run a task on a remote box** as
`SYSTEM`/admin — that's the `atexec` / `schtasks` lateral in
[[remote-execution]]. The difference: local abuse = *modify an existing task on
this box*; lateral = *create a task on a box you already have admin on*. The
detection and the mechanics are shared.

## Tooling

- **[[winpeas]]** — flags writable tasks + writable task binaries.
- **PowerUp** (`Invoke-TaskAbuse`, `Start-TaskAbuse`) — the PowerShell
  automation for the writable-task and writable-binary vectors.
- **`schtasks`** — manual enumerate / change / run.
- **atexec** (impacket / netexec) — the remote-task lateral (cross-ref
  [[remote-execution]]).

## Red-team notes (OPSEC)

- **Prefer the writable-binary over the task-recreate** — replacing the file a
  *legit* task already runs is quieter than creating a brand-new task (which
  fires Event 4698, the loud one).
- **Trigger it, then delete/restore** — `schtasks /run "<task>"` to fire on
  your timing (not the box's), grab the shell, then restore the original
  binary/action so the next legit run isn't your payload.
- **The task's principal is your privilege ceiling** — a task running as
  `SYSTEM` hands you SYSTEM; one running as a local admin hands you admin.
  Confirm the principal before you invest.
- **Don't leave a `C:\temp\evil.exe` task** — a task pointing at `%temp%` is a
  persistence *and* a privesc breadcrumb; clean both.

## Detection

- **Event 4698** — a scheduled task **created** (the lateral / new-task tell).
- **Event 4699** — a task **updated** (the writable-task / action-change tell).
- **Event 4702** — a task **deleted** (cleanup tell).
- **Event 4697** — a task **enabled**; **4700** task disabled; **4701** task
  updated (older builds).
- **The action-path anomaly** — a SYSTEM principal task whose action resolves
  to a writable / non-standard path (`%temp%`, a user profile, a newly-written
  binary) — Sysmon 1 + 4688 correlated with 4699.

## Links

- [[windows-privilege-escalation]] — the hub
- [[service-privesc]] — the sibling vector (services instead of tasks)
- [[windows-local-persistence]] — a task is persistence too
- [[environment-variable-attack]] — the script/interpreter redirect it leans on
- [[remote-execution]] — the atexec lateral side
- [[winpeas]] — the enumeration that finds these
