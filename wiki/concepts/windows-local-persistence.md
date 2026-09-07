---
title: "Windows Local Persistence"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [windows, persistence, local, red-team]
---

# Windows Local Persistence

**Staying on the *box* after you've won local access.**
[[windows-privilege-escalation|Local privesc]] gets you admin/SYSTEM *now*;
local persistence makes that access **survive reboots, logoffs, and a cleanup
pass**, so the host remains a foothold you can re-use for
[[credential-dumping]], [[ntlm-relay-coercion|coercion]], and
[[remote-execution|lateral movement]] later. It's the host-level sibling of
[[ad-persistence]] (which is the *domain*-level DCShadow/Skeleton Key/AdminSDHolder
game) — same intent, different object.

In an AD engagement the reason you persist *locally* is usually one of:
- keep the **pivot box** alive (re-connect after a reboot / ticket expiry),
- keep a **coercion target** warm (the box you run the printer bug / Potato from),
- maintain **local admin** so the next time you're on the box you're already
  high-priv (no re-privesc).

## The mechanisms

### Run keys (logon-triggered)

Registry `Run` values execute at (user or system) logon:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run            (all users)
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run            (per user)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\...\Winlogon  →  Userinit / Shell                          (logon shell)
```

A `Run` value pointing at your binary (or a `rundll32.exe <yourdll>,<entry>`)
fires every logon. Quiet, but a **logon is required** — it doesn't fire on a
headless reboot with no logon.

### Services (start-triggered, SYSTEM)

Install a **service** that runs your binary at startup as `LOCAL SYSTEM`:
`sc create evil binPath= C:\...\evil.exe start= auto`. Fires on **reboot**
(no logon needed) and runs at the top local privilege. The same object
[[service-privesc|services]] are privesc'd *through* — here you're *creating*
one to persist. The tell is Event **7045** (new service).

### Scheduled tasks (trigger of your choice)

A [[scheduled-task-abuse|task]] that runs your binary at startup / logon / on a
schedule. More flexible timing than a Run key (can fire without a logon, on a
timer, at boot). Tell is Event **4698**.

### WMI (event-driven, the quiet one)

A WMI **event subscription** fires your command when a WMI event occurs — no
new service, no Run key, no file in `Startup`. The three classes:

```
__EventFilter          (the trigger — e.g. "at startup", "on process start")
__CommandConsumer      (the action — your command)
__FilterToConsumerBinding   (glues filter → consumer)
```

Persist across reboot, run with the WMI service's context (often SYSTEM), and
leave **no file** in the usual persistence locations — which is exactly why
defenders hunt them (Events **5857 / 5860 / 5861**). The "quiet" persistence of
choice when the EDR watches services + Run keys.

### Startup folder (the simple one)

Drop a `.lnk`/`.exe` in the **Startup** folder (`C:\Users\Public\Start Menu\Programs\Startup`
or the per-user one). Fires at logon. Trivially found by defenders — use it for
speed, not stealth.

### DLL side-load / COM hijack persistence

- **DLL side-load** — leave a [[dll-hijacking-sideloading|sidecar DLL]] next to
  a binary that runs at logon/boot; the trusted parent loads your DLL every
  time. Persistence *and* a trusted parent in one.
- **COM hijack** — point a **CLSID**'s `InprocServer32` at your DLL. A trusted
  binary that instantiates that COM object loads your DLL. Survives because it's
  a registry value, not a file in an obvious spot.

### Image File Execution Options (the debugger trap)

Set an **IFEO `Debugger`** value for a target executable
(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<target>`).
Next time `<target>` runs, Windows launches your **`Debugger`** binary instead
(alongside it). A persistence *and* a trigger-on-a-specific-app mechanism.

## Choosing by objective

| Objective | Best mechanism | Why |
|---|---|---|
| Survive reboot, SYSTEM, headless | **Service** or **WMI** | fire without a logon, top privilege |
| Quiet, no obvious file | **WMI** or **COM hijack** | registry/event, no `Startup` file, no 7045 |
| Fast & simple | **Run key** / **Startup** | one write, done (louder) |
| Trusted parent | **DLL side-load** | the parent is signed/known-good |
| Fire on a specific app | **IFEO Debugger** | trigger tied to that app's launch |

## Tooling

- **PowerUp** (`Add-ElevatedPersistence`, `Add-MITREAttack`) — PowerShell
  automation for Run keys, services, and the rest.
- **`sc` / `schtasks` / `reg`** — manual service / task / registry writes.
- **WMI via `wmic` / a WMI script** — the subscription classes.

## Red-team notes (OPSEC)

- **Match the persistence to the EDR** — if the box's EDR is screaming on new
  services (7045) and Run keys, go **WMI** or **COM**; if it's young, a service
  is fine and easier to reason about.
- **One mechanism, not five** — stacking Run key + service + task + WMI is
  insurance *and* four independent tells. Pick the one that fits the objective
  and the defender, and make it clean.
- **Keep it durable but reversible** — you may need to *remove* the persistence
  during cleanup (or hand it over). Know exactly what you wrote so you can
  undo it without leaving a half-deleted service.
- **Persistence is a decision, not a default** — on a box you'll pivot *off*
  quickly, persistence may be overkill (more footprint, less gain). Persist
  where you'll come back to; stay clean where you won't.

## Detection

- **Event 7045** — a new **service** (the service-persistence tell).
- **Event 4698** — a new **scheduled task** (the task tell).
- **Sysmon 13** — a write to a **Run key** / `Winlogon` / **IFEO** value
  (the registry tells).
- **Events 5857 / 5860 / 5861** — a **WMI** filter / consumer / binding created
  (the WMI tell — the quiet one defenders specifically hunt).
- **A new file in `Startup`** / a new DLL beside a boot-time binary (the
  file-based tells).
- **The meta-signal** — a persistence mechanism written by a **non-admin** or
  appearing *minutes after* a privesc event (the correlation that ties it to
  your foothold).

## Links

- [[windows-privilege-escalation]] — the win this persists
- [[service-privesc]] — the service object (privesc *through* it, persist *as* it)
- [[scheduled-task-abuse]] — the task object
- [[dll-hijacking-sideloading]] — the side-load persistence variant
- [[ad-persistence]] — the domain-level sibling (DCShadow/Skeleton Key/AdminSDHolder)
- [[windows-local-persistence]] is the host side of the [[redteam-ad-methodology|engagement arc]]
