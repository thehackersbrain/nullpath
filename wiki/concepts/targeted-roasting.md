---
title: "Targeted roasting (ACL-driven Kerberoast / AS-REP, no-SPN, no-preauth)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, active-directory, credential-access, acl-abuse, offline-cracking]
---

# Targeted roasting

Classic [[kerberoasting]] and [[as-rep-roasting]] passively harvest whatever the
domain already exposes. **Targeted roasting** *creates* the condition: when you
hold a write primitive over a victim account (a BloodHound `GenericWrite` /
`GenericAll` edge — [[acl-abuse]]), you **temporarily set the attribute that
makes them roastable**, pull the crackable material, and revert. It turns an ACL
edge into a **password** — often the cleanest way to "cash in" a control edge on
a user you don't want to (or can't) reset.

## Targeted Kerberoasting (write an SPN)

If a victim user has **no SPN** but you can write `servicePrincipalName` on them,
add a fake SPN, Kerberoast them, crack, remove the SPN.

```bash
# PowerView
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/nopyourwatching'}
Get-DomainSPNTicket -SPN 'fake/nopyourwatching' | ...            # roast
Set-DomainObject -Identity victim -Clear serviceprincipalname   # revert

# targetedKerberoast.py — finds writable users, sets SPN + roasts + cleans up
targetedKerberoast.py -v -d corp.local -u attacker -p pass
# or drive the SPN/UAC writes with bloodyAD ([[bloodyad]]): add uac / set attribute, then roast
```

`targetedKerberoast.py` automates the set→roast→clean loop across every user you
can write. Crack the output as normal ([[kerberoasting]]: hashcat `-m 13100`).

## Targeted AS-REP roasting (flip DONT_REQ_PREAUTH)

If you can write `userAccountControl` on the victim, enable
**`DONT_REQ_PREAUTH`**, AS-REP roast them, then clear the bit.

```bash
# PowerView — set the "do not require preauth" UAC bit, roast, then revert
Set-DomainObject -Identity victim -XOR @{useraccountcontrol=4194304}
Get-DomainUser victim | ...                                     # AS-REP roast ([[as-rep-roasting]])
Set-DomainObject -Identity victim -XOR @{useraccountcontrol=4194304}   # flip back
```

Crack with hashcat `-m 18200`.

## Roasting variants worth knowing

- **Kerberoasting without an SPN (U2U).** You can roast a user who has no SPN
  without writing one, using a **user-to-user (U2U)** S4U2self request — the
  service ticket is encrypted with the *target user's* key, so it's crackable
  like a normal Kerberoast. Useful when you *can't* write `servicePrincipalName`.
- **AS-REP roasting the writable way** is the targeted case above; the passive
  case is [[as-rep-roasting]].
- **Kerberoasting without pre-auth (CVE-2022-33679).** An **unauthenticated**
  twist: request an AS-REP for a preauth-disabled account forcing **RC4**, and
  because part of the response is known plaintext, recover the **session key**
  and obtain a limited TGT — no creds needed. Niche and patch-dependent, but it
  belongs in the exhaustive roasting picture.

## Red-team notes (OPSEC)

- **The attribute write is the loud part.** Setting an SPN or flipping a UAC bit
  fires **5136** on the victim object; do it, roast, and **revert in one tight
  window** so the object looks untouched afterward. `targetedKerberoast.py` does
  this automatically.
- **Pick the victim from the graph.** Roast the users your edge actually covers
  that also look weak (service-ish accounts, stale users) — and avoid
  honeypot/[[honeytokens|honey]] accounts, where *any* SPN/UAC write or roast is
  malicious by definition.
- **Prefer this over resetting the victim's password** — a reset locks the user
  out and is far louder than a transient attribute you revert.

## Detection

- **5136** on `servicePrincipalName` or `userAccountControl` for a normal user
  (an SPN suddenly appearing on a user account, or `DONT_REQ_PREAUTH` toggled),
  **immediately followed by 4769/4768** for that account — the set→roast pattern.
- The usual roast tells ([[kerberoasting]] 4769 RC4 bursts, [[as-rep-roasting]]
  4768 type-0), correlated with the attribute change.
- Mitigation: alert on SPN/UAC writes to user objects; least-privilege on those
  attributes ([[acl-abuse]]); [[gmsa]] / strong passwords so a crack fails anyway.

## Links

- [[kerberoasting]] — the TGS crack this triggers on demand
- [[as-rep-roasting]] — the AS-REP crack the UAC flip enables
- [[acl-abuse]] — the GenericWrite/GenericAll edge that makes it possible
- [[bloodhound]] — where you find the writable-user edges
- [[kerberos-preauth]] — the pre-auth bit toggled for targeted AS-REP
- [[honeytokens]] — the trap accounts to avoid roasting
- [[kerberos-armoring-fast]] — the defense that blunts the AS-REP half
