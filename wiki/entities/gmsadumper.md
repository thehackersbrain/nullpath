---
title: "gMSADumper — read gMSA managed passwords over LDAP"
type: entity
created: 2026-09-07
updated: 2026-09-07
tags: [tool, python, gmsa, credential-access, ldap]
---

# gMSADumper

**gMSADumper** (`gMSADumper.py`, by micahvandeusen) is the go-to tool for
**dumping Group Managed Service Account passwords over LDAP**. It reads the
computed **`msDS-ManagedPassword`** blob for every gMSA the supplied account is
allowed to retrieve (i.e. is listed in that gMSA's `msDS-GroupMSAMembership`),
parses the `MSDS-MANAGEDPASSWORD_BLOB`, and prints the **current NT hash** (and
Kerberos keys) — no LSASS dump, no [[dcsync]], no offline cracking. It's the
tooling behind the "read the managed password" path in [[gmsa]].

## Usage

```bash
# Enumerate + dump every gMSA this account can retrieve
gMSADumper.py -u user -p 'Password1' -d corp.local
gMSADumper.py -u user -p :<nthash> -d corp.local -l dc01.corp.local   # PtH + explicit DC

# Output gives, per readable gMSA:
#   svc_gmsa$:::<nthash>        <- feed straight into PtH / silver-ticket / roast-free auth
```

Run it from the Linux operator host over the tunnel
([[pivoting-and-tunneling]]). Equivalents: **`nxc ldap dc01 -u u -p p --gmsa`**
([[netexec]]) and **[[bloodyad|bloodyAD]] `get object '<gmsa>$' --attr
msDS-ManagedPassword`**; on-host, RSAT `Get-ADServiceAccount -Properties
msDS-ManagedPassword` + **DSInternals** `ConvertFrom-ADManagedPasswordBlob`.

## Where it fits

- **The read is gated by `msDS-GroupMSAMembership`.** You either already control
  a principal in that set, or you **write** the attribute to add one you control
  — a classic [[acl-abuse]] move (BloodHound `ReadGMSAPassword` / `AddSelf`
  edges). Either way the output is the **current** key, and it **auto-updates
  every rotation**, so a retained read doubles as **persistence**.
- The recovered NT hash → [[pass-the-hash-and-ticket|PtH/PtT]],
  [[golden-silver-tickets|silver ticket]] for the gMSA's SPN, or direct logon as
  the service (often an elevated context on a sensitive host).

## OPSEC / detection

- **Quiet.** It's an LDAP read of an attribute you're authorized for — far lower
  signal than an [[lsass]] dump or [[dcsync]]. The catchable events are the
  **write** to `msDS-GroupMSAMembership` (5136) if you had to grant yourself the
  read, and directory-service reads of `msDS-ManagedPassword` where that auditing
  is enabled.
- Mitigation: tightly scope `msDS-GroupMSAMembership` to the exact service
  host(s), audit writes to it, and keep the rollover interval short — see
  [[gmsa]], [[ad-tiering-and-hardening]].

## Links

- [[gmsa]] — the account type and full attack surface (this is the LDAP-read path)
- [[acl-abuse]] — writing `msDS-GroupMSAMembership` to grant yourself the read
- [[netexec]] — `nxc ldap --gmsa` does the same inline
- [[pass-the-hash-and-ticket]] / [[golden-silver-tickets]] — using the recovered key
- [[dcsync]] / [[lsass]] — the louder alternatives to the same secret

## References

- [gMSADumper (GitHub)](https://github.com/micahvandeusen/gMSADumper)
- [DSInternals — ConvertFrom-ADManagedPasswordBlob](https://github.com/MichaelGrafnetter/DSInternals)
