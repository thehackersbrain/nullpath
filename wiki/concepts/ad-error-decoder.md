---
title: "AD/Kerberos error decoder (failure → cause → fix)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [tradecraft, troubleshooting, kerberos, ad-cs, field-notes, opsec]
---

# AD/Kerberos error decoder

**The failure mode is usually the hint.** Most of the time you're not blocked —
you're one clock-sync, one FQDN, or one enctype away. This is the field decoder:
the errors you actually hit running Impacket/Rubeus/Certipy/nxc against a domain
(especially from a Linux operator host over a tunnel), what each really means,
and the fix. Pairs with [[ticket-manipulation]] and [[foothold-playbook]].

## Kerberos errors (the big ones)

| Error | What it usually means | Fix |
|---|---|---|
| **KRB_AP_ERR_SKEW** / "clock skew too great" | your host's time differs from the DC by >5 min | **sync to the DC**: `sudo ntpdate <dc>` / `sudo rdate -n <dc>`, or wrap the tool in `faketime "$(...)"`. #1 tunnel gotcha. |
| **KDC_ERR_PREAUTH_FAILED** | wrong password / hash / key, **or wrong enctype** | recheck the cred; try the **AES key** instead of RC4 (or vice versa); confirm you're using the right account. |
| **KDC_ERR_PREAUTH_REQUIRED** | the account **requires** pre-auth (normal) | it means the account is **not** AS-REP-roastable; you need real creds, not `-no-pass`. |
| **KDC_ERR_C_PRINCIPAL_UNKNOWN** | the **client** (user) doesn't exist as asked | fix username **casing**/spelling, the **realm** (`user@CORP.LOCAL`), and that you're hitting the right domain. |
| **KDC_ERR_S_PRINCIPAL_UNKNOWN** | the **service/SPN** doesn't exist as asked | use the **FQDN** SPN (`cifs/host.corp.local`, not the IP/short name); verify the SPN exists (`GetUserSPNs`); check DNS. Very common on kerberoast/silver/S4U. |
| **KRB_AP_ERR_MODIFIED** | the target **can't decrypt** your service ticket | **wrong service key** (bad silver-ticket hash) or **wrong target name** — you targeted by **IP not hostname**, or the SPN/host doesn't match the key. Use the exact SPN host the key belongs to. |
| **KDC_ERR_ETYPE_NOTSUPP** | requested **enctype** not held by the account/domain | switch enctype (RC4↔AES); e.g. RC4 requested on an RC4-disabled account, or you supplied an AES key the account doesn't have. See [[kerberos-encryption-types]]. |
| **KDC_ERR_BADOPTION** (in S4U/delegation) | delegation not permitted as asked | S4U2proxy target not in `msDS-AllowedToDelegateTo`; **RBCD not set**; or a non-forwardable ticket (Protected Users) — see [[bronze-bit]] (`-force-forwardable`). |
| **KDC_ERR_TGT_REVOKED** | `krbtgt` rotated / ticket invalidated | re-request; your forged/old ticket is dead (someone rotated [[krbtgt]]). |
| **KDC_ERR_CLIENT_REVOKED** | account **disabled / locked / expired** | wrong target, or you locked it — check `badPwdCount`/lockout ([[password-spraying]]). |
| **KDC_ERR_POLICY** | account **restrictions** hit | logon-hours / workstation restrictions / "sensitive"/Protected Users. |
| **KRB_AP_ERR_TKT_EXPIRED** | ticket lifetime elapsed | renew or re-request; check skew too. |
| **KRB_ERR_RESPONSE_TOO_BIG** | UDP response too large (big PAC) | force **TCP** for Kerberos (impacket does this; set `KRB5_CONFIG` `udp_preference_limit = 1`). |
| **KDC_ERR_WRONG_REALM** / cross-realm oddities | trust/DNS/hosts confusion | populate `/etc/hosts`, target **by hostname**, get the realm casing right ([[trust-key-abuse]] for the trust case). |

## AD CS / PKINIT / Certipy

| Error | What it usually means | Fix |
|---|---|---|
| **KDC_ERR_PADATA_TYPE_NOSUPP** | the DC **can't do PKINIT** (no/expired KDC cert) | cert logon is unavailable; fall back to **UnPAC-the-hash** (`certipy auth` gets the NT hash via U2U even without PKINIT — [[pkinit-unpac-the-hash]]). |
| Certipy: **KDC_ERR_CLIENT_NOT_TRUSTED** | cert not trusted for logon | issuing CA not in **[[ntauthcertificates]]**; cert lacks **Client Authentication** EKU; or SID-binding enforcement rejects it. |
| Certipy: **"Object SID … does not match"** | post-KB5014754 strong SID binding | the modern default; you need an ESC that defeats mapping — [[esc9]]/[[esc10]]/[[esc16]] ([[certificate-mapping]]). |
| Certipy `find` shows nothing vulnerable | no ESC on reachable CAs, or wrong context | try authenticated `find`, check other CAs, and cross-forest publication ([[cross-forest-adcs]]). |
| Certipy `auth` errors after a good `req` | usually **skew or DNS** | sync time, target the DC by **FQDN**. |

## LDAP / SMB / tool errors

| Error | What it usually means | Fix |
|---|---|---|
| LDAP **strongerAuthRequired** / `00002028` | **LDAP signing / channel binding** required | use **LDAPS** (636) or Kerberos (`-k`); many writes (RBCD, shadow creds) then work. |
| **STATUS_LOGON_FAILURE** | bad creds | recheck password/hash/domain; `--local-auth` for a local account. |
| **STATUS_ACCESS_DENIED** (creds valid) | authenticated but **no rights** | you're in, just unprivileged — enumerate what the cred *can* do ([[ad-enumeration]], `bloodyAD get writable`). |
| **STATUS_ACCOUNT_RESTRICTION** | logon type/workstation/hours restriction | try a different exec transport ([[remote-execution]]) or account. |
| nxc: **signing:True** / ntlmrelayx "not relaying" | **SMB signing enforced** on the target | pick an unsigned target (`--gen-relay-list`); relay elsewhere ([[ntlm-relay-coercion]]). |
| bloodhound-python: **DNS resolution failed** | can't resolve the domain over the tunnel | `-ns <dc-ip>` and/or add DC names to `/etc/hosts` ([[pivoting-and-tunneling]]). |
| "**The NETBIOS connection … failed**" | name resolution / SMB reachability | target by IP for SMB, by **hostname** for Kerberos; check the tunnel route. |

## The five fixes that solve most of it

1. **Sync your clock to the DC** (`ntpdate`/`rdate`/`faketime`) — kills skew errors.
2. **Use FQDNs, not IPs, for anything Kerberos** — SPNs bind to names; add `/etc/hosts`.
3. **Set `KRB5CCNAME`** (and `KRB5_CONFIG`) before `-k`/`--use-kcache` calls
   ([[ticket-manipulation]]).
4. **Switch enctype** (RC4↔AES) when a key/etype error hits
   ([[kerberos-encryption-types]]).
5. **Go LDAPS / `-k`** when a write is refused for signing/channel-binding.

## Links

- [[ticket-manipulation]] — kirbi/ccache/KRB5CCNAME plumbing (half these fixes)
- [[foothold-playbook]] — the "what next" side of getting unstuck
- [[kerberos-encryption-types]] — the enctype errors in depth
- [[pivoting-and-tunneling]] — why skew/DNS bite over a tunnel
- [[kerberos-authentication]] — the flow these errors map onto
- [[ad-enumeration]] — enumerate-before-exploit (most "errors" are wrong assumptions)
