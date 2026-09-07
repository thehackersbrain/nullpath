---
title: "ADFS (Active Directory Federation Services)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [ad, adfs, federation, sts, saml, red-team, tier0]
---

# ADFS (Active Directory Federation Services)

**The Windows federation role that issues tokens — SAML, WS-Trust, Kerberos,
OAuth/OIDC — for external and internal apps.** ADFS is a *Security Token
Service* (STS): it authenticates an identity (a user, a machine, a device) and
returns an **assertion** that a *Relying Party* accepts. It's the front door for
remote users, the MFA enforcement point, and — for an attacker — a Tier 0-adjacent,
often-internet-facing target that sits *in front of* the KDC and the domain.

ADFS is not "cloud" — it's an on-prem Windows role (a server farm, load-balanced),
deployed exactly where AD lives. That's why it's in scope for an AD engagement:
own ADFS and you can mint tokens for federated apps, bypass MFA, authenticate as
machine/device identities, and use it as a Kerberos pre-auth endpoint.

## The model (what ADFS actually is)

- **STS / RSTS** — the token issuer and its **Request Security Token Service**
  endpoints (`/adfs/ls/`, `/adals/oauth2/token`, the WS-Trust `wstrust` endpoint).
  This is where you POST auth and get tokens back.
- **Relying Party Trust (RPT)** — a trust ADFS has with an *external app* (the
  Service Provider). Each RPT declares **which auth types are allowed**
  (Kerberos / NTLM / forms / certificate / OAuth) and **which claims** to assert.
  The RPT list is the map of "which apps can a token get me into."
- **Claims** — the attributes (userPrincipalName, group, role, …) embedded in the
  issued token. Control the claims and you control what the RPT believes about you.
- **Federation protocols** — SAML 1.1/2.0, WS-Trust (WST), Kerberos, NTLM,
  OAuth 2.0 / OIDC. ADFS speaks all of them; each has a different token shape and
  a different theft/replay surface.
- **Identity Provider (IdP) vs Service Provider (SP)** — ADFS is the IdP; the
  federated app is the SP. The token flows IdP → SP.
- **ADFS farm** — multiple ADFS servers behind a load balancer; state (sessions,
  tokens) is shared, so a token minted on one node is valid on all.

## Why it's an attack surface

1. **Internet-facing / Tier 0-adjacent** — it's the external entry for remote
   users, so it's reachable even when the rest of AD isn't. A foothold here is a
   foothold at the door of the domain.
2. **The MFA enforcement point** — ADFS is where MFA is enforced for interactive
   logon. A **MFA bypass** (see [[adfs-mfa-bypass]]) is one of the highest-value
   wins in an AD engagement: full access without the second factor.
3. **Device & computer authentication** — ADFS accepts **machine accounts and
   device certs** as identities ([[adfs-device-auth]]). A machine hash or device
   cert you already hold becomes an ADFS login.
4. **A Kerberos pre-auth endpoint** — ADFS performs Kerberos pre-auth, so it's a
   second AS-REQ/AS-REP surface for [[as-rep-roasting]] and AS-REQ/PKINIT forging
   ([[adfs-preauth]]).
5. **Token issuance** — every issued SAML/WST/Kerberos/OAuth token is a
   replayable artefact ([[adfs-token-theft]]).

## Attack surface map

| Surface | Technique | Page |
|---|---|---|
| MFA enforcement | SAML token poisoning (CVE-2020-0688), WST MFA-exempt issue | [[adfs-mfa-bypass]] |
| Device/computer auth | machine account / device cert → ADFS token | [[adfs-device-auth]] |
| Kerberos pre-auth | AS-REP roasting, AS-REQ/PKINIT forging via ADFS | [[adfs-preauth]] |
| Token lifecycle | SAML/WST/OAuth token theft + replay | [[adfs-token-theft]] |
| RPT enumeration | map which apps + auth types are federated | below |

**RPT enumeration first.** Before any technique, enumerate the Relying Party
Trusts — which apps exist, which auth types each allows, which claims are
asserted. That tells you the payoff of each path (a RPT that allows Kerberos or
NTLM with no MFA is the easiest win) and is low-noise:

```powershell
# on an ADFS server (or via the PowerShell SDK)
Get-AdfsRelyingPartyTrust | Select Name, Enabled
Get-AdfsRelyingPartyTrust -TargetName <app> |
  Select ClaimIssuanceAuthorizationRules, PermissionToIssueTokens
# WS-Trust: which auth types does the RPT accept?
Get-AdfsRelyingPartyTrust -TargetName <app>.AuthTypes   # via the farm config
```

## Red-team notes (OPSEC)

- **Check the version before you pick a bypass** — CVE-2020-0688 only hits
  unpatched ADFS (pre-2020-02 builds). Enumerate the ADFS version
  (`adfsadmin` / the farm config / the error pages) so you know which bypasses
  are live.
- **ADFS is loud when it's broken** — MFA-bypass and token-forge events stand
  out in the ADFS logs. Do the RPT enumeration (quiet, read-only) before the
  noisy mint, and keep the mint a single tight sequence.
- **You may already hold an ADFS identity** — a machine account hash or a device
  cert from elsewhere in the engagement is a ready-made ADFS login
  ([[adfs-device-auth]]). Reuse identity material before you try to mint a new one.
- **Tier 0 mind, not "just the web"** — ADFS tokens gate *privileged* apps
  (SCCM, AD CS, admin portals). The payoff is often a domain-relevant foothold,
  not just an app session.

## Detection

- **ADFS event 25 / 125** — authentication success / failure; watch for auth by a
  **machine account** or **device** (not a user) and for success *without an MFA
  challenge* (event 368 token issue with no preceding MFA).
- **WS-Trust requests carrying an existing token** — the CVE-2020-0688 shape
  (an RST that presents a valid token and requests new/modified claims).
- **Anomalous claims** — a token issued with claims that don't match the subject
  (the poisoning tell).
- **Kerberos pre-auth to ADFS** — AS-REP requests (4768 with no pre-auth) and
  PKINIT (4768 pre-auth type 12) landing on the ADFS/KDC path.
- **Token replay** — the same SAML assertion / OAuth token / session cookie used
  from a new source or IP.

## Links

- [[adfs-mfa-bypass]] — the highest-value win: SAML token poisoning + WST MFA-exempt issue
- [[adfs-device-auth]] — machine account / device cert as an ADFS identity
- [[adfs-preauth]] — ADFS as a Kerberos pre-auth endpoint
- [[adfs-token-theft]] — SAML/WST/OAuth token theft and replay
- [[kerberos-authentication]] — the KDC path ADFS sits in front of
- [[kerberos-preauth]] — the pre-auth ADFS exposes a second surface for
- [[as-rep-roasting]] — the roast ADFS can serve as an endpoint for
- [[shadow-credentials]] — the device/user certs ADFS device-auth reuses
- [[pkinit-unpac-the-hash]] — the PKINIT path ADFS also exposes
- [[service-account]] — the machine accounts ADFS accepts as identities
- [[ntauthcertificates]] — the device certs that authenticate to ADFS
- [[ad-tier-model]] — where ADFS sits (external/Tier 0-adjacent)
- [[redteam-ad-methodology]] — the engagement arc ADFS slots into
- [[pki-and-ad-cs-architecture]] — the cert infra behind device auth
