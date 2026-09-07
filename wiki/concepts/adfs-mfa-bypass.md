---
title: "ADFS MFA Bypass (SAML Token Poisoning)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [ad, adfs, mfa, bypass, saml, wst, cve, red-team]
---

# ADFS MFA Bypass (SAML Token Poisoning)

**Turning a valid ADFS token into MFA-free access to *any* federated app.** ADFS
enforces MFA for *interactive* logon, but the **token-based** request path
(WS-Trust "issue" with an existing token) is commonly **MFA-exempt**. CVE-2020-0688
weaponised exactly that: present a valid SAML token and ADFS mints you a new token
for **any Relying Party** with **any claims**, skipping MFA. One captured token →
MFA bypass → privileged-app access.

This is the single highest-value ADFS win because it defeats the second factor
without needing a password, a hash, or admin rights.

## The mechanics

### The MFA-exempt token path (the root cause)

ADFS treats a request that **already carries a valid token** as
"pre-authenticated" and **does not re-challenge MFA** — it trusts the presented
token and issues a new one on its authority. The WS-Trust `wstrust` endpoint
(`/adfs/ls/wstrust`) accepts an RST (Request Security Token) that includes:

- an **existing valid token** in the request context, and
- a **claim request** for the target Relying Party.

ADFS validates the existing token, then issues a **new token for the requested
RPT with the requested claims** — no MFA prompt, because the request "already
authenticated."

### CVE-2020-0688 (token poisoning)

- **Affects:** ADFS 3.0.2 / 4.0.x before the 2020-02 cumulative update.
- **The bug:** ADFS did not properly validate the **claims** in a WS-Trust request
  that carried a valid token. An attacker could take a *valid* SAML token (for
  *any* RPT), and craft a WS-Trust request that:
  1. presents that valid token, and
  2. requests **modified/arbitrary claims** (e.g. `group` membership you don't
     have, a different `userPrincipalName`, a privileged role).
- **The effect:** ADFS issues a **new token with the attacker-chosen claims** for
  **any RPT**, MFA-exempt. So from one low-priv token you forge a high-priv token
  for a privileged app — full MFA bypass *and* claim escalation.
- **The chain:**
  ```
  any valid SAML token (low-priv user, any RPT)
    → WS-Trust request: present token + request target RPT + chosen claims
    → ADFS issues new token, target RPT, chosen claims, no MFA
    → present forged token to the privileged RPT
  ```

### Other MFA-exempt paths (still relevant on patched builds)

Even when CVE-2020-0688 is patched, the *underlying* MFA-exempt token path remains
in several forms — these are the "MFA bypass by design" surfaces:

- **WS-Trust token issue with a valid token** — the same pre-authenticated
  behaviour, now claim-validated, but still MFA-exempt: a valid token → new token
  for the RPTs that token is allowed to reach, no MFA.
- **Device-based auth** — registered/trusted **devices** authenticate MFA-exempt
  ([[adfs-device-auth]]). A device cert or machine account → ADFS token, no MFA.
- **Kerberos-based auth** — a valid **Kerberos ticket** authenticates to ADFS
  MFA-exempt. Hold a TGT (or forge one) → ADFS token, no MFA.

## Tooling

- **PoC / exploit scripts** for CVE-2020-0688 (public Python/PowerShell) — take a
  captured SAML token, craft the WS-Trust poisoning request, return the forged
  token.
- **Manual WS-Trust** — a crafted HTTP POST to `/adfs/ls/wstrust` with the
  SOAP RST; the quietest, no tool name on the wire.
- **Capture the seed token** — from a browser (DevTools), a proxy, or a stolen
  session ([[adfs-token-theft]]).

## Red-team notes (OPSEC)

- **Version-gate the bypass** — CVE-2020-0688 only fires on unpatched ADFS.
  Fingerprint the build first (error pages, `adfsadmin`, the farm config). On a
  patched box, fall back to the MFA-exempt device/Kerberos/token paths.
- **You need one valid seed token** — the poisoning needs a *valid* SAML token to
  start. The quiet way to get it is a stolen low-priv session
  ([[adfs-token-theft]]), not a loud interactive login.
- **Claim-escalate to the payoff RPT** — the win is the *privileged* RPT (SCCM,
  AD CS, an admin portal). Enumerate RPTs first ([[adfs]]) and target the one
  whose claims grant the domain-relevant right.
- **Keep it one sequence** — the mint (WS-Trust request → forged token) should be
  a single tight transaction; the ADFS logs correlate the seed token, the request,
  and the issued token.

## Detection

- **ADFS event 368 (token issue) with no preceding MFA challenge** — the core
  tell: a token minted on the token-based path without a second factor.
- **A WS-Trust RST that carries an existing token** — the poisoning shape;
  specifically, requested **claims that differ from the seed token's claims**
  (the CVE-2020-0688 signature).
- **Anomalous claims in the issued token** — group/role/UPN claims that don't
  match the authenticated subject.
- **The seed → forge correlation** — a low-priv seed token followed minutes later
  by a high-priv token for a different RPT from the same source.
- **MFA-exempt device/Kerberos auth** — ADFS success by a device cert or Kerberos
  ticket with no MFA (the by-design bypasses, [[adfs-device-auth]]).

## Links

- [[adfs]] — the hub (architecture, RPT enumeration, the attack-surface map)
- [[adfs-device-auth]] — the MFA-exempt device/computer path
- [[adfs-preauth]] — the MFA-exempt Kerberos path
- [[adfs-token-theft]] — how you get the seed token
- [[kerberos-authentication]] — the Kerberos path ADFS trusts MFA-exempt
- [[redteam-ad-methodology]] — where an MFA bypass sits in the arc
