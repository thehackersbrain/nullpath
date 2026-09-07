---
title: Shadow Credentials (msDS-KeyCredentialLink Abuse)
type: concept
created: 2026-06-13
updated: 2026-09-07
tags: [active-directory, kerberos, privilege-escalation, persistence, pkinit]
---

# Shadow Credentials (msDS-KeyCredentialLink Abuse)

A passwordless account-takeover technique: an attacker with write access
to a target's `msDS-KeyCredentialLink` attribute appends a key-trust
certificate they control, then authenticates as the target via
[[pkinit-unpac-the-hash|PKINIT]] — recovering a TGT and (via UnPAC the
hash) the account's NT hash, without touching the real password.

## Mechanism

`msDS-KeyCredentialLink` stores "Key Credential" objects binding a public
key to a user/computer for **Key Trust** authentication (the modern
equivalent of "virtual smart card"). Any principal that can write this
attribute can add their own key — `GenericWrite`/`GenericAll`/explicit
attribute write are the relevant [[acl-abuse]] edges (BloodHound
`AddKeyCredentialLink`).

## Attack flow

1. **Whisker / pyWhisker** `add /target:<account>` — appends attacker key,
   outputs a ready-made Rubeus command.
2. **Rubeus** `asktgt /certificate:<cert> /getcredentials /ptt` — PKINIT
   auth as the target, returns TGT + NT hash via
   [[pkinit-unpac-the-hash|PAC_CREDENTIAL_INFO]].
3. **(Computer accounts)** Rubeus `s4u` (S4U2Self) to impersonate a
   privileged user against the compromised computer's services — see
   [[kerberos-delegation-abuse]].

## Requirements

- AD CS configured with at least one CA
- DC running Windows Server 2016+ (PKINIT support)
- Write access to `msDS-KeyCredentialLink` on the target

## Relation to other techniques

- The "write to an attribute → become the account" pattern is the same
  shape as [[acl-abuse]] in general, but the *output* (a usable cert +
  NT hash) is what makes it distinct and so powerful.
- [[ad-cs-esc-attacks]] achieve a similar end-state (a usable cert for
  another principal) via certificate template misconfiguration instead of
  a DACL write.
- Origin: Elad Shamir, 2021. Standard in BloodHound-driven paths today.

## Red-team notes (OPSEC)

- **You need the write edge first** — a `GenericWrite`/`GenericAll` (or explicit
  write on `msDS-KeyCredentialLink`) over the target, straight off a
  [[bloodhound]] path ([[acl-abuse]]). Confirm the edge before touching it.
- **Quieter than a password reset.** It's the preferred takeover when you hold
  write over an account you *don't* want to lock out — you add a key, auth as
  them, and never change their password.
- **Add the key, use it, remove it.** `pywhisker`/`certipy shadow auto` from
  Linux (or `Whisker.exe` on-host) adds the KeyCredential; then PKINIT +
  **UnPAC the NT hash** ([[pkinit-unpac-the-hash]]); then **delete the key you
  added** — a lingering `msDS-KeyCredentialLink` is both the tell and a
  loose backdoor.
- **The whole chain runs remotely** over the tunnel (certipy/pywhisker), so the
  only footprint is the 5136 attribute write + a 4768 cert pre-auth on the DC.
- **Works when RC4/roasting is dead** — it recovers the NT hash directly via
  the PAC even on an AES-only, hardened domain.

## Detection

- Monitor writes to `msDS-KeyCredentialLink` (rare in normal operation).
- Certificate-based Kerberos pre-auth (4768) for an account that doesn't
  normally use smart-card/cert logon is anomalous.

## See also

- [[path-shadow-credentials-to-nt-hash]] — the end-to-end chain (write the key,
  PKINIT, UnPAC the hash)
- [[hideandsec]] — the research this technique is built on
