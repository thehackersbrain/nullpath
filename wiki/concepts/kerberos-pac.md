---
title: Kerberos PAC (Privilege Attribute Certificate)
type: concept
created: 2026-09-06
updated: 2026-09-06
tags: [kerberos, active-directory, pac, protocol]
---

# Kerberos PAC (Privilege Attribute Certificate)

The **PAC** is a Windows-specific blob embedded inside Kerberos tickets
(TGT and, via delegation, service tickets) that carries the user's
**group memberships, SIDs, and account attributes**. The KDC signs it; a set
of **PAC signers** (the domain controllers, `krbtgt`, and a configurable list
of "Kerberos pac signer" accounts) co-sign it. Whoever can sign or read the
PAC can influence what a ticket claims about the user — which is why the PAC
is a recurring attack and detection surface.

## Structure (what's in it)

- **ClientInfo** — user name, user SID, (for PKINIT) `PAC_CREDENTIAL_INFO`
  carrying the user's **NT hash**.
- **GroupMembership** — the SIDs the user is a member of (this is what
  `whoami /groups` reflects after auth).
- **ServerCheckSum / signature header** — the KDC + PAC signer signatures
  over the above.

The PAC is what makes a Kerberos ticket *carry* AD identity. A forged or
tampered PAC is a forged identity — group SIDs in the PAC are what grant
access, so controlling the PAC's group list is privilege escalation.

## How it's abused

- **UnPAC the hash** — with PKINIT (certificate) pre-auth, the PAC includes
  `PAC_CREDENTIAL_INFO` with the user's NT hash. Recover the private key /
  plant a [[shadow-credentials]] cert and read it back — see
  [[pkinit-unpac-the-hash]].
- **PAC signer compromise** — if you control an account in the domain's
  "KDC PAC signers" set (or a DC), you can sign PACs for arbitrary group
  SIDs → mint a ticket that claims membership in Domain Admins without the
  full [[golden-silver-tickets]] krbtgt secret.
- **PAC size / checksum anomaly** — a hand-built ticket with an unusually
  small PAC (just the required fields) or a PAC signed by an unexpected
  account is a classic forged-ticket tell (see [[golden-silver-tickets]],
  [[diamond-ticket]]).
- **Delegation** — in [[s4u2self-s4u2proxy]]/unconstrained delegation the
  victim's TGT (and its PAC) is embedded in a service ticket; reading it
  yields the victim's groups and, with PKINIT, the hash.

## Commands

```powershell
# Inspect the PAC of a ticket you hold (Rubeus)
Rubeus.exe asktgt /user:attacker /getcredentials /ptt   # then:
Rubeus.exe triage
# Dump/decode a saved ticket's PAC:
Rubeus.exe ticket /ticket:<base64-ticket> /decode

# Check the domain's PAC signer accounts (who else can sign PACs)
Get-DomainObject -Identity "KRBTGT" -Properties *   # krbtgt is always a signer
# The "Kerberos pac signer" attribute lives on the domain object / DC
```

```bash
# Impacket ticketer / getTGT output shows the PAC; mitm6/kerberos tools decode it
# to read PAC_CREDENTIAL_INFO (NT hash) on PKINIT tickets:
#   (see pkinit-unpac-the-hash for the full flow)
```

## Detection

- **PAC size** — a TGT with a PAC far smaller than a normal one for that
  account (few groups) suggests a hand-forged ticket.
- **PAC signer** — a ticket signed by a PAC signer account that isn't the
  KDC/`krbtgt` is suspicious.
- **4768/4769** — correlate TGT/TGS requests with the resulting group
  membership; a service account suddenly appearing in Domain Admins' group
  list in the PAC is the event.
- **PKINIT 4768** from a non-CA client — see [[shadow-credentials]].

## Mitigations

- Keep the **PAC signer set minimal** (only DCs + `krbtgt`); audit who is a
  signer.
- Alert on small/anomalous PAC sizes and unexpected PAC signers.
- [[gmsa]] and [[ad-tiering-and-hardening]] limit the blast radius of a
  compromised signer.

## Links

- [[pkinit-unpac-the-hash]] — PAC_CREDENTIAL_INFO → NT hash recovery
- [[golden-silver-tickets]], [[diamond-ticket]], [[sapphire-ticket]] — forged tickets must carry a valid-looking PAC (Sapphire injects a real one)
- [[ms14-068]] — the classic PAC-signature-validation forgery (CVE-2014-6324)
- [[nopac]] — sAMAccountName spoofing → S4U2self ticket as a DC (CVE-2021-42287)
- [[kerberos-authentication]] — where the PAC sits in the TGT/TGS flow
- [[krbtgt]] — a default PAC signer
- [[pass-the-key]] — fresh tickets carry a KDC-signed PAC (why PtK is quieter)
- [[krb5pac]] — the PAC manipulation library (UnPAC / SID History / RBCD forgery)

## References

- [MS-DPAPI / PAC (PAC) specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kerb)
- [ired.team: Kerberos attacks (PAC)](https://www.ired.team/active-directory-kerberos-abuse/kerberos-attacks)
- [InternalAllTheThings: Kerberos](https://swisskyrepo.github.io/InternalAllTheThings/)
