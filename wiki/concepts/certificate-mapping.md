---
title: "Certificate Mapping (strong vs weak; ESC9/ESC10)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, pki, pkinit, kerberos]
---

# Certificate Mapping

When a certificate is presented for **PKINIT** / Schannel logon, the DC must
map it to an AD account. *How* it maps is the ESC9/ESC10 surface and the point
Microsoft's **May 2022 patch (KB5014754, CVE-2022-34691)** hardened.

## Implicit (weak) vs explicit (strong)

- **Implicit mapping** — the cert's **SAN UPN/DNS** is matched to an account.
  Weak: whoever controls a SAN controls the identity.
- **The SID binding (`szOID_NTDS_CA_SECURITY_EXT`)** — post-patch, issued certs
  embed the requester's **SID**, and DCs in **Full Enforcement** require it to
  match. A template lacking this extension is the **[[esc9]]** condition.
- **Strong explicit mapping** — `altSecurityIdentities` on the account with a
  strong format (Issuer+Serial, SKI, SHA1-PubKey). Weak explicit formats
  (Issuer+Subject, UPN) are **[[esc10]]** / ESC14 abuse.

## Enforcement modes

`StrongCertificateBindingEnforcement` (DC registry): `0` = disabled (fully
abusable), `1` = compatibility (default, still abusable in cases), `2` = full
enforcement. Many domains sit at `1`, which keeps ESC9/ESC10 alive.

## Red-team notes (OPSEC)

- Check enforcement + template SID extension with `certipy find`; ESC9/ESC10
  are viable exactly when a template omits the SID ext **or** enforcement is
  `<2` and a weak `altSecurityIdentities` can be written ([[acl-abuse]]).
- The abuse chains through [[shadow-credentials]] / a UPN swap; the tell is a
  4768 cert-preauth for an account that mismatches the cert's real requester.

## Links

- [[esc9]], [[esc10]], [[ad-cs-esc-attacks]]
- [[pkinit-unpac-the-hash]], [[kerberos-authentication]]
- [[certified-pre-owned]]
