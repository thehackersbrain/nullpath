---
title: "Bronze Bit (CVE-2020-17049) — S4U2proxy forwardable-flag bypass"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, active-directory, delegation, cve, privilege-escalation]
---

# Bronze Bit (CVE-2020-17049)

**Bronze Bit** abuses constrained delegation ([[kerberos-delegation]],
[[s4u2self-s4u2proxy]]) by tampering with the **forwardable flag** of the service
ticket used in **S4U2proxy**. Normally the KDC only performs S4U2proxy if the
presented S4U2self ticket is **forwardable**, and it makes tickets
**non-forwardable** for accounts that shouldn't be delegated (members of
**Protected Users**, or accounts flagged *"sensitive and cannot be
delegated"*). Because that S4U2self ticket is **encrypted with the service
account's own key** — which the attacker controlling the delegating service
already knows — the attacker can **decrypt it, flip the forwardable bit on, and
re-encrypt**, defeating both protections.

## What it unlocks

Given control of a service account configured for **constrained delegation**
(or [[resource-based-constrained-delegation|RBCD]]) and knowledge of its
password/AES key, Bronze Bit lets you:

1. **Impersonate users that are supposed to be un-delegatable** — Protected
   Users and "sensitive" accounts (including, often, Domain Admins), which
   otherwise defeat S4U-based impersonation.
2. Complete the S4U2proxy even when the KDC would have refused the
   non-forwardable ticket — turning a delegation edge you'd think was blocked
   into a working impersonation to the target SPN.

## Command (Impacket)

```bash
# getST.py implements it with -force-forwardable (flip the bit before S4U2proxy):
getST.py -spn cifs/target.corp.local -impersonate Administrator \
  -force-forwardable \
  corp.local/svc_deleg -hashes :<svc-nthash>

export KRB5CCNAME=Administrator@cifs_target.ccache
nxc smb target.corp.local --use-kcache        # impersonated access
```

The `-force-forwardable` flag is the Bronze Bit; without it, S4U2proxy against a
protected target fails.

## Red-team notes (OPSEC)

- **It removes the "sensitive/Protected Users" safety net** that teams rely on to
  protect Tier-0 accounts from delegation abuse — so a constrained-delegation or
  RBCD edge you'd otherwise skip (because the juicy target is protected) may still
  be exploitable. Re-check delegation paths with Bronze Bit in mind.
- Needs the **service account's key** and a delegation config — it's an
  amplifier on [[s4u2self-s4u2proxy]] / [[resource-based-constrained-delegation]],
  not a standalone entry.
- Patched by the **Nov 2020** update (KDC enforces the flag / `EnforceKDCFlags`);
  it lives on in unpatched or partially-patched estates.

## Detection

- **4769** S4U2proxy activity for a delegating service reaching a **Protected
  Users** / sensitive account — that combination should be impossible and is the
  signal.
- Delegation use targeting Tier-0 principals; correlate with the delegating
  account's normal behavior.
- Mitigations: **patch** CVE-2020-17049; put Tier-0 accounts in **Protected
  Users** *and* mark them "sensitive and cannot be delegated" (still audit,
  since Bronze Bit defeats them pre-patch); minimize constrained-delegation and
  RBCD ([[ad-tiering-and-hardening]]).

## Links

- [[s4u2self-s4u2proxy]] — the S4U flow whose ticket flag is flipped
- [[kerberos-delegation]] / [[resource-based-constrained-delegation]] — the delegation edges it amplifies
- [[kerberos-pac]] — the ticket internals; [[kerberos-encryption-types]] for the key that decrypts the S4U2self ticket
- [[pass-the-hash-and-ticket]] — using the resulting impersonation ticket
