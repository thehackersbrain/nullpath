---
title: "DCSync — replicate any AD secret via MS-DRSR"
type: concept
created: 2026-09-06
updated: 2026-09-07
tags: [active-directory, dcsync, ms-drsr, replication, krbtgt, credential-access]
---

# DCSync — replicate any AD secret via MS-DRSR

**DCSync** abuses the legitimate **MS-DRSR** (Directory Replication Service
Remoting) protocol to make a real Domain Controller **"replicate" secrets to
you** — NTLM hashes, Kerberos RC4/AES keys, password history, and the
`krbtgt` secret — for **any account in the domain**. No code execution on a
DC, no `ntds.dit` access, no VSS: just the **right AD permissions**. It's the
standard, cleanest way to obtain the [[krbtgt]] secret to forge a
[[golden-silver-tickets|Golden Ticket]], and it's the remote equivalent of an
offline [[ntds-dit]] dump. The raw source summary lives in
[[dcsync]] (sources); this is the working concept page.

## Why it works

- AD DCs **replicate** the full directory (including password hashes/keys) to
  each other over **MS-DRSR** (the `DSGetNCChanges` / partial-secrecy
  replication interfaces). This is *normal, trusted* traffic.
- The replication rights are **ACLs on the domain object**: the extended
  rights **`DS-Replication-Get-Changes`** (a specific partition) and
  **`DS-Replication-Get-Changes-All`** (all partitions). Whoever holds both
  can ask a DC to "replicate" the secrets of **any object** — the DC treats
  the request as coming from another DC.
- **Who normally holds these rights**: Domain Admins, Enterprise Admins, the
  DCs themselves (machine accounts), the **Entra/Azure AD Connect** service
  account, and any account/group you've (mis)granted them to. A **machine
  account with DCSync rights is a goldmine** (see [[service-account]] and the
  [[esc8-ntlm-relay-adcs]] / [[path-esc8-petitpotam-to-dcsync]] chain).

## What you get

- **NTLM hashes** for any user/computer account → [[pass-the-hash-and-ticket|PtH]]
  / lateral movement.
- **Kerberos RC4 (ntlm) + AES (aes128/aes256) keys** for any account →
  [[pass-the-key|PtK]] / forge tickets directly.
- **`krbtgt`** → a **[[golden-silver-tickets|Golden Ticket]]** (domain-wide,
  durable).
- **Password history** (the last N hashes) → crack older ones, or PtH as a
  previous password.
- **gMSA secrets** ([[gmsa]]) and **trust account keys** ([[ad-trust-attacks]])
  — DCSync exposes those too (they're directory objects with secrets).

## The prerequisite (enumerating the rights)

```powershell
# Who can DCSync? (the domain object's replication ACLs)
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
  Where-Object { $_.ObjectAceType -match "DS-Replication-Get-Changes" }
```
BloodHound exposes this as the **`GetChanges`** / **`GetChangesAll`** edges
from a principal to the domain. A machine account (or a service account)
holding these edges is the classic **DCSync foothold**.

## How it's run

```bash
# Impacket secretsdump — single account (the krbtgt grab)
secretsdump.py corp.local/attacker:'Pass'@dc01 -just-dc-user krbtgt
# Pass-the-hash instead of a password
secretsdump.py -hashes :<nthash> corp.local/attacker@dc01 -just-dc-user krbtgt

# Full-domain dump (the wire-equivalent of ntds.dit)
secretsdump.py corp.local/attacker:'Pass'@dc01 -just-dc
```
```powershell
# Mimikatz
lsadump::dcsync /domain:corp.local /user:krbtgt
lsadump::dcsync /domain:corp.local /user:Administrator
```
See [[secretsdump]] and [[mimikatz]] for the tool pages.

## Red-team notes (OPSEC)

- **Pull only what you need.** `-just-dc-user krbtgt` (or the one target
  account) is a single, quiet replication; a full `-just-dc` domain dump is a
  large 4662 burst and grabs *every* secret — often broader than scope allows.
- **Operate from a plausible principal.** A **machine account** or service
  account that legitimately holds the replication rights is the ideal context;
  a workstation user account asking a DC to replicate is the anomaly.
- **Prefer DCSync to an [[ntds-dit]] dump** when you only need `krbtgt` — no DC
  shell, no VSS, no on-disk artefact; just the ACL and one DRSUAPI call.
- **Assume replication honeytokens.** A canary account granted replication
  rights fires the moment you DCSync it ([[honeytokens]]) — validate targets.
- **Run remotely** over the tunnel (`secretsdump.py -hashes :<nt> …`); the
  4662 footprint still lands on the DC, so keep the account count minimal.

## Detection

- **Event 4662** (object permissions) on the **domain object** with the
  **replication GUIDs** (`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` for
  Get-Changes, `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` for Get-Changes-All),
  where **`SubjectUserName` is not a DC or known sync account** — the
  high-fidelity tell.
- **Correlate with 4624 Logon Type 3** (NTLM) from a non-DC host to the DC,
  or with a 4768/4769 right after (the attacker now uses the keys).
- **MS-DRSR traffic from a non-DC IP** (a workstation asking a DC to
  replicate).
- **Honey accounts with replication rights** ([[honeytokens]]) — a DCSync of
  a honeypot is an instant tripwire.

## Mitigations

- **Least-privilege the domain object ACL** — `Get-Changes`/`Get-Changes-All`
  should be held *only* by DCs + the intended sync principals (audit and
  prune; don't grant it to a broad admin group). See
  [[ad-tiering-and-hardening]], [[ad-tier-model]].
- **Restrict DRSUAPI** at the network/host level (non-DCs shouldn't reach
  `drsuapi`/MS-DRSR on a DC).
- **If DCSync is suspected, rotate `krbtgt` twice** ([[krbtgt]]) — invalidates
  any Golden Ticket minted from the exposed secret.
- **Alert on** the 4662 replication-GUID pattern from a non-DC principal.

## Relation to the rest of the wiki

- **The "get everything" primitive** — DCSync is the *acquisition* step that
  feeds [[golden-silver-tickets]] (krbtgt), [[pass-the-hash-and-ticket]]
  (user hashes), [[pass-the-key]] (AES keys), [[gmsa]] (gMSA secrets), and
  [[ad-trust-attacks]] (trust keys).
- **The complement to the offline dump** — an offline [[ntds-dit]] VSS dump
  gives the same secrets without the replication ACLs (but needs a DC shell +
  VSS); DCSync needs the ACLs but no DC shell.
- **The target of coercion** — a coerced **machine account** with DCSync
  rights is the end of the [[esc8-ntlm-relay-adcs]] /
  [[ntlm-relay-coercion]] chains.

## Links

- [[krbtgt]] — the headline DCSync target
- [[golden-silver-tickets]] — what the krbtgt DCSync enables
- [[secretsdump]] — the impacket tool that runs it
- [[mimikatz]] — the `lsadump::dcsync` implementation
- [[ntds-dit]] — the offline (no-ACL) alternative
- [[ad-structure]] — the domain object whose ACLs gate DCSync
- [[domain-controller]] — the server that "replicates" to you
- [[pass-the-hash-and-ticket]], [[pass-the-key]] — what the hashes/keys do
- [[honeytokens]] — the DCSync tripwire
- [[ad-tiering-and-hardening]] — the ACL-audit + krbtgt-rotation remediation
- [[dasync]] — a Python DCSync implementation (alternative to secretsdump)
