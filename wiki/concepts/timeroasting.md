---
title: "Timeroasting (unauthenticated computer-account roasting via MS-SNTP)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [kerberos, active-directory, credential-access, offline-cracking, unauthenticated]
---

# Timeroasting

**Timeroasting** (Tom Tervoort / Secura, 2023) is an **unauthenticated** offline
attack on **computer-account** passwords that abuses the legacy **MS-SNTP**
authentication extension in Windows time sync. A client can ask a DC for a signed
time response, and the DC computes the MAC using a key derived from the **machine
account's password hash (MD4/NT hash)** — **without authenticating the
requester** and identifying the account only by its **RID**. So anyone who can
reach UDP/123 on a DC can request, for any computer RID, a response containing a
**crackable hash of that machine's password** — no domain creds required. It's the
[[kerberoasting]]/[[as-rep-roasting]] idea moved to NTP and stripped of the need
to authenticate first.

## Why it (sometimes) works despite random machine passwords

- Machine account passwords are normally **random 120-char** secrets → practically
  uncrackable. So Timeroasting is usually *not* a mass-cred win against standard
  domain-joined Windows.
- It bites where passwords **aren't** default-random:
  - Accounts an admin **manually set** to a weak/known password.
  - **Non-Windows / appliance** computer accounts, IoT, or scripted joins with
    predictable passwords.
  - Accounts whose password was **reset and not rotated**, or `pre-created`
    computer objects (`pre2k`-style) with password == lowercased sAMAccountName.
- Independently, it's a stealthy **unauthenticated enumeration** primitive: valid
  computer RIDs respond, so you can sweep the RID space with zero auth.

## Command

```bash
# Timeroast (SecuraBV) — sweep RIDs against a DC, collect hashes
python3 timeroast.py <dc-ip> -o hashes.txt

# Crack offline — hashcat mode 31300 (MS-SNTP / Timeroast)
hashcat -m 31300 hashes.txt wordlist.txt
```

## Red-team notes (OPSEC)

- **Lowest-noise roast in the toolbox.** It's **NTP traffic to UDP/123**, not
  Kerberos or NTLM — it generates **no 4768/4769/4625 logon events** and no
  authentication footprint at all. For pre-auth recon or a quiet cred attempt on a
  new engagement, it's near-invisible.
- **Set expectations**: treat it as a *targeted* check for weak/appliance machine
  passwords and an unauth RID enumerator, not a domain-wide cracking play — most
  hashes won't crack.
- Pairs with predictable-password (`pre2k`-style) hunting; a cracked machine
  account can enable [[golden-silver-tickets|silver ticket]] forging for that
  host's services or [[resource-based-constrained-delegation|RBCD]] if you can
  also add/modify computer objects.

## Detection

- **Very hard** — there are no authentication logs. Detection means monitoring
  **MS-SNTP request volume/patterns** on the DC's NTP service (a burst of signed
  time requests across many RIDs from one source), which most environments don't
  log.
- Mitigations: ensure machine account passwords are **random and rotated**
  (default), remove/rotate weak manually-set computer passwords, restrict who can
  reach the DC's NTP, and disable the legacy MS-SNTP path where feasible.

## Links

- [[kerberoasting]] / [[as-rep-roasting]] — the authenticated offline-roast siblings
- [[kerberos-preauth]] — the pre-auth concept this analogizes (but Timeroast needs no auth)
- [[hashcat]] — mode 31300; [[credential-dumping]] for what a cracked machine key enables
- [[golden-silver-tickets]] / [[resource-based-constrained-delegation]] — downstream use of a machine secret
