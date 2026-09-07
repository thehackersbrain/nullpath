---
title: "Attack Path: DCSync AES128 → Diamond Ticket → Durable Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, diamond-ticket, privilege-escalation, persistence]
---

# Attack Path: DCSync AES128 → Diamond Ticket → Durable Domain Admin

The **[[diamond-ticket]]** play: when you suspect the defender may rotate
`krbtgt` (or you want access that outlives a rotation), you forge the TGT with
the **AES128** key of `krbtgt` instead of AES256. Because AD retains the
*previous* `krbtgt` password for ~10h after a rotation (the KDC validates
against current + previous), an **old-AES128-signed TGT keeps working** across
a rotation where an AES256 Golden Ticket's assumptions are re-examined — and
AES128 (`0x11`) is quieter than RC4 (`0x17`) on an AES domain. This is the
"durable DA" variant of the standard Golden Ticket path.

## Chain

```
You (some foothold with a DCSync right)
  --DCSync krbtgt--> capture the AES128 key (aes128-cts-hmac-sha1-96)
  --Diamond Ticket (Rubeus asktgt /aes128)--> TGT for Administrator signed w/ old AES128
  --(survives a single krbtgt rotation)--> durable Domain Admin
```

## Prerequisites / what signals this path exists

- A **DCSync right** to pull `krbtgt` — confirm you hold
  `GetChanges`/`GetChangesAll` (BloodHound DCSync edge) before committing.
- The domain still has the **AES128 key present** for `krbtgt` (most do; an
  AES256-only domain has already removed the Diamond's lever).

```powershell
# Confirm the DCSync right
Get-DomainObject -Identity "corp.local" -Properties * | Select-String "GetChangesAll"
# or BloodHound: <you> -> GetChangesAll (the DCSync edge)
```

See [[dcsync]] for the replication right, [[diamond-ticket]] for the forgery,
[[kerberos-encryption-types]] for the etype context.

## Step 1 — DCSync krbtgt, grab the AES128 key

```bash
secretsdump.py -k -no-pass corp.local/<dcsync-user>@dc01.corp.local -just-dc-user krbtgt
# output lines:
#   aes256-cts-hmac-sha1-96 : <64-hex>
#   aes128-cts-hmac-sha1-96 : <32-hex>   <-- the Diamond Ticket key
#   rc4_hmac_nt             : <nt-hash>
```

**Verify:** you captured the `aes128-cts-hmac-sha1-96` (32-hex) value. If
there's no AES128 line, the domain is AES256/RC4-only — the Diamond's rotation
resistance is weaker; fall back to a standard
[[golden-silver-tickets|Golden Ticket]].

## Step 2 — Forge the Diamond Ticket (AES128)

```powershell
Rubeus.exe asktgt /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /aes128:<32-hex> /sids:S-1-5-21-...:512 /ptt
Rubeus.exe triage        # TGT for Administrator, etype aes128
whoami /all              # corp.local\administrator + 512
```

The TGT/PAC is signed with the **AES128** key — that's the "downgrade."
See [[diamond-ticket]].

**Verify:** `whoami /all` lists `corp.local\administrator`. Note the ticket's
enctype is AES128 (the tell, and the feature).

### Failure modes & fallbacks
- **No AES128 key in the DCSync output** — domain is AES256/RC4-only; use a
  standard Golden Ticket (`/aes256` or `/rc4`).
- **Ticket rejected (checksum)** — you supplied the wrong key/enctype pair;
  rebuild with the exact key the DC will validate against.
- **Domain forces AES256 for TGTs** — the AES128 TGT may be rejected on a
  strict domain; test against a service before relying on it.

## Step 3 — Why it's "durable" (the rotation window)

After the defender rotates `krbtgt` once, AD keeps the **previous** password
for ~10h. Your AES128-signed TGT (built from the *old* key) remains valid
through that window — and if the rotation was done as a single (not double)
rotation, you can keep working. See [[krbtgt]] for the double-rotation
remediation this is designed to slip past.

**Verify durability (if you can):** after a suspected rotation, re-test with
`whoami /userid` / a fresh service call using the *same* injected ticket — if
it still authenticates, the Diamond held.

## Step 4 — Use / persist

```powershell
# Use the Diamond TGT for DCSync / lateral / persistence
psexec.py -k -no-pass corp.local/Administrator@dc01.corp.local
# Set up durable access (see ad-persistence)
```

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (DCSync) | 4662 on the domain object (GetChanges+GetChangesAll) | a non-DC account replicating |
| 2 (Diamond) | 4768 TGT with **aes128** (`0x11`) for a privileged account | an AES128 TGT on an AES256 domain |
| 3 (survives rotation) | the same TGT working *after* a `krbtgt` rotation | a DA ticket outliving the rotation window |

## Cleanup notes
- DCSync's trail is 4662; the Diamond TGT is memory-only (dies with the
  session).
- If caught, expect `krbtgt` to rotate **twice** — after the second rotation
  (and the 10h window lapsing) the old-AES128 key is gone and the Diamond
  Ticket fails until rebuilt from the new key.
- The planted identity is a TGT, not an AD object — nothing to remove in AD.

## Related
- [[diamond-ticket]] — the forgery primitive (step 2)
- [[dcsync]] — the key source (step 1)
- [[krbtgt]] — the rotation model this slips past
- [[kerberos-encryption-types]] — the AES128 downgrade context
- [[golden-silver-tickets]] — the standard (non-durable) contrast
- [[ad-persistence]] — durable access once you're DA
