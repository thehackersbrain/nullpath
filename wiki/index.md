---
title: Index
type: note
created: 2026-06-12
updated: 2026-09-07
tags: [meta]
---

# Index

Catalog of all wiki pages. Updated on every ingest. The agent reads this
first when answering queries.

## Sources

- [[kerberoasting]] — crack TGS tickets to recover service account
  passwords (Event 4769, RC4 downgrade)
- [[as-rep-roasting]] — crack AS-REP for accounts with Kerberos pre-auth
  disabled (Event 4768, preauth type 0)
- [[dcsync]] — abuse MS-DRSR replication rights to dump password
  hashes/keys for any account, including krbtgt
- [[pass-the-hash-and-ticket]] — reuse stolen NTLM hashes (PtH) or Kerberos
  tickets (PtT) for lateral movement, no cracking needed
- [[golden-silver-tickets]] — forge TGTs (Golden, via krbtgt secret) or TGSs
  (Silver, via service account secret) offline
- [[kerberos-delegation-abuse]] — unconstrained/constrained/RBCD delegation
  misconfigurations for impersonation and privilege escalation
- [[esc8-ntlm-relay-adcs]] — PetitPotam coercion → NTLM relay to AD CS →
  machine cert → DCSync (full ESC8 chain)
- [[rbcd-via-ntlm-relay]] — credential-less RBCD via mitm6/WPAD relay to
  LDAPS (dirkjanm "worst of both worlds")
- [[shadow-credentials]] — write msDS-KeyCredentialLink to plant a cert,
  authenticate via PKINIT, UnPAC the NT hash
- [[ad-forest-trust-attacks]] — SID filtering, TREAT_AS_EXTERNAL, and
  CVE-2020-0665 forest trust transitivity bypass
- [[gpo-abuse]] — abuse GenericWrite/WriteDacl on GPOs for domain-wide
  code execution (SharpGPOAbuse, GPOHound, etc.)
- [[ad-persistence-dcshadow-skeletonkey-adminsdholder]] — DCShadow,
  Skeleton Key, DSRM backdoor, AdminSDHolder/SDProp persistence
- [[pkinit-unpac-the-hash]] — PKINIT mechanics and recovering NT hashes
  from PAC_CREDENTIAL_INFO via S4U2Self+U2U

### Red-team reference sources

- [[certified-pre-owned]] — SpecterOps AD CS whitepaper; the ESC1-8 taxonomy
- [[the-hacker-recipes]] — ShutdownRepo AD attack cookbook (tool-forward recipes)
- [[adsecurity-org]] — Sean Metcalf's Kerberos attack/defense research
- [[harmj0y-blog]] — Will Schroeder's Kerberoasting/delegation/ACL research
- [[dirkjanm-blog]] — Dirk-jan Mollema's mitm6/RBCD-relay/PKINIT research

## Concepts

- [[kerberos-authentication]] — core AS-REQ/AS-REP, TGS-REQ/TGS-REP flow;
  hub page linking every attack to its protocol stage
- [[krbtgt]] — the account whose secret signs all TGTs; central to
  DCSync/Golden Ticket
- [[ntlm]] — legacy challenge-response protocol abused by Pass-the-Hash
- [[kerberoasting]] — request TGSs for SPN accounts + offline-crack the
  service password (4769 bursts; gMSA defeats the crack, not the identity)
- [[as-rep-roasting]] — crack accounts with pre-auth disabled (4768 type-0;
  GetNPUsers/Rubeus asrep; the AS-REQ-stage sibling of kerberoasting)
- [[dcsync]] — replicate any AD secret (incl. krbtgt, gMSA, trust keys) via
  MS-DRSR with Get-Changes/Get-Changes-All (4662 replication GUIDs)
- [[golden-silver-tickets]] — forge a TGT (Golden, krbtgt secret) or TGS
  (Silver, service secret) offline; detection tells + krbtgt double-rotation
- [[kerberos-delegation]] — the UDE/CDE/RBCD hub: the three attributes
  (TrustedForDelegation / msDS-AllowedToDelegateTo /
  msDS-AllowedToActOnBehalfOfOtherIdentity), 4769-R0 detection
- [[gmsa]] — auto-rotated service secret: mechanics + the attack surface
  (LSASS dump / DCSync / reset); the most-repeated mitigation
- [[ad-tiering-and-hardening]] — tiered admin model, Protected Users,
  Credential Guard, LAPS, AES enforcement, honeytokens — the recurring
  hardening baseline across all techniques
- [[acl-abuse]] — GenericAll/WriteDacl/WriteOwner/GenericWrite object
  control abuse (BloodHound edges)
- [[ad-cs-esc-attacks]] — AD CS ESC1-15 certificate template/CA
  misconfigurations
- [[ntlm-relay-coercion]] — NTLM relay + coercion (PetitPotam, mitm6/WPAD)
  and its relay targets
- [[sccm-abuse]] — SCCM/MECM credential extraction and lateral movement
- [[wds-mdt-discovery]] — WDS/MDT SCP discovery and unattend.xml credential
  harvesting
- [[shadow-credentials]] — msDS-KeyCredentialLink key-trust abuse for
  passwordless takeover + NT hash recovery
- [[ad-trust-attacks]] — forest trust SID filtering and its bypasses
- [[gpo-abuse]] — GPO edit-rights as a domain-wide code execution primitive
- [[ad-persistence]] — DCShadow/Skeleton Key/AdminSDHolder domain-dominance
  persistence
- [[pkinit-unpac-the-hash]] — certificate-based Kerberos pre-auth and NT
  hash recovery, the hub linking AD CS attacks back to NTLM
- [[pass-the-key]] — reuse a captured AES/RC4 Kerberos key to mint a fresh,
  legitimate TGT (quieter than PtH/PtT/Golden)
- [[diamond-ticket]] — Golden Ticket forged with the AES128 krbtgt key to
  survive a single `krbtgt` rotation
- [[kerberos-pac]] — the Privilege Attribute Check blob the KDC signs; PAC
  forging, PAC CREDENTIAL_INFO NT-hash recovery
- [[kerberos-encryption-types]] — RC4 (0x17) vs AES128 (0x11) vs AES256
  (0x12): the etype downgrade/upgrade that drives roasting and forgery
- [[kerberos-preauth]] — AS-REQ pre-authentication; disabled → AS-REP
  roasting, and the preauth types
- [[s4u2self-s4u2proxy]] — the S4U2Self/S4U2Proxy service-for-user /
  service-for-service primitives under delegation
- [[honeytokens]] — AD canary credentials/certs/objects that fire on touch
- [[ntds-dit]] — the DC's directory database; offline/online dump for all
  account secrets
- [[lsass]] — the LSASS credential cache; the in-memory hash/key/password
  source
- [[sam-database]] — the local SAM; offline NTLM-hash store per machine
- [[laps]] — Local Admin Password Solution; per-machine admin password and
  who can read it
- [[sid-history]] — the `sidHistory` attribute; write a privileged group SID
  to escalate
- [[mitm6-ipv6-relay]] — the IPv6 MITM/relay (WPAD → LDAPS) that forces
  credential-less NTLM for RBCD/AD CS
- [[krbrelay]] — the Kerberos+NTLM "worst of both worlds" relay
- [[resource-based-constrained-delegation]] — RBCD
  (`msDS-AllowedToActOnBehalfOfOtherIdentity`): write the attribute on a
  machine, mint a TGS to it, lateral as yourself
- [[service-principal-name]] — the SPN that ties an AD account to a Kerberos
  service; the Kerberoast target surface
- [[pass-the-hash-and-ticket]] — reuse a stolen NTLM hash (PtH) or
  Kerberos ticket (PtT) directly to authenticate (no cracking)
- [[overpass-the-hash]] — use a known NT hash to request a real (non-forged)
  TGT via AS-REQ (the "overpass" of pass-the-hash)
- [[pass-the-cert]] — authenticate to the KDC with a stolen/valid X.509 cert
  (PKINIT) without the private-key password
- [[smb]] — the file/printer sharing protocol: signing (the relay control),
  lateral exec (psexec/wmiexec), the SMBv1/anonymous surface
- [[ldap]] — the directory protocol: enumeration + the relay target for RBCD/
  ACL/ownership writes; signing + channel binding as the controls
- [[ccache]] — the Kerberos ticket wallet (.ccache/.kirbi): dump/inject/forge
  the identity a tool authenticates as
- [[service-account]] — user vs service vs machine account taxonomy; which
  attack applies to which account (roast/RBCD/silver/coerce)
- [[tgt-tgs]] — TGT vs TGS: the two ticket types, their keys/lifetimes, and
  which attacks hit which (Golden/Silver/PtK/Kerberoast/RBCD)
- [[ad-tier-model]] — the Tier 0/1/2 trust model itself: what's in each tier,
  the trust-flow rule, PAWs; the frame every path note is measured against
- [[remote-execution]] — Windows remote-exec transports (psexec/wmiexec/
  smbexec/atexec/WinRM/PSRemoting/RDP) + the detection per channel
- [[printer-bug]] — CVE-2021-34527 Print Spooler RPC coercion (the spooler
  side of the coercion family, alongside PetitPotam)
- [[wpad]] — WPAD autoconfig: the ambient, no-prompt NTLM capture
  (evilwpad / mitm6) that feeds RBCD relays
- [[domain-controller]] — what a DC is, the five FSMO roles, DSRM; why DC =
  Tier 0 and the DC as the end-game target
- [[ad-structure]] — the AD hierarchy glossary: objects/OUs/domain/tree/
  forest/site, SIDs, DNs; why the structure dictates the attacks
- [[dcshadow]] — persist via a rogue AD replication partner (or a shadow DC /
  DSRM backdoor); replication-delivered writes that mute the LDAP audit
- [[skeleton-key]] — the DC LSASS memory patch that accepts a static master
  key; survives krbtgt rotation
- [[pki-and-ad-cs-architecture]] — CAs, templates, enrollment agents,
  NTAuth: the AD CS moving parts before the ESCs
- [[certificate-templates]] — template flags/EKUs and which flags make a
  template dangerous (the ESC flag table)
- [[certificate-mapping]] — how a cert maps to an AD account (implicit vs
  explicit, SID binding, enforcement modes)
- [[ntauthcertificates]] — the forest client-auth trust store (rogue CA =
  domain-wide forgery)
- [[golden-certificate]] — the cert analog of the golden ticket (CA key or
  rogue CA → PKINIT as anyone)
- [[esc1]] — enrollee-supplied SAN on a client-auth template (the classic)
- [[esc2]] — Any Purpose / no-EKU template
- [[esc3]] — Certificate Request Agent (enroll on behalf of)
- [[esc4]] — writable certificate-template ACL
- [[esc5]] — CA object / CA server ACL (ManageCA via WriteDacl)
- [[esc6]] — EDITF_ATTRIBUTESUBJECTALTNAME2 (template- or CA-wide SAN)
- [[esc7]] — ManageCA / ManageCertificates (CA management rights)
- [[esc8]] — NTLM relay to AD CS web enrollment (PetitPotam → DCSync)
- [[esc9]] — template omits the security extension (no SID binding)
- [[esc10]] — weak certificate binding (CertificateMappingMethods)
- [[esc11]] — NTLM relay to RPC ICPR enrollment
- [[esc12]] — CA admin key access (CVE-2022-26923 / key in the open)
- [[esc13]] — issuance policy linked to a privileged group
- [[esc14]] — weak explicit mapping via altSecurityIdentities
- [[esc15]] — EKUwu / CVE-2024-49019 (V1 template default policy)
- [[unconstrained-delegation]] — UDE abuse mechanics: TGT capture → TGS to
  DC → UnPAC the DC hash → DCSync
- [[kerberos-event-ids]] — 4768/4769/4770/4771 + 4776/4648/4624: the field
  values and the per-attack tells
- [[llmnr-nbt-ns-poisoning]] — LLMNR/NBNS name-resolution spoofing → NTLM
  capture/relay (the Responder technique)
- [[credential-dumping]] — the on-host secret stores map (LSASS/SAM/NTDS/DPAPI)
  and online vs offline dump postures
- [[redteam-ad-methodology]] — the operational kill-chain arc of an AD
  engagement (recon → foothold → pivots → dominance → persistence)
- [[situational-awareness]] — post-foothold AD recon: who/what/where before
  you move
- [[c2-and-pivoting-ad]] — operating AD tradecraft from a Linux host over a
  tunnel (tool transport, proxychains, pivoting)
- [[defense-evasion-ad]] — EDR/AMSI/ETW evasion for AD tooling (Rubeus,
  Certipy, Mimikatz, SharpHound)
- [[opsec-ad-tradecraft]] — operating without tripping the SOC (the cross-
  technique OPSEC hub)
- [[bloodhound-opsec]] — quiet SharpHound collection tradecraft
- [[ticket-and-credential-opsec]] — ticket/credential handling hygiene on an
  engagement (store, use, burn, clean up)
- [[reverse-engineering-workflow]] — static + dynamic malware analysis arc
  (triage → decompile → run/dump → detection write-up)
- [[pe-executable]] — the Windows PE format: headers, IAT, sections, entropy
  — the structure anti-analysis hides
- [[shellcode]] — position-independent x86/x64 payloads: PEB-walk bootstrap,
  calling convention, stack alignment, null-byte avoidance
- [[api-hashing]] — resolve APIs by name-hash (djb2) without strings; the
  string-free import table
- [[process-injection]] — running code in another process: remote thread,
  APC, hollowing, module stomping, thread hijack, callback injection
- [[windows-syscalls]] — direct `Nt*`/`syscall` calls past the user-mode
  hook (the EDR hook the API-skip beats, and the layer that survives it)
- [[anti-debugging]] — the debugger checks (PEB flags, IsDebuggerPresent,
  timing, Int3) and how they're defeated
- [[anti-analysis]] — the VM/sandbox checks (CPUID, uptime, MAC, count) and
  the time-bomb/multi-stage that beat the 60s run
- [[packer-unpacking]] — stub + payload + OEP; finding the OEP, dumping the
  unpacked image, the anti-unpacking race
- [[amsi]] — the PowerShell/.NET script-scan API and its bypasses (patch,
  hook, the clean-result anomaly)
- [[etw]] — the kernel event-bus EDRs subscribe to; session-kill / provider-
  disable / callback-removal and the VBS counter
- [[beaconing]] — the C2 heartbeat: periodicity, jitter, the small-request/
  command-response shape, and how it's detected
- [[windows-privilege-escalation]] — Windows local privesc hub: foothold →
  local admin → the AD chain it unlocks (enumeration, technique map, AD
  bridge, detection)
- [[uac-bypass]] — defeating UAC to gain an elevated token (the low-priv →
  admin rung on a logged-on box)
- [[token-privilege-escalation]] — stealing/impersonating a higher-priv
  process token (the SeImpersonate + SYSTEM-pipe model behind the printer bug)
- [[service-privesc]] — writable service binary / binPath / SCOM / unquoted
  path → admin
- [[scheduled-task-abuse]] — writable scheduled task (or `atexec`/`schtasks`
  as a privesc + lateral vehicle)
- [[named-pipe-hijacking]] — impersonate over a pipe a SYSTEM process opens
  (the primitive the Potato family and the printer bug drive)
- [[dll-hijacking-sideloading]] — DLL search-order / sidecar-DLL abuse to run
  under a trusted parent
- [[environment-variable-attack]] — PATH/PATHEXT manipulation to execute in a
  privileged context
- [[potato-family]] — Coerced Pipe Impersonation (Rotten/God/Juicy/ODD/BOOM):
  any local user → SYSTEM on modern Windows
- [[windows-local-persistence]] — host-level persistence (Run keys, services,
  tasks, WMI, COM, IFEO) to keep the local foothold alive

- [[ad-enumeration]] — remote AD enum cheat-cards from the Linux operator host
  (nxc/ldapsearch/bloodhound-python/certipy find over the tunnel)
- [[password-spraying]] — low-and-slow one-password-many-accounts guessing;
  lockout-aware first foothold (4625/4771; kerbrute/nxc)
- [[kerberos-double-hop]] — why the second hop from a WinRM/psexec shell fails
  and how to beat it (CredSSP, PtT injection, S4U)
- [[pivoting-and-tunneling]] — operator-side plumbing: ligolo-ng/chisel/SSH
  dynamic forwards + proxychains to route AD tooling into the target net

- [[dpapi]] — decrypt masterkeys → browser creds+cookies, Credential
  Manager/RDP/WiFi, and the domain DPAPI backup key for offline mass-decrypt
- [[mssql-abuse]] — xp_cmdshell, EXECUTE AS/linked-server crawl, xp_dirtree
  UNC coercion → relay/roast; MSSQLSvc SPN is kerberoastable
- [[modern-c2-frameworks]] — the open-source C2 landscape (Sliver / Mythic /
  Havoc) beyond Cobalt Strike + Meterpreter

- [[ad-trusts]] — trust fundamentals: types, direction, transitivity, SID-filter
  defaults; the forest (not the domain) is the security boundary
- [[trust-key-abuse]] — forge inter-realm TGTs ("trust tickets") with the trust
  key; child→parent Enterprise Admin (raiseChild)
- [[foreign-security-principals]] — quiet cross-trust path: use existing foreign
  group membership, no forgery, low signal
- [[cross-forest-adcs]] — PKI as a cross-forest auth bridge (CA published into
  another forest's NTAuth bypasses SID filtering)
- [[esc16]] — security extension disabled **CA-wide** (the domain-wide ESC9;
  UPN-swap against any client-auth template)
- [[sapphire-ticket]] — stealthiest krbtgt forgery: embed a real privileged PAC
  pulled via S4U2self (ticketer -impersonate)
- [[bronze-bit]] — CVE-2020-17049: flip the S4U2proxy forwardable bit to defeat
  Protected Users / "sensitive" delegation protections
- [[timeroasting]] — unauthenticated computer-account roast via MS-SNTP (UDP/123,
  no logon events; hashcat -m 31300)

## Entities

### Tools

- [[rubeus]] — Go Kerberos attack tool (asktgt/ask, PtK, Golden/Diamond
  tickets, triage)
- [[mimikatz]] — the Swiss-army credential dumper (logonpasswords,
  kerberos::golden, dcsync)
- [[evil-winrm]] — offensive WinRM shell (PtH/PtT, upload, in-memory .NET);
  the go-to WinRM foothold client
- [[impacket]] — Python protocol toolkit (secretsdump, psexec, ticketer,
  GetST, etc.)
- [[secretsdump]] — NTDS/SAM dumper: remote DCSync (`-just-dc-user krbtgt`)
  + offline VSS-hive parsing (gMSA + trust keys in the output)
- [[procdump]] — Sysinternals process-memory dumper (the `procdump -ma
  lsass.exe` dump that mimikatz parses)
- [[certipy]] — AD CS attack tool (find/find-ca, req)
- [[bloodhound]] — AD attack-path graph (SharpHound ingest, path queries)
- [[rusthound]] — Rust BloodHound collector; single static binary, no
  .NET/Python (RustHound-CE for BloodHound CE)
- [[powerview]] — PowerShell AD enumeration (Get-DomainObject, ACL queries)
- [[petitpotam]] — the MS-EFSRPC NTLM-relay coercion trigger
- [[ntlmrelayx]] — the NTLM relay engine (AD CS, RBCD, addcomputer targets)
- [[mitm6]] — the IPv6 MITM/relay tool (WPAD, LDAPS RBCD)
- [[whisker]] — Shadow Credentials tool (plant/UnPAC the NT hash)
- [[netexec]] — mass scanning + execution (SMB/WinRM/LDAP); NetExec (`nxc`),
  the actively maintained successor to the unmaintained CrackMapExec (`cme`)
- [[hashcat]] — GPU offline password cracker (the roast/dump hash modes)
- [[john-the-ripper]] — CPU offline cracker (the JtR formats for
  kerberoast/AS-REP/NTLM/krbtgt)
- [[kerbrute]] — Kerberos attack tool (kerberoast, asrep, ptk, TGT brute)
- [[dasync]] — DCSync via MS-DRSR to a local DB (the targeted dcsync tool)
- [[powerupack]] — the Windows offensive suite (Privesc, SharpGPOAbuse,
  GPOHound)
- [[winpeas]] — the local Windows privesc + recon sweeper (the single-pass
  post-foothold enumeration for every local-privesc vector)
- [[sharp-gpo-abuse]] — write malicious GPO preferences for linked-machine
  code exec
- [[gpohound]] — GPO attack-surface enumeration (writable GPOs → linked
  targets)
- [[mvictor]] — SCCM/MECM lateral movement + credential extraction
- [[pxethief]] — steal SCCM/WDS PXE-boot credentials
- [[wdsfilecrawler]] — crawl the WDS/MDT deployment share for answer-file
  creds
- [[certify]] — Go AD CS attack tool (find/req; the Go twin of certipy)
- [[responder]] — LLMNR/NBNS/mDNS NTLM capture + auto-relay to LDAP (-A RBCD)
- [[evilwpad]] — rogue WPAD (PAC serve + NTLM capture + LDAP/RBCD relay), Go
- [[adrecon]] — .NET AD recon (objects, ACLs, replication rights, trusts)
- [[krb5pac]] — Kerberos PAC manipulation (UnPAC the hash, SID History,
  RBCD TGS forgery)
- [[ghidra]] — the NSA open-source RE suite (decompiler, XREFs, headless
  batch analysis, the static-analysis default)
- [[x64dbg]] — the free x64 debugger (API monitor, OEP find, anti-debugging
  defeat, the dynamic-analysis default)
- [[upx]] — the reference open-source packer (documented stub, `upx -d`
  de-pack; the teaching model for packer/unpacker)
- [[cobalt-strike]] — the commercial red-team C2 framework (beacon, malleable
  profile, the post-exploitation suite)
- [[meterpreter]] — the in-memory post-exploitation payload (stager/stage,
  the C2's hands on the host)
- [[sysmon]] — the host-telemetry standard (Process Access, File Create,
  Network Connect, Driver Load) the detection runs on
- [[sigma]] — the vendor-agnostic detection-rule language (YAML rules →
  Splunk/Elastic/Sysmon)

### CVEs

- [[cve-2020-0665]] — forest trust transitivity bypass (LSASS hook,
  local-SID injection)
- [[cve-2022-26923]] — AD CS dNSHostName → DC machine cert (ESC12)
- [[cve-2024-49019]] — "EKUwu" AD CS V1 template application-policy abuse
  (ESC15)

### Researchers / References

- [[dirkjanm]] — NTLM relay / RBCD / mitm6 researcher (dirkjanm.io)
- [[specterops]] — BloodHound + AD CS ESC1-15 + Diamond Ticket / honeytokens
- [[ired-team]] — primary AD attack+detection reference
- [[internalallthethings]] — swisskyrepo hands-on AD/SCCM/WDS reference
- [[hideandsec]] — Shadow Credentials / PKINIT researcher (hideandsec.sh)
- [[ly4k]] — this wiki's author (thehackersbrain); creator of certipy,
  Whisker, BerserkArch; founder of Cyber Craft Labs

### Projects

- [[berserkarch]] — the security-focused Arch-based Linux distro (the
  author's working environment)
- [[cyber-craft-labs]] — the author's security R&D lab

## Notes

- [[path-genericwrite-to-dcsync]] — GenericWrite/ACL → Shadow Credentials →
  DCSync chain (BloodHound-driven privesc to domain dominance)
- [[path-unconstrained-delegation-to-domain-admin]] — Coercion →
  Unconstrained Delegation → DCSync → Golden Ticket → persistence
- [[path-gpo-write-to-domain-admin]] — Writable GPO linked to DC OU → code
  exec on DCs → Domain Admin
- [[path-cross-forest-trust-pivot]] — Forest A krbtgt → SID history trust
  pivot → Forest B Enterprise Admin
- [[path-esc1-template-to-domain-admin]] — Enrollment rights on an ESC1
  cert template → Administrator cert → Domain Admin
- [[path-sccm-naa-to-domain-admin]] — Local admin on any SCCM client →
  Network Access Account recovery → Domain Admin
- [[path-pass-the-key-to-domain-admin]] — LSASS key → Pass the Key → DCSync
  → Golden Ticket → Domain Admin
- [[path-diamond-ticket-to-domain-admin]] — DCSync AES128 → Diamond Ticket →
  durable (rotation-surviving) Domain Admin
- [[path-golden-ticket-to-domain-admin]] — DCSync/offline-dump krbtgt →
  Golden Ticket (AES256, DA SID) → Domain Admin → persistence
- [[path-sid-history-to-enterprise-admin]] — GenericWrite on a user → write
  EA SID into sidHistory → Enterprise Admin
- [[path-laps-to-domain-admin]] — LAPS password read → local admin on a
  Tier-0 box → DCSync → Domain Admin
- [[path-kerberoast-to-domain-admin]] — Kerberoast SPN accounts → crack a
  service account holding a DCSync right → krbtgt → Golden Ticket → DA
- [[path-esc8-petitpotam-to-dcsync]] — PetitPotam coercion → NTLM relay to
  AD CS → machine cert for a DC → DCSync → Golden Ticket → DA (no creds)
- [[path-mitm6-rbcd-to-local-admin]] — mitm6 coercion → NTLM relay to LDAP →
  RBCD attr on a target → lateral (local admin) to it
- [[path-shadow-credentials-to-nt-hash]] — GenericWrite on an account → plant
  shadow cred → PKINIT → UnPAC the NT hash → domain dominance
- [[path-asrep-roast-to-domain-admin]] — AS-REP roast a preauth-disabled
  account → crack its password → DCSync/Golden → Domain Admin
- [[path-constrained-delegation-to-domain-admin]] — KCD (TrustedToAuth +
  high-priv SPN) → Kerberoast the service → S4U impersonate Administrator →
  Tier-0 box → Domain Admin
- [[path-pass-the-hash-to-domain-admin]] — dumped NT hash → PtH lateral to a
  Tier-0 box → DCSync → Golden Ticket → Domain Admin
- [[path-overpass-the-hash-to-local-admin]] — local-admin NT hash → Overpass
  (real KDC TGT, no krbtgt) → Kerberos logon → local admin on the target
- [[path-silver-ticket-to-local-admin]] — forge a TGS with a service/machine
  secret + SPN (no DC) → access a specific service as Administrator
- [[path-rbcd-to-domain-admin]] — RBCD on a DC → S4U2Proxy impersonate a DA
  on the DC → DCSync → Golden Ticket → Domain Admin
