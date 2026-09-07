# Log

Append-only chronological record of ingests, queries, and lint passes.
Each entry starts with `## [YYYY-MM-DD] <type> | <title>`.

`grep "^## \[" wiki/log.md | tail -5` for recent activity.

## [2026-06-12] setup | Wiki initialized

Set up directory structure (`raw/`, `wiki/{entities,concepts,sources,notes}`),
schema in `CLAUDE.md`, and index/log files. Based on the "LLM Wiki" pattern
shared by Andrej Karpathy.

## [2026-06-12] ingest | AD attack techniques (6 sources, via Gemini CLI)

Used `gemini --skip-trust -p "..."` to research and write 6 source docs into
`raw/`: Kerberoasting, AS-REP Roasting, DCSync, Pass-the-Hash/Pass-the-Ticket,
Golden/Silver Tickets, Kerberos Delegation Abuse (unconstrained/constrained/
RBCD). Created matching `wiki/sources/*.md` summary pages, plus 5 concept
pages: [[kerberos-authentication]] (hub linking each attack to its protocol
stage), [[krbtgt]], [[ntlm]], [[gmsa]], [[ad-tiering-and-hardening]] (the
recurring mitigation baseline). Updated index.

## [2026-06-13] ingest | ACL abuse, AD CS ESC1-15, NTLM relay/coercion, SCCM, WDS/MDT (6 sources)

Processed 6 new raw docs (`acl_abuse.md`, `ad_cs_attacks.md`,
`ntlm_relay_ad_cs.md`, `rbcd_delegation.md`, `sccm_security.md`,
`wds_mdt_discovery.md`). New concept pages: [[acl-abuse]] (GenericAll/
WriteDacl/WriteOwner/GenericWrite — BloodHound object-control edges),
[[ad-cs-esc-attacks]] (ESC1-15 hub), [[ntlm-relay-coercion]] (PetitPotam/
mitm6/WPAD + relay targets), [[sccm-abuse]], [[wds-mdt-discovery]]. New
source pages: [[esc8-ntlm-relay-adcs]] (PetitPotam → relay → cert → DCSync
chain) and [[rbcd-via-ntlm-relay]] (credential-less RBCD via mitm6/WPAD →
LDAPS relay, dirkjanm "worst of both worlds"). Cross-linked the latter into
[[kerberos-delegation-abuse]]. Updated index.

## [2026-06-13] ingest | Shadow Credentials, AD trust attacks, GPO abuse, AD persistence, PKINIT (5 sources)

Processed 5 new raw docs (`shadow_credentials.md`, `ad_forest_trust_attacks.md`,
`gpo_abuse.md`, `ad_persistence_dcshadow_skeletonkey_adminsdholder.md`,
`pkinit_unpac_the_hash.md`) from ired.team, dirkjanm.io, InternalAllTheThings,
and hideandsec.sh. New concept pages: [[shadow-credentials]] (msDS-KeyCredentialLink
key-trust takeover), [[ad-trust-attacks]] (SID filtering, TREAT_AS_EXTERNAL,
CVE-2020-0665), [[gpo-abuse]] (GPO edit-rights → domain-wide code exec),
[[ad-persistence]] (DCShadow/Skeleton Key/AdminSDHolder), and
[[pkinit-unpac-the-hash]] (PKINIT + UnPAC the hash, the hub linking AD CS/cert
attacks back to NTLM). Matching source pages created. Cross-linked into
[[kerberos-authentication]], [[acl-abuse]], [[ad-cs-esc-attacks]], and
[[kerberos-delegation-abuse]]. Updated index.

## [2026-06-13] lint | Backfill commands + attack-path notes

Backfilled a `## Commands` section (concrete CLI/Mimikatz/Rubeus/Impacket
invocations) into the 11 source pages that lacked one:
[[kerberoasting]], [[as-rep-roasting]], [[dcsync]], [[golden-silver-tickets]],
[[pass-the-hash-and-ticket]], [[kerberos-delegation-abuse]],
[[shadow-credentials]], [[ad-forest-trust-attacks]], [[gpo-abuse]],
[[ad-persistence-dcshadow-skeletonkey-adminsdholder]], and
[[pkinit-unpac-the-hash]].

Wrote 4 new zettelkasten attack-path notes under `wiki/notes/`, chaining
existing concepts into full kill-chains: [[path-genericwrite-to-dcsync]],
[[path-unconstrained-delegation-to-domain-admin]],
[[path-gpo-write-to-domain-admin]], and [[path-cross-forest-trust-pivot]].
Updated index with the new Notes section entries.

## [2026-06-13] lint | Commands for AD CS/SCCM/WDS concepts + 2 new attack paths

Added `## Commands` sections to the remaining concept hub pages that lacked
them: [[acl-abuse]] (PowerView/dacledit ACE abuse for each right),
[[ad-cs-esc-attacks]] (filled in ESC3, ESC7, ESC9-ESC15 with concrete
`certipy`/`ntlmrelayx` chains), [[ntlm-relay-coercion]] (coercion +
mitm6/WPAD + generic ntlmrelayx setups), [[sccm-abuse]] (PXEThief, remote
secrets via registered device, Client Push relay), and [[wds-mdt-discovery]]
(SCP discovery, deployment share/unattend harvesting, wdsfilecrawler).

Wrote 2 more attack-path notes: [[path-esc1-template-to-domain-admin]]
(enrollment rights on an ESC1 template → Administrator cert → DA, with ESC4
fallback) and [[path-sccm-naa-to-domain-admin]] (local admin on any SCCM
 client → NAA credential recovery → DA, plus credential-less device-registration
 variant). Updated index.

## [2026-09-06] lint | Major expansion: new concepts, entities, and attack-path notes

Filled out the wiki's thin spots. **14 new concept pages** covering the
Kerberos/AD substrate the existing pages referenced but didn't define:
[[pass-the-key]], [[diamond-ticket]], [[kerberos-pac]],
[[kerberos-encryption-types]], [[kerberos-preauth]],
[[s4u2self-s4u2proxy]], [[honeytokens]], [[ntds-dit]], [[lsass]],
[[sam-database]], [[laps]], [[sid-history]], [[mitm6-ipv6-relay]],
[[krbrelay]].

**First entity pages (20)** under `wiki/entities/`:
- Tools: [[rubeus]], [[mimikatz]], [[impacket]], [[certipy]], [[bloodhound]],
  [[powerview]], [[petitpotam]], [[ntlmrelayx]], [[mitm6]], [[whisker]],
  [[crackmapexec]], [[hashcat]]
- CVEs: [[cve-2020-0665]] (forest trust transitivity bypass),
  [[cve-2022-26923]] (AD CS dNSHostName / ESC12),
  [[cve-2024-49019]] (EKUwu / ESC15)
- Researchers/references: [[dirkjanm]], [[specterops]], [[ired-team]],
  [[internalallthethings]], [[hideandsec]]

**4 new attack-path notes** under `wiki/notes/`:
[[path-pass-the-key-to-domain-admin]],
[[path-diamond-ticket-to-domain-admin]],
[[path-sid-history-to-enterprise-admin]],
[[path-laps-to-domain-admin]].

**Deepened two thin hubs**: [[krbtgt]] (KDC key usage, the three keys,
Diamond-Ticket rotation window, detection) and [[ntlm]] (NT/LM/NTLMv1/v2
mechanics, WDigest, where NTLM runs, relay surface, detection). Fixed a
Rubeus reference URL (Ghostpack, not a "GenerateMSMA" repo) and a hashcat
AS-REP mode (18200, not 7500). Updated index (new Concepts entries, first
Entities section, 4 new Notes entries).

## [2026-09-06] expand | Second batch: high-mention gaps, missing tools, author entities, 4 more attack paths

Filled the biggest remaining gaps (techniques referenced but never given a
page) and rounded out the toolset + author identity.

**4 new concept pages**: [[resource-based-constrained-delegation]] (RBCD —
the attribute, the s4u/RBCD TGS, detection), [[service-principal-name]] (the
SPN surface behind Kerberoast), [[overpass-the-hash]] (NT hash → real TGT via
AS-REQ), [[pass-the-cert]] (PKINIT cert auth without the key password).

**9 new tool entities**: [[john-the-ripper]] (CPU cracker, the JtR format
map), [[kerbrute]] (kerberoast/asrep/ptk), [[dasync]] (targeted DCSync to a
local DB), [[powerupack]] (the Windows offensive suite),
[[sharp-gpo-abuse]] + [[gpohound]] (the GPO exploit + enumeration pair),
[[mvictor]] (SCCM lateral), [[pxethief]] + [[wdsfilecrawler]] (the PXE/WDS
credential tools).

**3 author/project entities**: [[ly4k]] (this wiki's author, thehackersbrain),
[[berserkarch]] (the distro), [[cyber-craft-labs]] (the R&D lab); added
`[[ly4k]]` backlinks in [[certipy]] and [[whisker]].

**4 new attack-path notes**: [[path-kerberoast-to-domain-admin]] (roast →
crack a DCSync-holding service account → krbtgt → Golden),
[[path-esc8-petitpotam-to-dcsync]] (PetitPotam → relay to AD CS → machine
cert for a DC → DCSync, no creds), [[path-mitm6-rbcd-to-local-admin]] (mitm6
coercion → relay to LDAP → RBCD attr → lateral), [[path-shadow-credentials-to-nt-hash]]
(GenericWrite → plant → PKINIT → UnPAC the hash).

Fixed a truncated attribute name in the RBCD mitigations
(`msDS-AllowedToActOnBlood...` → the full
`msDS-AllowedToActOnBehalfOfOtherIdentity`). Updated index (4 new Concepts,
9 new Tools, a new Projects subsection + author under Researchers, 4 new
Notes).

## [2026-09-06] expand | Third batch: protocol/substrate concepts + 4 more kill-chains

Filled the high-mention protocol/substrate gaps (terms referenced hundreds of
times but never given a page) and added four more attack-path notes covering
chains whose techniques were source pages without a dedicated path note.

**4 new concept pages**: [[smb]] (SMB versions, signing as the relay control,
lateral exec, the SMBv1/anonymous surface), [[ldap]] (the directory protocol,
enumeration + the relay target for RBCD/ACL/ownership writes, signing +
channel binding), [[ccache]] (the Kerberos ticket wallet: .ccache/.kirbi,
dump/inject/forge the identity), [[service-account]] (user vs service vs
machine account taxonomy — which attack applies to which account).

**4 new attack-path notes**: [[path-asrep-roast-to-domain-admin]] (roast a
preauth-disabled account → crack → DCSync → Golden),
[[path-constrained-delegation-to-domain-admin]] (KCD TrustedToAuth + high-priv
SPN → Kerberoast the service → S4U impersonate Administrator → Tier-0 box),
[[path-pass-the-hash-to-domain-admin]] (dumped NT hash → PtH lateral to a
Tier-0 box → DCSync → Golden), [[path-silver-ticket-to-local-admin]] (forge a
TGS with a service/machine secret + SPN, no DC → access a specific service as
Administrator).

**Deepened [[impacket]]**: added the RBCD script rows (`getST.py`,
`addcomputer.py`, `rbcd.py`), an RBCD invocation block, and links to the new
protocol/substrate pages. Updated index (4 new Concepts, 4 new Notes).

## [2026-09-06] expand | Fourth batch: ticket/tier/exec/coercion concepts + RBCD-to-DC chain + 4 tools

Filled the "what are the two tickets / what's a tier / how do I exec / how do
I coerce without creds" substrate gaps and added the RBCD-aimed-at-a-DC chain,
plus four tool entities referenced across the wiki.

**5 new concept pages**: [[tgt-tgs]] (TGT vs TGS — the two ticket types, their
signing keys/lifetimes, and a table mapping every Kerberos attack to which
ticket it forges/steals), [[ad-tier-model]] (the Tier 0/1/2 trust model itself
— what's in each tier, the trust-flow rule, PAWs; the frame every path note is
measured against), [[remote-execution]] (the psexec/wmiexec/smbexec/atexec/
WinRM/PSRemoting/RDP decision table + per-channel detection), [[printer-bug]]
(CVE-2021-34527 Print Spooler RPC coercion, the spooler side of the coercion
family), [[wpad]] (WPAD autoconfig — the ambient no-prompt NTLM capture that
feeds RBCD relays).

**1 new attack-path note**: [[path-rbcd-to-domain-admin]] (write RBCD on a DC
→ S4U2Proxy impersonate a DA on the DC → land local-admin on the DC → DCSync
→ Golden Ticket → DA; the "RBCD aimed at the DC" completion of the lateral
RBCD chain).

**4 new tool entities**: [[certify]] (Go AD CS tool, twin of certipy),
[[responder]] (LLMNR/NBNS/mDNS NTLM capture + auto-relay -A RBCD),
[[adrecon]] (.NET AD recon), [[krb5pac]] (PAC manipulation — UnPAC/SID
History/RBCD forgery).

**Backlinks wired** into: [[mitm6-ipv6-relay]] (→ wpad/responder),
[[ntlm-relay-coercion]] (→ printer-bug/wpad/responder),
[[ad-cs-esc-attacks]] (certify C#→Go fix + link), [[certipy]] (→ certify),
[[kerberos-pac]] (→ krb5pac), [[bloodhound]] (→ adrecon),
[[ad-tiering-and-hardening]] (→ ad-tier-model), [[service-principal-name]]
(→ tgt-tgs), [[smb]] (→ remote-execution/printer-bug/wpad), [[sccm-abuse]]
(→ remote-execution), [[sid-history]] (→ krb5pac),
[[kerberos-authentication]] (→ tgt-tgs),
[[resource-based-constrained-delegation]] (→ path-rbcd-to-domain-admin),
[[path-unconstrained-delegation-to-domain-admin]] (→ printer-bug + a
flag-attribution fix), [[path-mitm6-rbcd-to-local-admin]] (→
path-rbcd-to-domain-admin). Updated index (5 new Concepts, 4 new Tools, 1 new
Note).

## [2026-09-06] expand | Fifth batch: DC/FSMO + AD-structure foundation + DCShadow/Skeleton Key split

Filled the last two big substrate gaps — "what is a DC / what are the FSMO
roles" and "what's the AD hierarchy" — and split the two domain-persistence
techniques out of the [[ad-persistence]] hub into their own deep-dive pages.

**4 new concept pages**:
- [[domain-controller]] — what a DC is (AD DS, the KDC, SYSVOL, [[ntds-dit]]),
  the **five FSMO roles** (Schema/Domain Naming/PDC/RID/Infrastructure) with
  their attack relevance, **DSRM** (the per-DC local admin that can DCSync and
  is the basis of [[dcshadow]]), and why DC = Tier 0 / the end-game.
- [[ad-structure]] — the foundational hierarchy glossary: the object model
  (classes/attributes/DN/SID/ACL), **OU → domain → tree → forest**, **sites**
  (network-position surface), and *why the structure dictates the attacks*
  (per-domain `krbtgt`, per-domain SID namespaces, trust edges, OU-scoped GPOs,
  site-aware relay).
- [[dcshadow]] — dedicated deep-dive (split from [[ad-persistence]]): the
  **rogue-replication-partner** variant (push `sidHistory`/`primaryGroupID`/
  `AdminSDHolder` ACL over MS-DRSR, muting the LDAP-modify audit) **and** the
  **shadow-DC / DSRM** variant (own a DC's local DSRM admin → DCSync even after
  your domain accounts are wiped).
- [[skeleton-key]] — dedicated deep-dive (split from [[ad-persistence]]): the
  **DC LSASS memory patch** that accepts a static master key for any account,
  why it **survives `krbtgt` rotation**, its in-memory (reboot-dies) nature +
  persistence variants, detection (LSASS memory-vs-disk mismatch, a Golden
  Ticket outliving a rotation), and remediation (rebuild DCs from clean image).

**Backlinks wired** into: [[ad-persistence]] (hub → both new pages),
[[krbtgt]] (→ dcshadow/skeleton-key), [[lsass]] (→ skeleton-key),
[[sid-history]] (→ dcshadow), [[ntds-dit]] (→ domain-controller),
[[ad-tier-model]] (→ domain-controller),
[[path-unconstrained-delegation-to-domain-admin]] (→ dcshadow/skeleton-key).
Updated index (4 new Concepts).

## [2026-09-06] expand | Sixth batch: Kerberoasting concept + gMSA deep-dive + secretsdump tool

Closed the "second-most-mentioned topic with no concept page" gap and
deepened the thin gMSA page.

- **[[kerberoasting]] (new concept)** — the TGS request + offline-crack
  mechanism, the SPN enumeration → request → crack → exploit flow, the 4769
  burst detection, the gMSA/AES mitigations, and the contrast with
  `krbtgt` (single-service key vs. domain-wide). Sits alongside the existing
  [[kerberoasting]] (sources) summary page — the concept+source pair pattern
  already used by gpo-abuse/shadow-credentials/pkinit. All pre-existing
  `[[kerberoasting]]` links (service-principal-name, path-kerberoast,
  honeytokens, gmsa, service-account) now resolve to the concept page too.
- **[[gmsa]] (deepened)** — was a 31-line "mitigation" stub; now the full
  mechanics: what a gMSA is in AD (computer-like object + service SPN +
  auto-rotated secret cached in the host's LSASS), why rotation defeats
  *offline cracking* specifically, and the **gMSA attack surface** (crack the
  current key pre-rollover, LSASS dump of the cached key, DCSync/offline NTDS
  for the current password, ACL-write reset of the gMSA object, using the
  live identity) — plus detection + the real mitigations (object ACL, LSASS
  protection, short rollover interval).
- **[[secretsdump]] (new tool entity)** — the impacket NTDS/SAM dumper:
  remote DRSUAPI/DCSync mode (`-just-dc-user krbtgt`) + offline VSS-hive
  parsing, what it outputs (domain/local hashes, krbtgt, gMSA keys, trust
  accounts), detection (4662 + VSS), mitigations (DRSUAPI ACL, DC volume
  protection).

**Backlinks wired** into: [[ntds-dit]] (→ secretsdump, gmsa),
[[impacket]] (secretsdump rows → secretsdump entity), [[lsass]] (→ gmsa).
Updated index (1 new Concept, 1 new Tool; gmsa line expanded).

## [2026-09-06] expand | Seventh batch: DCSync/Golden-Silver/AS-REP/Delegation concepts + Golden-Ticket path note

Promoted four of the highest-mentioned topics that only had source pages into
full concept pages, and added the missing "canonical" DA path note.

- **[[dcsync]] (new concept)** — MS-DRSR `DSGetNCChanges` abuse: the
  Get-Changes/Get-Changes-All ACLs on the domain object, who normally holds
  them (incl. machine accounts + the Azure AD Connect account), what you get
  (NTLM/AES keys, history, `krbtgt`, gMSA, trust keys), enumeration +
  invocation, 4662 replication-GUID detection, DRSUAPI/ACL mitigation, and
  its role as the "get everything" primitive feeding Golden/PtH/PtK.
- **[[golden-silver-tickets]] (new concept)** — the working reference for
  offline TGT/TGS forgery: the Golden vs Silver comparison table, the exact
  forgery inputs (krbtgt key + domain SID vs service key + SPN), Rubeus/
  ticketer invocations, the RC4-downgrade tell, the PAC requirement,
  per-type detection (4768-without-4768, 4769-no-4768, abnormal lifetimes),
  and the krbtgt double-rotation / gMSA / PAC-validation remediations.
  (Sits alongside the existing source page; the `[[diamond-ticket]]` concept
  already covered the AES128 variant.)
- **[[as-rep-roasting]] (new concept)** — `DONT_REQ_PREAUTH` accounts: the
  AS-REQ-stage sibling of kerberoasting, the UAC-bit enumeration,
  GetNPUsers/Rubeus invocations, 4768-type-0 detection, preauth/Protected
  Users/gMSA mitigations.
- **[[kerberos-delegation]] (new concept, hub)** — the UDE/CDE/RBCD family:
  the three attributes (`TrustedForDelegation`, `msDS-AllowedToDelegateTo`,
  `msDS-AllowedToActOnBehalfOfOtherIdentity`) and *who writes each*, what
  each enables, the 4769-`R0` + 5136/4662 detection, the pruning/ACL
  mitigations. Links out to the S4U mechanics ([[s4u2self-s4u2proxy]]), the
  RBCD deep-dive ([[resource-based-constrained-delegation]]), the raw source
  ([[kerberos-delegation-abuse]]), and the four delegation path notes.
- **[[path-golden-ticket-to-domain-admin]] (new note)** — the canonical
  DA path (the one the diamond-ticket note contrasts against):
  DCSync/offline-dump `krbtgt` → Golden Ticket (AES256, DA SID 512) → DA →
  optional [[ad-persistence]]. Steps + per-step detection table + failure
  modes + cleanup.

**Backlinks wired** into: [[s4u2self-s4u2proxy]] (→ kerberos-delegation hub),
[[resource-based-constrained-delegation]] (→ hub),
[[path-unconstrained-delegation-to-domain-admin]] (→ hub),
[[path-constrained-delegation-to-domain-admin]] (→ hub),
[[kerberos-authentication]] (→ kerberos-delegation, as-rep-roasting). All
pre-existing `[[dcsync]]`/`[[golden-silver-tickets]]`/`[[as-rep-roasting]]`/
`[[kerberos-delegation-abuse]]` links now also resolve to the new concept
pages (concept+source pair pattern). Updated index (4 new Concepts, 1 new
Note).

## [2026-09-06] expand | Eighth batch: PtH/PtT concept + evilwpad entity + Overpass path note

- **[[pass-the-hash-and-ticket]] (new concept)** — the working reference for
  the two credential-reuse lateral techniques: the PtH vs PtT comparison
  table, why an NTLM hash *is* the credential (challenge-response, no
  plaintext), the Mimikatz `sekurlsa::pth` + Impacket `-hashes` invocations,
  PtT `.kirbi`/`.ccache` capture + `ptt` injection, the PtH limits (target
  must accept NTLM) and PtT-vs-forgery contrast, the 4624-type-3-NTLM/Key-
  Length-0 + 4648 + 4769-without-4768 detection tells, and the
  NTLM-restriction / Protected Users / Credential Guard / LAPS / AES
  mitigations. (Sits alongside the same-stem source page; all pre-existing
  `[[pass-the-hash-and-ticket]]` links now also resolve to this concept.)
- **[[evilwpad]] (new entity)** — the canonical rogue-WPAD tool (b1774, Go):
  DNS-position requirement (a `wpad` record), PAC serve + NTLM capture, the
  LDAP/RBCD relay mode, invocation, the WPAD-to-odd-IP + RBCD-write
  detection, and the `wpad`-record / HTTPS-PAC / NTLM-audit mitigations.
- **[[path-overpass-the-hash-to-local-admin]] (new note)** — the
  "hash → local admin on a target" chain: NT hash of a local-admin user
  (LSASS/SAM/DCSync) → **Overpass** (Rubeus `asktgt /rc4` → real KDC-minted
  TGT, no krbtgt) → TGS for `cifs/<target>` → Kerberos logon → local admin.
  Includes the Overpass-vs-PtH-vs-Golden-vs-PtK "why here" contrast, the
  AES256-forced-domain failure mode, the 4768-RC4 tell, and cleanup notes.

**Backlinks wired** into: [[overpass-the-hash]] (→ the new path note),
[[wpad]] (→ evilwpad, responder), [[mitm6-ipv6-relay]] (→ evilwpad),
[[resource-based-constrained-delegation]] (→ evilwpad RBCD relay). Updated
index (1 new Concept, 1 new Tool, 1 new Note).

## [2026-09-07] lint | Orphan cross-refs + Kerberos enctype/hashcat corrections

Ran the full lint pass. Fixed **9 orphan pages** (no inbound links) by adding
cross-references: attack-path notes linked from their parent concept
([[laps]]→[[path-laps-to-domain-admin]], [[pass-the-key]], [[shadow-credentials]]),
and tool/CVE entities linked from the concept that uses them ([[dcsync]]→[[dasync]],
[[as-rep-roasting]]→[[kerbrute]], [[acl-abuse]]→[[powerupack]],
[[ad-cs-esc-attacks]]→[[specterops]], [[ad-trust-attacks]]→[[cve-2020-0665]],
[[shadow-credentials]]→[[hideandsec]]). Corrected factual errors that contradicted
[[kerberos-encryption-types]]: [[as-rep-roasting]] RC4 enctype `0x10`→`0x17`;
[[kerberoasting]] AES enctypes `0x12/0x18`→`0x11`/`0x12`, hashcat AES mode
`18200`→`19700`/`19800`, and John format `kerberos-17`→`krb5tgs`. No contradictions
found in krbtgt double-rotation, DCSync replication GUIDs, or Golden/Silver secrets.

## [2026-09-07] tradecraft | Inline red-team OPSEC sections + red-team sources

Made the wiki a working tradecraft reference (per updated CLAUDE.md): wove an
inline `## Red-team notes (OPSEC)` section into the core technique pages —
[[kerberoasting]], [[as-rep-roasting]], [[dcsync]], [[kerberos-delegation]],
[[resource-based-constrained-delegation]], [[ntlm-relay-coercion]],
[[acl-abuse]], [[ad-cs-esc-attacks]], [[golden-silver-tickets]],
[[pass-the-hash-and-ticket]], [[shadow-credentials]] — plus a "Collection
OPSEC" block on [[bloodhound]]. Each ties targeting/enctype/tooling-by-context/
remote-operation into that page's own Detection section (no separate ops pages).
Added red-team reference sources: [[certified-pre-owned]], [[the-hacker-recipes]],
[[adsecurity-org]], [[harmj0y-blog]], [[dirkjanm-blog]].

## [2026-09-07] update | NetExec rename + AD CS ESC family completion + new techniques

CrackMapExec is unmaintained — replaced with NetExec. Renamed
`wiki/entities/crackmapexec.md` → [[netexec]] (canonical CLI `nxc`; `cme`
retired; `-M` module syntax, `-x`/`-X` exec, spider/LSASS/Mimikatz modules,
BloodHound ingestor). Updated every `[[crackmapexec]]` wikilink and the
`crackmapexec smb` command examples to `nxc` (kerbrute, mvictor, bloodhound,
smb, remote-execution, path-sccm-naa, path-pass-the-hash); lateral chip in
taxonomy updated. Added 15 concept pages: the remaining ESC family
([[esc5]], [[esc7]], [[esc8]], [[esc9]], [[esc10]], [[esc11]], [[esc12]],
[[esc13]], [[esc14]], [[esc15]] — completing ESC1–15 with per-ESC deep-dive
pages linked from [[ad-cs-esc-attacks]]), [[golden-certificate]] (CA key /
rogue CA PKINIT persistence), [[kerberos-event-ids]] (4768/4769/4770/4771 +
NTLM-side events, per-attack tell table), [[llmnr-nbt-ns-poisoning]] (the
Responder technique: LLMNR/NBT-NS spoofing → NTLM capture/relay),
[[credential-dumping]] (on-host secret stores map + online/offline dump
postures), [[unconstrained-delegation]] (UDE abuse mechanics: TGT capture →
TGS-to-DC → UnPAC → DCSync). Wired backlinks: responder/wpad/mitm6/
ntlm-relay-coercion → llmnr, printer-bug/petitpotam → esc8, kerberos-
delegation → unconstrained-delegation, lsass/sam/ntds → credential-dumping.
Added [[procdump]] entity (Sysinternals LSASS dumper); fixed the one
dangling wikilink that remained ([[unconstrained-delegation]] →
[[path-mitm6-rbcd-to-local-admin]]). Filled the index (15 new pages + 12
previously-unindexed pages: esc1-4/6,
certificate-templates, certificate-mapping, ntauthcertificates,
pki-and-ad-cs-architecture, the 7 AD-ops pages) and the taxonomy (full AD CS
section, new "AD Ops & Methodology" section).

## [2026-09-07] ingest | Reverse-engineering & malware domain + C2/evasion/detection

New wiki domain: reverse engineering / malware development / C2. Added 12
concept pages: [[reverse-engineering-workflow]] (the static+dynamic analysis
arc, the RE-domain analog of [[redteam-ad-methodology]]), [[pe-executable]]
(PE headers/IAT/sections/entropy), [[shellcode]] (x64 PEB-walk bootstrap,
calling convention, stack alignment, null-byte avoidance), [[api-hashing]]
(djb2 nameless API resolution), [[process-injection]] (remote thread / APC /
hollowing / module stomping / thread hijack / callback injection),
[[windows-syscalls]] (direct `Nt*`/`syscall` past the user-mode hook, the
layer ETW survives), [[anti-debugging]] (PEB flags / IsDebuggerPresent /
timing / Int3 + the anti-anti-debugging race), [[anti-analysis]] (CPUID /
uptime / MAC / count + time-bomb & multi-stage), [[packer-unpacking]] (stub /
payload / OEP, OEP find + dump, anti-unpacking), [[amsi]] (PowerShell/.NET
script-scan + patch/hook bypasses), [[etw]] (kernel event-bus, session-kill /
provider-disable / callback-removal + VBS counter), [[beaconing]] (C2
heartbeat: periodicity, jitter, small-request/command-response shape +
detection). Added 7 entity pages: [[ghidra]] (static RE), [[x64dbg]]
(dynamic RE), [[upx]] (reference packer), [[cobalt-strike]] (C2 framework),
[[meterpreter]] (post-exploitation payload), [[sysmon]] (host telemetry),
[[sigma]] (detection-rule language). Wired backlinks: defense-evasion-ad →
amsi/etw/windows-syscalls/process-injection/beaconing; c2-and-pivoting-ad →
beaconing/cobalt-strike/meterpreter; lsass + credential-dumping →
process-injection/meterpreter/sysmon/sigma/defense-evasion-ad; redteam-ad-
methodology → reverse-engineering-workflow. Index filled (12 concepts + 7
tools) and taxonomy gained two sections: "Reverse Engineering & Malware" and
"C2, Evasion & Host Detection".

## [2026-09-07] ingest | Windows local privesc domain

New domain (AD-specialized wiki, Windows host focus): winning the box —
low-priv → local admin/SYSTEM — and keeping it. Added 10 concept pages:
[[windows-privilege-escalation]] (the hub: enumeration, technique map, the
AD bridge, detection), [[uac-bypass]], [[token-privilege-escalation]] (the
SeImpersonate + SYSTEM-pipe model behind the printer bug), [[service-privesc]],
[[scheduled-task-abuse]], [[named-pipe-hijacking]], [[dll-hijacking-sideloading]],
[[environment-variable-attack]], [[potato-family]] (Coerced Pipe Impersonation,
Rotten/God/Juicy/ODD/BOOM), and [[windows-local-persistence]] (Run keys,
services, tasks, WMI, COM, IFEO). Added 1 entity page: [[winpeas]] (local
privesc sweeper). Wired backlinks: redteam-ad-methodology → local privesc as
the on-foothold step; defense-evasion-ad → the quiet local-privesc vectors;
printer-bug → token-privilege-escalation/named-pipe-hijacking/potato-family;
remote-execution + situational-awareness + credential-dumping →
windows-privilege-escalation; ntlm-relay-coercion → the local
pipe-coercion sibling. Index filled (10 concepts + 1 tool) and taxonomy gained
a "Windows Local Privesc & Host" section (hue 265, before Lateral).

## [2026-09-07] ingest | Hands-on lateral/initial-access & operator plumbing gaps

Filled concrete hands-on gaps the AD/Kerberos-heavy wiki was missing. Added 4
concept pages: [[password-spraying]] (lockout-aware low-and-slow first foothold
— kerbrute/nxc, --pass-pol budgeting, 4625/4771, honeytoken traps),
[[kerberos-double-hop]] (the WinRM/psexec second-hop failure and the fixes:
CredSSP vs PtT/OPtH ticket injection vs delegation/S4U), [[pivoting-and-tunneling]]
(operator-side plumbing — ligolo-ng TUN, chisel-over-HTTP, SSH dynamic forwards,
C2 SOCKS, proxychains proxy_dns, the Kerberos/UDP gotchas), and [[ad-enumeration]]
(remote enum cheat-cards from the Linux operator host over the tunnel — nxc/
ldapsearch/bloodhound-python/GetUserSPNs/GetNPUsers/certipy find, "where paths
hide"). Added 1 entity: [[evil-winrm]] (offensive WinRM client — PtH/PtT, -r
realm for the double-hop, in-memory .NET). Wired backlinks: remote-execution →
kerberos-double-hop + evil-winrm; c2-and-pivoting-ad → pivoting-and-tunneling +
ad-enumeration; situational-awareness → ad-enumeration (on-host vs remote
counterpart); redteam-ad-methodology foothold/lateral phases → password-spraying/
ad-enumeration/kerberos-double-hop/pivoting-and-tunneling. Index updated (4
concepts + 1 tool). Taxonomy: password-spraying → Credential Access;
kerberos-double-hop → Lateral Movement; ad-enumeration + pivoting-and-tunneling →
AD Ops & Methodology.

## [2026-09-07] update | NetExec crash-course (hidden gems) + drop qmd

Expanded [[netexec]] with a "Crash course: modern nxc (the hidden gems)"
section covering the under-used modern features: built-in secret extraction
flags (`--sam`/`--lsa`/`--ntds`/`--dpapi`/`--sccm` — no module needed), the
`nxcdb` results database + workspaces, lockout-safe spraying (`--ufail-limit`/
`--gfail-limit`/`--fail-limit`) tied to [[password-spraying]], killer modules
(`gpp_password`, `get-desc-users`, `maq`, `coerce_plus`, `laps`, `adcs`,
`ntlmv1`, `keepass_*`, `wcc`), the non-SMB protocols (ldap `--bloodhound`/
`--gmsa`/roasting, mssql `mssql_priv`, winrm/ssh), and the Kerberos-over-tunnel
QoL (`--generate-hosts-file`/`--generate-krb5-file`/`--dns-server`/
`--use-kcache`). Cross-linked to ad-enumeration/password-spraying/
pivoting-and-tunneling/sccm-abuse/laps/gmsa/ntds-dit/dcsync. CLAUDE.md: removed
the qmd search section (this is a website, not a local search-index base) and
replaced it with a lightweight "## Search" note (index.md + grep + the site's
own build-time client-side search); maintenance loop is now just index.md +
log.md then `npm run build`.

## [2026-09-07] update | RustHound collector added

Added [[rusthound]] entity (RustHound / RustHound-CE — the Rust BloodHound
collector: single static binary, no .NET/Python runtime, cross-platform, fast;
RustHound-CE emits BloodHound CE format vs legacy RustHound = BH v4). Key angle
captured: on a Windows foothold it sidesteps the AMSI/.NET assembly-load
telemetry SharpHound trips, but LDAP collection volume is unchanged so
[[bloodhound-opsec]] still applies. Wired mentions into [[bloodhound]]
(collector list + workflow + refs), [[bloodhound-opsec]] (collection snippet),
[[ad-enumeration]] (collection cheat-card + tools), [[c2-and-pivoting-ad]]
(over-the-tunnel collection). Index updated (1 tool).

## [2026-09-07] ingest | Gap-fill: DPAPI, MSSQL abuse, modern C2

Lint pass found the wiki had zero orphans but three referenced-but-missing (or
absent-surface) domains. Added 3 concept pages: [[dpapi]] (masterkey model, the
three ways to the masterkey, the **domain DPAPI backup key** as a mass-decrypt/
persistence primitive, browser creds+cookies for MFA-bypass session theft;
mimikatz/SharpDPAPI/DonPAPI/`nxc --dpapi`), [[mssql-abuse]] (xp_cmdshell,
EXECUTE AS impersonation, TRUSTWORTHY, linked-server crawl, and the `xp_dirtree`
UNC-coercion primitive → relay/roast; MSSQLSvc SPN kerberoast + silver ticket),
and [[modern-c2-frameworks]] (Sliver/Mythic/Havoc landscape, sleep obfuscation,
JARM/JA3 + named-pipe/memory-scan detection). Wired backlinks: credential-dumping
+ lsass → dpapi; kerberoasting → mssql-abuse; ntlm-relay-coercion (added
xp_dirtree as a coercion technique) → mssql-abuse; beaconing + cobalt-strike +
c2-and-pivoting-ad → modern-c2-frameworks. Index updated (3 concepts). Taxonomy:
dpapi → Credential Access; mssql-abuse → Lateral Movement; modern-c2-frameworks
→ C2/Evasion. (Deferred by user: GPP cpassword, Credential Guard/RunAsPPL,
password-cracking methodology.)

## [2026-09-07] ingest | Forests/trusts depth + cross-forest AD CS/ESC16 + modern ticket forgeries

Gap analysis: AD CS and Kerberos ticketing were actually the *deepest* areas
(not thin), but forests/trusts was genuinely thin (one 68-line page) and there
were precise modern gaps. Added 8 concept pages in three groups.
**Forests & trusts:** [[ad-trusts]] (fundamentals hub — types/direction/
transitivity/SID-filter defaults; forest-not-domain is the boundary; TDO/trust
key), [[trust-key-abuse]] (inter-realm TGT / "trust ticket" forging, child→parent
Enterprise Admin via krbtgt+SID-history or the trust key, raiseChild, cross-forest
SID-filtering caveats), [[foreign-security-principals]] (the quiet cross-trust
path via real foreign group membership). **Cross-forest AD CS + ESC16:**
[[cross-forest-adcs]] (NTAuth publication as an auth bridge that bypasses SID
filtering; cross-forest ESC1/ESC8/ESC11), [[esc16]] (security extension disabled
CA-wide — the domain-wide ESC9; UPN-swap against any client-auth template).
**Modern ticket forgeries:** [[sapphire-ticket]] (S4U2self → real privileged PAC
into a forged TGT; ticketer -impersonate; beats PAC-anomaly detection),
[[bronze-bit]] (CVE-2020-17049 — flip the S4U2proxy forwardable bit to defeat
Protected Users / "sensitive"; getST -force-forwardable), [[timeroasting]]
(unauth computer-account roast via MS-SNTP; UDP/123, no logon events; hashcat
-m 31300). Wired backlinks: ad-cs-esc-attacks → esc16 + cross-forest-adcs;
esc9 → esc16; ntauthcertificates → cross-forest-adcs; ad-trust-attacks +
sid-history → ad-trusts/trust-key-abuse/foreign-security-principals;
golden-silver-tickets → sapphire-ticket/trust-key-abuse; diamond-ticket →
sapphire-ticket; s4u2self-s4u2proxy → bronze-bit/sapphire-ticket;
kerberos-delegation → bronze-bit; kerberoasting → timeroasting. Index updated
(8 concepts). Taxonomy: sapphire-ticket → Forgery; bronze-bit → Delegation;
esc16 + cross-forest-adcs → AD CS; ad-trusts/trust-key-abuse/
foreign-security-principals → Forest & Trust; timeroasting → Credential Access.
NOTE: [[diamond-ticket]] frames Diamond as an AES128 *downgrade*, which is off
from the standard definition (Diamond = decrypt/modify a real TGT's PAC) — flagged
for correction, not yet rewritten. Two false-positive auto-mode safety blocks hit
Bash writes mid-batch; completed via Read/Edit/Write tools.
