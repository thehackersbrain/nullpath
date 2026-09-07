// Curated sidebar / topic-map taxonomy for the wiki.
// Concepts are grouped into kill-chain sections; attack-path notes get their
// own section. Any concept not listed here lands in `other` (kept out of the
// nav unless it actually has pages), so new pages are never lost.

export interface SectionDef {
  id: string;
  title: string;
  blurb: string;
  chips: string[]; // tool/tag chips shown on the home topic-map card
  slugs: string[];
}

export const SECTIONS: SectionDef[] = [
  {
    id: "fundamentals",
    title: "AD & Kerberos Fundamentals",
    blurb:
      "The objects, protocols and stores an attacker reasons over: directory structure, Kerberos flow, NTLM, and where the secrets live.",
    chips: ["kerberos", "ldap", "ntlm"],
    slugs: [
      "ad-structure",
      "domain-controller",
      "ldap",
      "smb",
      "sam-database",
      "ntds-dit",
      "lsass",
      "credential-dumping",
      "service-account",
      "service-principal-name",
      "kerberos-authentication",
      "tgt-tgs",
      "kerberos-preauth",
      "kerberos-pac",
      "kerberos-encryption-types",
      "krbtgt",
      "ntlm",
      "ccache",
      "gmsa",
      "laps",
      "kerberos-armoring-fast",
      "ad-tier-model",
    ],
  },
  {
    id: "credential-access",
    title: "Credential Access",
    blurb:
      "Getting authentication material out of the domain: roasting, replication, and reusing hashes, keys, tickets and certs.",
    chips: ["impacket", "rubeus", "hashcat"],
    slugs: [
      "password-spraying",
      "kerberoasting",
      "as-rep-roasting",
      "dcsync",
      "pass-the-hash-and-ticket",
      "pass-the-key",
      "overpass-the-hash",
      "pass-the-cert",
      "shadow-credentials",
      "pkinit-unpac-the-hash",
      "dpapi",
      "timeroasting",
      "targeted-roasting",
    ],
  },
  {
    id: "forgery",
    title: "Kerberos Ticket Forgery",
    blurb:
      "Once you hold a signing secret, forge tickets offline: Golden, Silver, Diamond, and SID-history injection.",
    chips: ["mimikatz", "rubeus", "ticketer"],
    slugs: ["golden-silver-tickets", "diamond-ticket", "sapphire-ticket", "nopac", "ms14-068", "sid-history"],
  },
  {
    id: "delegation",
    title: "Delegation Abuse",
    blurb:
      "Unconstrained, constrained and resource-based delegation misconfigurations that turn into impersonation and privilege escalation.",
    chips: ["rubeus", "impacket", "s4u"],
    slugs: [
      "kerberos-delegation",
      "unconstrained-delegation",
      "resource-based-constrained-delegation",
      "s4u2self-s4u2proxy",
      "bronze-bit",
    ],
  },
  {
    id: "coercion-relay",
    title: "Coercion & NTLM Relay",
    blurb:
      "Force a machine to authenticate, then relay it: PetitPotam, the printer bug, mitm6/WPAD, and Kerberos relay.",
    chips: ["ntlmrelayx", "mitm6", "coercer"],
    slugs: [
      "ntlm-relay-coercion",
      "printer-bug",
      "mitm6-ipv6-relay",
      "wpad",
      "llmnr-nbt-ns-poisoning",
      "krbrelay",
    ],
  },
  {
    id: "adcs",
    title: "AD CS / PKI (ESC)",
    blurb:
      "Active Directory Certificate Services misconfigurations — the ESC1–ESC15 family — that mint authentication certificates.",
    chips: ["certipy", "certify", "adcs"],
    slugs: [
      "ad-cs-esc-attacks",
      "pki-and-ad-cs-architecture",
      "certificate-templates",
      "certificate-mapping",
      "ntauthcertificates",
      "esc1",
      "esc2",
      "esc3",
      "esc4",
      "esc5",
      "esc6",
      "esc7",
      "esc8",
      "esc9",
      "esc10",
      "esc11",
      "esc12",
      "esc13",
      "esc14",
      "esc15",
      "esc16",
      "cross-forest-adcs",
      "golden-certificate",
    ],
  },
  {
    id: "acl",
    title: "ACL & Object Control",
    blurb:
      "Abusing DACLs on directory objects and GPOs — GenericAll, WriteDACL, WriteOwner — to walk edges toward Domain Admin.",
    chips: ["bloodhound", "powerview", "gpoabuse"],
    slugs: ["acl-abuse", "gpo-abuse"],
  },
  {
    id: "local-privesc",
    title: "Windows Local Privesc & Host",
    blurb:
      "Winning the box: low-priv shell → local admin/SYSTEM via UAC, tokens, services, tasks, pipes, DLLs and PATH, plus the Potato family — and keeping it.",
    chips: ["winpeas", "uac", "potato"],
    slugs: [
      "windows-privilege-escalation",
      "winpeas",
      "uac-bypass",
      "token-privilege-escalation",
      "service-privesc",
      "scheduled-task-abuse",
      "named-pipe-hijacking",
      "dll-hijacking-sideloading",
      "environment-variable-attack",
      "potato-family",
      "windows-local-persistence",
    ],
  },
  {
    id: "lateral",
    title: "Lateral Movement & Execution",
    blurb:
      "Turning credentials into code execution across hosts: SMB, WMI, WinRM, PSRemoting and RDP.",
    chips: ["impacket", "netexec", "evil-winrm"],
    slugs: ["remote-execution", "kerberos-double-hop", "mssql-abuse"],
  },
  {
    id: "persistence",
    title: "Persistence & Domain Dominance",
    blurb:
      "Durable footholds once you own the domain: DCShadow, Skeleton Key, AdminSDHolder and DSRM backdoors.",
    chips: ["mimikatz", "dcshadow", "adminsdholder"],
    slugs: ["ad-persistence", "dcshadow", "skeleton-key"],
  },
  {
    id: "sccm",
    title: "SCCM & Imaging",
    blurb:
      "Attacking the deployment plane: SCCM/MECM network access accounts and WDS/MDT imaging shares.",
    chips: ["sccmhunter", "pxethief"],
    slugs: ["sccm-abuse", "wds-mdt-discovery"],
  },
  {
    id: "trusts",
    title: "Forest & Trust Attacks",
    blurb:
      "Crossing the domain and forest boundary: SID filtering, TREAT_AS_EXTERNAL and trust-key abuse.",
    chips: ["impacket", "mimikatz"],
    slugs: [
      "ad-trusts",
      "ad-trust-attacks",
      "trust-key-abuse",
      "foreign-security-principals",
    ],
  },
  {
    id: "detection",
    title: "Detection & Hardening",
    blurb:
      "The defender's side: tiering baselines, honeytokens and the log artifacts each technique leaves behind.",
    chips: ["sigma", "4769", "honeytokens"],
    slugs: ["ad-tiering-and-hardening", "honeytokens", "kerberos-event-ids"],
  },
  {
    id: "ad-ops",
    title: "AD Ops & Methodology",
    blurb:
      "How an engagement actually runs: the kill-chain arc, situational awareness, C2/pivoting and staying quiet.",
    chips: ["methodology", "opsec", "pivoting"],
    slugs: [
      "redteam-ad-methodology",
      "situational-awareness",
      "ad-enumeration",
      "c2-and-pivoting-ad",
      "pivoting-and-tunneling",
      "defense-evasion-ad",
      "opsec-ad-tradecraft",
      "bloodhound-opsec",
      "ticket-and-credential-opsec",
      "foothold-playbook",
      "ad-error-decoder",
      "ticket-manipulation",
    ],
  },
  {
    id: "re-malware",
    title: "Reverse Engineering & Malware",
    blurb:
      "Reading and building Windows binaries: the PE format, shellcode, API hashing, packing, injection, and the static + dynamic analysis workflow.",
    chips: ["ghidra", "x64dbg", "shellcode"],
    slugs: [
      "reverse-engineering-workflow",
      "pe-executable",
      "shellcode",
      "api-hashing",
      "process-injection",
      "windows-syscalls",
      "anti-debugging",
      "anti-analysis",
      "packer-unpacking",
      "ghidra",
      "x64dbg",
      "upx",
    ],
  },
  {
    id: "c2-evasion",
    title: "C2, Evasion & Host Detection",
    blurb:
      "Running C2 and staying quiet: beaconing, Cobalt Strike, AMSI/ETW evasion, and the Sysmon/Sigma detection they're built against.",
    chips: ["cobalt-strike", "sigma", "beaconing"],
    slugs: [
      "beaconing",
      "amsi",
      "etw",
      "cobalt-strike",
      "meterpreter",
      "modern-c2-frameworks",
      "sysmon",
      "sigma",
    ],
  },
  {
    id: "paths",
    title: "Attack Paths",
    blurb:
      "End-to-end chains: the specific misconfiguration, the tooling, and the walk from foothold to domain dominance.",
    chips: ["chain", "foothold→DA"],
    slugs: [], // populated dynamically from the notes collection
  },
];

// A distinct hue per section for colour-coded wayfinding (dots, hover glow).
export const SECTION_HUE: Record<string, number> = {
  fundamentals: 210,
  "credential-access": 30,
  forgery: 60,
  delegation: 285,
  "coercion-relay": 330,
  adcs: 150,
  acl: 255,
  "local-privesc": 265,
  lateral: 190,
  persistence: 15,
  sccm: 100,
  trusts: 305,
  detection: 170,
  "ad-ops": 355,
  "re-malware": 200,
  "c2-evasion": 130,
  paths: 235,
  other: 255,
};

export function hueFor(id: string): number {
  return SECTION_HUE[id] ?? 208;
}

const SLUG_TO_SECTION = new Map<string, string>();
for (const s of SECTIONS) {
  for (const slug of s.slugs) SLUG_TO_SECTION.set(slug, s.id);
}

export function sectionForSlug(slug: string, collection: string): string {
  if (collection === "notes") return "paths";
  return SLUG_TO_SECTION.get(slug) ?? "other";
}

export function sectionById(id: string): SectionDef | undefined {
  return SECTIONS.find((s) => s.id === id);
}
