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
      "kerberoasting",
      "as-rep-roasting",
      "dcsync",
      "pass-the-hash-and-ticket",
      "pass-the-key",
      "overpass-the-hash",
      "pass-the-cert",
      "shadow-credentials",
      "pkinit-unpac-the-hash",
    ],
  },
  {
    id: "forgery",
    title: "Kerberos Ticket Forgery",
    blurb:
      "Once you hold a signing secret, forge tickets offline: Golden, Silver, Diamond, and SID-history injection.",
    chips: ["mimikatz", "rubeus", "ticketer"],
    slugs: ["golden-silver-tickets", "diamond-ticket", "sid-history"],
  },
  {
    id: "delegation",
    title: "Delegation Abuse",
    blurb:
      "Unconstrained, constrained and resource-based delegation misconfigurations that turn into impersonation and privilege escalation.",
    chips: ["rubeus", "impacket", "s4u"],
    slugs: [
      "kerberos-delegation",
      "resource-based-constrained-delegation",
      "s4u2self-s4u2proxy",
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
      "krbrelay",
    ],
  },
  {
    id: "adcs",
    title: "AD CS / PKI (ESC)",
    blurb:
      "Active Directory Certificate Services misconfigurations — the ESC1–ESC15 family — that mint authentication certificates.",
    chips: ["certipy", "certify", "adcs"],
    slugs: ["ad-cs-esc-attacks"],
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
    id: "lateral",
    title: "Lateral Movement & Execution",
    blurb:
      "Turning credentials into code execution across hosts: SMB, WMI, WinRM, PSRemoting and RDP.",
    chips: ["impacket", "crackmapexec", "evil-winrm"],
    slugs: ["remote-execution"],
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
    slugs: ["ad-trust-attacks"],
  },
  {
    id: "detection",
    title: "Detection & Hardening",
    blurb:
      "The defender's side: tiering baselines, honeytokens and the log artifacts each technique leaves behind.",
    chips: ["sigma", "4769", "honeytokens"],
    slugs: ["ad-tiering-and-hardening", "honeytokens"],
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
  lateral: 190,
  persistence: 15,
  sccm: 100,
  trusts: 305,
  detection: 170,
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
