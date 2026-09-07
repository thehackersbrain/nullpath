import { getCollection, type CollectionEntry } from "astro:content";
import {
  SECTIONS,
  sectionForSlug,
  hueFor,
  sectionById,
  type SectionDef,
} from "./taxonomy";

export type CollectionName = "concepts" | "notes" | "sources" | "entities";

// Priority decides the canonical page when a slug exists in several collections
// (e.g. `kerberoasting` is both a concept and a source summary).
const PRIORITY: CollectionName[] = ["concepts", "notes", "sources", "entities"];

const KIND_LABEL: Record<CollectionName, string> = {
  concepts: "concept",
  notes: "attack path",
  sources: "source",
  entities: "reference",
};

export interface WikiPage {
  slug: string;
  collection: CollectionName;
  kind: string;
  title: string;
  tags: string[];
  created?: Date;
  updated?: Date;
  url: string;
  section: string;
  entry: CollectionEntry<CollectionName>;
}

let _cache: WikiPage[] | null = null;

async function loadAll(): Promise<WikiPage[]> {
  if (_cache) return _cache;
  const names: CollectionName[] = ["concepts", "notes", "sources", "entities"];
  const pages: WikiPage[] = [];

  for (const name of names) {
    const entries = await getCollection(name);
    for (const entry of entries) {
      const slug = entry.id.replace(/\.md$/, "");
      pages.push({
        slug,
        collection: name,
        kind: KIND_LABEL[name],
        title: entry.data.title,
        tags: entry.data.tags ?? [],
        created: entry.data.created,
        updated: entry.data.updated,
        url: `/wiki/${slug}`,
        section: sectionForSlug(slug, name),
        entry: entry as CollectionEntry<CollectionName>,
      });
    }
  }
  _cache = pages;
  return pages;
}

/** Every page across every collection. */
export async function getAllPages(): Promise<WikiPage[]> {
  return loadAll();
}

/**
 * One canonical page per unique slug, chosen by collection priority.
 * This is what the `/wiki/[slug]` route iterates over.
 */
export async function getCanonicalPages(): Promise<WikiPage[]> {
  const all = await loadAll();
  const bySlug = new Map<string, WikiPage>();
  for (const p of all) {
    const existing = bySlug.get(p.slug);
    if (!existing || PRIORITY.indexOf(p.collection) < PRIORITY.indexOf(existing.collection)) {
      bySlug.set(p.slug, p);
    }
  }
  return [...bySlug.values()];
}

export async function resolvePage(slug: string): Promise<WikiPage | undefined> {
  const canon = await getCanonicalPages();
  return canon.find((p) => p.slug === slug);
}

export interface SectionView extends SectionDef {
  pages: WikiPage[];
  count: number;
  hue: number;
}

/** Sections with their pages attached, in taxonomy order. Empty ones dropped. */
export async function getSections(): Promise<SectionView[]> {
  const canon = await getCanonicalPages();
  const views: SectionView[] = [];

  for (const def of SECTIONS) {
    let pages: WikiPage[];
    if (def.id === "paths") {
      pages = canon.filter((p) => p.collection === "notes");
    } else {
      pages = def.slugs
        .map((slug) => canon.find((p) => p.slug === slug))
        .filter((p): p is WikiPage => Boolean(p));
    }
    if (pages.length) views.push({ ...def, pages, count: pages.length, hue: hueFor(def.id) });
  }

  // Anything not captured by the curated taxonomy.
  const claimed = new Set(views.flatMap((v) => v.pages.map((p) => p.slug)));
  const orphans = canon.filter(
    (p) => !claimed.has(p.slug) && p.collection !== "entities" && p.collection !== "sources"
  );
  if (orphans.length) {
    views.push({
      id: "other",
      title: "Other",
      blurb: "Pages not yet filed under a section.",
      chips: [],
      slugs: [],
      pages: orphans,
      count: orphans.length,
      hue: hueFor("other"),
    });
  }
  return views;
}

export async function getSectionView(id: string): Promise<SectionView | undefined> {
  const views = await getSections();
  return views.find((v) => v.id === id);
}

/** Pages sharing tags (and section) with the given page, best first. */
export async function getRelated(page: WikiPage, limit = 2): Promise<WikiPage[]> {
  const all = await getAllPages();
  const tagset = new Set(page.tags);
  return all
    .filter((p) => p.slug !== page.slug)
    .map((p) => ({
      p,
      shared:
        p.tags.filter((t) => tagset.has(t)).length +
        (p.section === page.section ? 0.5 : 0),
    }))
    .filter((x) => x.shared > 0)
    .sort((a, b) => b.shared - a.shared)
    .slice(0, limit)
    .map((x) => x.p);
}

/** Breadcrumb parent for a page, per collection. */
export function crumbFor(page: WikiPage): {
  title: string;
  href: string;
  sectionId?: string;
} {
  if (page.collection === "entities") return { title: "Entities", href: "/entities" };
  if (page.collection === "sources") return { title: "Sources", href: "/sources" };
  const s = sectionById(page.section);
  return {
    title: s?.title ?? "Wiki",
    href: s ? `/s/${s.id}` : "/sections",
    sectionId: s?.id,
  };
}

/**
 * Clean plain-text excerpt from raw markdown, for meta descriptions.
 * Strips code fences, headings, links/wikilinks, and markdown punctuation.
 */
export function excerpt(body: string, max = 160): string {
  let t = body ?? "";
  t = t.replace(/```[\s\S]*?```/g, " "); // code fences
  t = t.replace(/^\s*#{1,6}\s.*$/gm, " "); // headings
  t = t.replace(/^\s*[-*+]\s+/gm, ""); // list bullets
  t = t.replace(/`[^`]*`/g, ""); // inline code
  t = t.replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, (_m, a, b) => b || a); // wikilinks
  t = t.replace(/\[([^\]]+)\]\([^)]*\)/g, "$1"); // md links
  t = t.replace(/[*_>#]+/g, ""); // emphasis/quote marks
  t = t.replace(/\s+/g, " ").trim();
  if (t.length > max) t = t.slice(0, max - 1).replace(/\s+\S*$/, "") + "…";
  return t;
}

export function fmtDate(d?: Date): string {
  if (!d) return "";
  return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" });
}

export function fmtDateLong(d?: Date): string {
  if (!d) return "";
  return d.toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
}

/** Recently updated pages (concepts + notes), newest first. */
export async function getRecent(limit = 6): Promise<WikiPage[]> {
  const all = await getAllPages();
  return all
    .filter((p) => p.collection === "concepts" || p.collection === "notes")
    .filter((p) => p.updated)
    .sort((a, b) => (b.updated!.getTime() - a.updated!.getTime()))
    .slice(0, limit);
}

/** Compact search index shipped to the client. */
export async function getSearchIndex() {
  const canon = await getCanonicalPages();
  return canon.map((p) => ({
    title: p.title,
    url: p.url,
    kind: p.kind,
    section: p.section,
    tags: p.tags,
  }));
}
