# Nullpath — wiki frontend

Astro + Tailwind CSS v4 + TypeScript static site that renders the markdown wiki
in `../wiki` using the **Nullpath** design (see `_design/`).

## Run

```bash
npm install
npm run dev        # http://localhost:4321
npm run build      # static output → dist/
npm run preview    # serve the built dist/
```

## How it works

- **Content** — `src/content.config.ts` loads the four wiki collections
  (`concepts`, `notes`, `entities`, `sources`) directly from `../wiki/*` via
  Astro's glob loader. No files are copied; edit the wiki and rebuild.
- **Routing** — every page is served at `/wiki/<slug>`. When a slug exists in
  more than one collection (e.g. `kerberoasting` is a concept *and* a source),
  the canonical page is chosen by priority: concept → note → source → entity
  (`src/lib/wiki.ts`).
- **Wikilinks** — `[[slug]]` and `[[slug|alias]]` are rewritten to real links
  by a remark plugin (`src/lib/wikilinks.js`). Build-time check confirmed all
  115 referenced targets resolve.
- **Sidebar / sections** — the kill-chain taxonomy lives in
  `src/lib/taxonomy.ts`. Any concept not assigned to a section falls into an
  `Other` bucket, so new pages are never dropped — add its slug to a section to
  file it.
- **Search** — client-side over a compact index inlined at build time (the `/`
  command palette in the header, and the full `/search` page).
- **Code blocks** — Shiki (`vitesse-dark`), enhanced client-side with a
  language label + copy button. `bash` / `powershell` fences are highlighted.

## Deploy

Static output in `dist/` — host anywhere (Netlify, Vercel, Cloudflare Pages,
GitHub Pages, S3). Set the real origin in `astro.config.mjs` (`site:`) before
building so the sitemap uses correct URLs.

## Adding content

Write markdown in `../wiki/concepts` or `../wiki/notes` with the standard
frontmatter (`title`, `type`, `created`, `updated`, `tags`). To place a new
concept in the nav, add its slug to the relevant section in
`src/lib/taxonomy.ts`. Attack-path notes are picked up automatically.
