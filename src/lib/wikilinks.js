import { visit } from "unist-util-visit";

// Turn a wikilink target into the slug we route on.
// Filenames in wiki/ are already lowercase-kebab, so this is mostly a trim,
// but we normalise spaces/casing so a stray `[[Pass The Key]]` still resolves.
export function normalizeSlug(target) {
  return target
    .trim()
    .toLowerCase()
    .replace(/\.md$/, "")
    .replace(/\s+/g, "-");
}

const WIKILINK = /\[\[([^\]]+?)\]\]/g;

/**
 * Remark plugin: rewrite Obsidian `[[slug]]` / `[[slug|alias]]` links into
 * real links to `/wiki/<slug>`. Unknown targets still link (the route renders
 * a "not documented yet" state), matching the design's 404.
 */
export function remarkWikilinks() {
  return (tree) => {
    visit(tree, "text", (node, index, parent) => {
      if (!parent || index === null || node.value.indexOf("[[") === -1) return;

      const value = node.value;
      const children = [];
      let last = 0;
      let m;
      WIKILINK.lastIndex = 0;

      while ((m = WIKILINK.exec(value)) !== null) {
        if (m.index > last) {
          children.push({ type: "text", value: value.slice(last, m.index) });
        }
        const inner = m[1];
        const pipe = inner.indexOf("|");
        const target = pipe === -1 ? inner : inner.slice(0, pipe);
        const label = pipe === -1 ? inner : inner.slice(pipe + 1);
        const slug = normalizeSlug(target);

        children.push({
          type: "link",
          url: `/wiki/${slug}`,
          data: { hProperties: { className: ["wikilink"], "data-slug": slug } },
          children: [{ type: "text", value: label.trim() }],
        });
        last = m.index + m[0].length;
      }

      if (children.length === 0) return;
      if (last < value.length) {
        children.push({ type: "text", value: value.slice(last) });
      }

      parent.children.splice(index, 1, ...children);
      return index + children.length;
    });
  };
}
