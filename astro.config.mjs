import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import sitemap from "@astrojs/sitemap";
import rehypeSlug from "rehype-slug";
import rehypeAutolinkHeadings from "rehype-autolink-headings";
import { remarkWikilinks } from "./src/lib/wikilinks.js";

// Update `site` to your deployed origin before building for production.
export default defineConfig({
  site: "https://nullpath.thehackersbrain.dev",
  integrations: [
    sitemap({
      changefreq: "weekly",
      priority: 0.7,
      serialize(item) {
        const path = new URL(item.url).pathname;
        if (path === "/") item.priority = 1.0;
        else if (/\/(wiki|source)\//.test(path)) item.priority = 0.8;
        else if (/\/s\//.test(path)) item.priority = 0.6;
        return item;
      },
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
  markdown: {
    remarkPlugins: [remarkWikilinks],
    rehypePlugins: [
      rehypeSlug,
      [
        rehypeAutolinkHeadings,
        {
          behavior: "wrap",
          properties: { className: ["heading-anchor"] },
        },
      ],
    ],
    shikiConfig: {
      // Cool-toned theme to match the cobalt/cyan palette.
      // Swap for "night-owl", "poimandres", "catppuccin-macchiato" or
      // "one-dark-pro" if you prefer a different feel.
      theme: "tokyo-night",
      wrap: false,
    },
  },
});
