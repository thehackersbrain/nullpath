import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const pageSchema = z.object({
  title: z.string(),
  type: z.string().optional(),
  created: z.coerce.date().optional(),
  updated: z.coerce.date().optional(),
  tags: z.array(z.string()).default([]),
});

const mk = (dir: string) =>
  defineCollection({
    loader: glob({ pattern: "**/*.md", base: `./wiki/${dir}` }),
    schema: pageSchema,
  });

// Root-level meta files (log.md, index.md) have no frontmatter, so use a
// fully-optional schema.
const meta = defineCollection({
  loader: glob({ pattern: "{index,log}.md", base: "./wiki" }),
  schema: z.object({
    title: z.string().optional(),
    type: z.string().optional(),
    created: z.coerce.date().optional(),
    updated: z.coerce.date().optional(),
    tags: z.array(z.string()).default([]),
  }),
});

export const collections = {
  concepts: mk("concepts"),
  notes: mk("notes"),
  entities: mk("entities"),
  sources: mk("sources"),
  meta,
};
