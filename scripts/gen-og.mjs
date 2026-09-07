// Generates public/og-default.png (1200x630) from an inline SVG via sharp.
// Run: node scripts/gen-og.mjs
import sharp from "sharp";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const out = join(dirname(fileURLToPath(import.meta.url)), "..", "public", "og-default.png");

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#141a28"/>
      <stop offset="1" stop-color="#0f131c"/>
    </linearGradient>
    <radialGradient id="glow" cx="18%" cy="0%" r="70%">
      <stop offset="0" stop-color="#46c8e0" stop-opacity="0.28"/>
      <stop offset="1" stop-color="#46c8e0" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="glow2" cx="100%" cy="0%" r="60%">
      <stop offset="0" stop-color="#9a8cf0" stop-opacity="0.22"/>
      <stop offset="1" stop-color="#9a8cf0" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <rect width="1200" height="630" fill="url(#bg)"/>
  <g stroke="#2a3446" stroke-width="1" opacity="0.35">
    ${Array.from({ length: 26 }, (_, i) => `<line x1="${i * 48}" y1="0" x2="${i * 48}" y2="630"/>`).join("")}
    ${Array.from({ length: 14 }, (_, i) => `<line x1="0" y1="${i * 48}" x2="1200" y2="${i * 48}"/>`).join("")}
  </g>
  <rect width="1200" height="630" fill="url(#glow)"/>
  <rect width="1200" height="630" fill="url(#glow2)"/>

  <g transform="translate(80,86)">
    <rect width="66" height="66" rx="15" fill="#1b2130" stroke="#2f3a4e"/>
    <text x="33" y="50" text-anchor="middle" font-family="'DejaVu Sans Mono', monospace" font-size="42" font-weight="700" fill="#46c8e0">/</text>
    <text x="88" y="48" font-family="'DejaVu Sans', sans-serif" font-size="34" font-weight="700" fill="#eef1f7">Nullpath</text>
  </g>

  <text x="80" y="320" font-family="'DejaVu Sans', sans-serif" font-size="76" font-weight="700" fill="#f4f6fb">The Active Directory</text>
  <text x="80" y="404" font-family="'DejaVu Sans', sans-serif" font-size="76" font-weight="700" fill="#f4f6fb">attack reference.</text>
  <rect x="82" y="440" width="120" height="5" rx="2" fill="#46c8e0"/>

  <text x="80" y="500" font-family="'DejaVu Sans', sans-serif" font-size="27" fill="#9aa4bd">Kerberos · delegation · AD CS · NTLM relay · attack paths</text>

  <text x="80" y="576" font-family="'DejaVu Sans Mono', monospace" font-size="22" fill="#6b7690">124 cross-linked notes · commands + detection footprint</text>
</svg>`;

const png = await sharp(Buffer.from(svg)).png().toBuffer();
writeFileSync(out, png);
console.log("wrote", out, png.length, "bytes");
