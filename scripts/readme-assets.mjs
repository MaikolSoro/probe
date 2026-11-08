// Generates the README banner and the animated terminal demo (both SVG, so
// GitHub renders them crisp and the terminal animates without a GIF).
// Run: node scripts/readme-assets.mjs
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';

const out = 'docs/assets';
mkdirSync(out, { recursive: true });
const mark = `data:image/png;base64,${readFileSync('assets/avenzoq-mark-transparent.png').toString('base64')}`;
const SANS = `-apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif`;
const MONO = `ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace`;
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

// ---------- banner ----------
const stats = [
  ['4', 'SCAN MODES', '#ff4d6d'],
  ['36', 'CHECKS + LLM JUDGE', '#f47bff'],
  ['32', 'ATTACK PROBES', '#a98bff'],
  ['10', 'OWASP LLM TOP 10', '#ff8a3d'],
  ['ES/EN', 'CLIENT REPORTS', '#5eead4'],
];
const modes = [
  ['MCP SERVERS', 'tool poisoning · rug pulls'],
  ['AI AGENTS', 'OpenAI · Anthropic · any JSON API'],
  ['CLIENT CONFIGS', 'Claude · Cursor · VS Code'],
  ['SKILLS', 'SKILL.md · hooks · installers'],
];
const banner = `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="420" viewBox="0 0 1280 420">
  <defs>
    <radialGradient id="g1" cx="18%" cy="20%" r="55%"><stop offset="0" stop-color="#8247ff" stop-opacity=".35"/><stop offset="1" stop-color="#8247ff" stop-opacity="0"/></radialGradient>
    <radialGradient id="g2" cx="85%" cy="90%" r="55%"><stop offset="0" stop-color="#f47bff" stop-opacity=".22"/><stop offset="1" stop-color="#f47bff" stop-opacity="0"/></radialGradient>
    <linearGradient id="brand" x1="0" x2="1"><stop offset="0" stop-color="#8247ff"/><stop offset=".55" stop-color="#f47bff"/><stop offset="1" stop-color="#ff8a3d"/></linearGradient>
    <pattern id="dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="#ffffff" fill-opacity=".06"/></pattern>
    <style>
      .eyebrow { font: 600 11px ${MONO}; letter-spacing: .22em; fill: #6b7280; }
      .title { font: 800 92px ${SANS}; letter-spacing: -3px; }
      .sub { font: 400 19px ${SANS}; fill: #c9cdd3; }
      .mode { font: 700 11px ${MONO}; letter-spacing: .14em; fill: #f4f4f5; }
      .modesub { font: 400 11px ${MONO}; fill: #8b93a1; }
      .num { font: 800 34px ${SANS}; }
      .lbl { font: 600 9.5px ${MONO}; letter-spacing: .16em; fill: #8b93a1; }
      .pulse { animation: pulse 2.4s ease-in-out infinite; }
      @keyframes pulse { 0%,100% { opacity: .35 } 50% { opacity: 1 } }
    </style>
  </defs>
  <rect width="1280" height="420" rx="18" fill="#0b0d10"/>
  <rect width="1280" height="420" rx="18" fill="url(#dots)"/>
  <rect width="1280" height="420" rx="18" fill="url(#g1)"/>
  <rect width="1280" height="420" rx="18" fill="url(#g2)"/>
  <text x="48" y="44" class="eyebrow">AVENZOQ / PROBE · AI AGENT SECURITY</text>
  <text x="1232" y="44" class="eyebrow" text-anchor="end">github.com/MaikolSoro/probe</text>
  <image href="${mark}" x="48" y="82" width="104" height="104"/>
  <text x="176" y="166" class="title"><tspan fill="#ffffff">avenzoq</tspan><tspan fill="#4b5563"> / </tspan><tspan fill="url(#brand)">probe</tspan></text>
  <rect x="176" y="182" width="430" height="3" rx="2" fill="url(#brand)"/>
  <text x="176" y="220" class="sub">Red-team your AI agents, MCP servers and skills — before attackers do.</text>
  <g transform="translate(1012 82)">
    <rect width="220" height="98" rx="10" fill="#14171c" stroke="#ff4d6d" stroke-opacity=".6"/>
    <circle cx="18" cy="22" r="4" fill="#ff4d6d" class="pulse"/>
    <text x="30" y="26" class="mode" fill="#ff4d6d" style="fill:#ff4d6d">OPEN SOURCE CLI</text>
    <text x="18" y="52" class="modesub">node ≥ 20 · zero config</text>
    <text x="18" y="70" class="modesub">exit 1 on critical/high</text>
    <text x="18" y="88" class="modesub">md · json · html · pdf</text>
  </g>
  ${modes
    .map(
      ([t, s], i) => `<g transform="translate(${48 + i * 300} 256)">
    <text x="0" y="0" class="mode"><tspan fill="#ff4d6d">▸</tspan> ${t}</text>
    <text x="14" y="18" class="modesub">${s}</text></g>`,
    )
    .join('\n  ')}
  <line x1="48" y1="304" x2="1232" y2="304" stroke="#262b33"/>
  ${stats
    .map(
      ([n, l, c], i) => `<g transform="translate(${48 + i * 237 + 100} 352)" text-anchor="middle">
    <text class="num" fill="${c}">${n}</text><text y="22" class="lbl">${l}</text></g>`,
    )
    .join('\n  ')}
</svg>
`;
writeFileSync(`${out}/banner.svg`, banner);

// ---------- animated terminal ----------
const C = { dim: '#6b7280', text: '#e5e7eb', prompt: '#5eead4', critical: '#e879f9', high: '#f87171', medium: '#fbbf24', low: '#22d3ee', ok: '#4ade80', head: '#ffffff' };
const lines = [
  ['cmd', '$ probe mcp --call-readonly --pdf -- node server.js'],
  ['blank', ''],
  ['head', 'AVENZOQ Probe · MCP · node server.js'],
  ['dim', 'Server: demo-store-tools 1.0.0 · 6 tools'],
  ['dim', 'Read-only tools called: list_products, get_latest_reviews'],
  ['blank', ''],
  ['critical', 'CRITICAL', 'get_weather          ', 'Tool description contains <IMPORTANT> tags'],
  ['critical', 'CRITICAL', 'get_weather          ', 'Tool description references ~/.ssh/id_rsa'],
  ['critical', 'CRITICAL', 'get_latest_reviews   ', 'Tool output tells the model to ignore its instructions'],
  ['high', 'HIGH    ', 'run_command          ', 'Tool grants code or command execution'],
  ['high', 'HIGH    ', '(server)             ', 'Private data and an outbound channel exposed together'],
  ['medium', 'MEDIUM  ', 'run_command          ', 'Claims to be read-only but changes state'],
  ['low', 'LOW     ', 'read_customer_records', 'Free-form "query" parameter without constraints'],
  ['dim', '…and 7 more'],
  ['blank', ''],
  ['summary', 'critical: 7 · high: 2 · medium: 2 · low: 3'],
  ['ok', '✔ Reports written to reports/: report.md, report.json, report.html, report.pdf'],
];
const W = 960;
const lineH = 22;
const top = 64;
const H = top + lines.length * lineH + 34;
const T = 13; // seconds per loop
const cmdChars = lines[0][1].length;
const typeEnd = 2.6; // command fully typed at this time
const step = 0.32;

// Each line appears at its own time and everything fades out at the end of the loop.
const at = (i) => (i === 0 ? 0.3 : typeEnd + 0.5 + i * step);
const pct = (s) => ((s / T) * 100).toFixed(2);
let css = '';
lines.forEach((_, i) => {
  if (i === 0) return;
  css += `.l${i}{opacity:0;animation:l${i} ${T}s steps(1,end) infinite}@keyframes l${i}{0%{opacity:0}${pct(at(i))}%{opacity:1}96%{opacity:1}100%{opacity:0}}\n`;
});
css += `.typing{transform-box:fill-box;transform-origin:left;transform:scaleX(0);animation:type ${T}s steps(${cmdChars},end) infinite}@keyframes type{0%{transform:scaleX(0)}${pct(0.3)}%{transform:scaleX(0)}${pct(typeEnd)}%{transform:scaleX(1)}96%{transform:scaleX(1)}100%{transform:scaleX(0)}}\n`;
css += `.cursor{animation:blink 1s steps(1,end) infinite}@keyframes blink{50%{opacity:0}}\n`;

const row = (l, i) => {
  const y = top + i * lineH;
  const [kind] = l;
  if (kind === 'blank') return '';
  if (kind === 'cmd')
    return `<clipPath id="cmdclip"><rect class="typing" x="28" y="${y - 16}" height="22" width="${cmdChars * 8.42 + 4}"/></clipPath>
  <text x="28" y="${y}" clip-path="url(#cmdclip)"><tspan fill="${C.prompt}">$</tspan><tspan fill="${C.text}">${esc(l[1].slice(1))}</tspan></text>`;
  if (['critical', 'high', 'medium', 'low'].includes(kind))
    return `<text x="28" y="${y}" class="l${i}"><tspan fill="${C[kind]}" font-weight="700">${l[1]}</tspan><tspan fill="${C.text}" xml:space="preserve"> ${esc(l[2])}  </tspan><tspan fill="#c9cdd3">${esc(l[3])}</tspan></text>`;
  const fill = { head: C.head, dim: C.dim, summary: C.text, ok: C.ok }[kind];
  return `<text x="28" y="${y}" class="l${i}" fill="${fill}"${kind === 'head' ? ' font-weight="700"' : ''}>${esc(l[1])}</text>`;
};

const terminal = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <style>
    text { font: 13.5px ${MONO}; white-space: pre; }
    .title { font: 12px ${SANS}; fill: #8b93a1; }
    ${css}
  </style>
  <rect width="${W}" height="${H}" rx="14" fill="#0b0d10"/>
  <rect x=".5" y=".5" width="${W - 1}" height="${H - 1}" rx="14" fill="none" stroke="#262b33"/>
  <circle cx="24" cy="22" r="6" fill="#ff5f57"/><circle cx="44" cy="22" r="6" fill="#febc2e"/><circle cx="64" cy="22" r="6" fill="#28c840"/>
  <text x="${W / 2}" y="26" class="title" text-anchor="middle">probe — zsh</text>
  <line x1="0" y1="40" x2="${W}" y2="40" stroke="#1f242b"/>
  ${lines.map(row).join('\n  ')}
  <rect class="cursor l${lines.length - 1}" x="28" y="${top + lines.length * lineH - 14}" width="8" height="16" fill="${C.prompt}"/>
</svg>
`;
writeFileSync(`${out}/terminal.svg`, terminal);
console.log(`Wrote ${out}/banner.svg and ${out}/terminal.svg`);
