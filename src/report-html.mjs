// Client-facing report: a self-contained HTML page (fonts and logo embedded)
// that can also be printed to PDF with headless Chrome.
import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ORDER, counts } from './report.mjs';
import { guidance } from './guidance.mjs';

const assets = join(dirname(fileURLToPath(import.meta.url)), '..', 'assets');
const asset = (file, type) => `data:${type};base64,${readFileSync(join(assets, file)).toString('base64')}`;
const esc = (v = '') => String(v).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

const T = {
  en: {
    doc: 'AI Security Report',
    target: 'Target',
    type: 'Type',
    date: 'Date',
    client: 'Prepared for',
    mcp: 'MCP server',
    agent: 'AI chat agent',
    overall: 'Overall risk',
    sev: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', none: 'No findings' },
    summary: 'Executive summary',
    scope: 'Scope and method',
    overview: 'Findings overview',
    details: 'Findings in detail',
    probes: 'Prompt-injection probes',
    where: 'Where',
    what: 'What it means',
    fix: 'How to fix it',
    evidence: 'Evidence',
    result: { vulnerable: 'Obeyed', resisted: 'Resisted', error: 'Error' },
    found: (n, c) =>
      n
        ? `We found <strong>${n} issue${n === 1 ? '' : 's'}</strong>. ${c.critical + c.high ? `<strong>${c.critical + c.high}</strong> of them are critical or high and should be fixed before this system is used in production.` : 'None of them is critical or high.'}`
        : 'These checks found no issues. That does not prove the system is secure; it means none of these known problems were detected.',
    scopeMcp: (n) => `Static analysis of the ${n} tools the MCP server exposes: names, descriptions, input schemas and annotations. No tool was executed for this part.`,
    scopeCalled: (list) => `Tools that declare themselves read-only and take no arguments were also called once (${list}) to check their output for planted instructions.`,
    scopeAgent: (n) => `${n} test messages were sent to the chat endpoint. Each one tries to make the agent follow untrusted instructions and carries a random code; if the code comes back, the agent obeyed.`,
    disclaimer: 'This report covers only the checks listed above, on the date shown. A clean result does not guarantee that a system is secure. Tests were run only on systems the client owns or authorized.',
  },
  es: {
    doc: 'Informe de seguridad de IA',
    target: 'Sistema revisado',
    type: 'Tipo',
    date: 'Fecha',
    client: 'Preparado para',
    mcp: 'Servidor MCP',
    agent: 'Agente de chat con IA',
    overall: 'Riesgo general',
    sev: { critical: 'Crítico', high: 'Alto', medium: 'Medio', low: 'Bajo', none: 'Sin hallazgos' },
    summary: 'Resumen ejecutivo',
    scope: 'Alcance y método',
    overview: 'Resumen de hallazgos',
    details: 'Hallazgos en detalle',
    probes: 'Pruebas de inyección de instrucciones',
    where: 'Dónde',
    what: 'Qué significa',
    fix: 'Cómo corregirlo',
    evidence: 'Evidencia',
    result: { vulnerable: 'Obedeció', resisted: 'Resistió', error: 'Error' },
    found: (n, c) =>
      n
        ? `Encontramos <strong>${n} hallazgo${n === 1 ? '' : 's'}</strong>. ${c.critical + c.high ? `<strong>${c.critical + c.high}</strong> son críticos o altos y conviene corregirlos antes de usar este sistema en producción.` : 'Ninguno es crítico ni alto.'}`
        : 'Estas pruebas no encontraron problemas. Eso no garantiza que el sistema sea seguro: significa que no se detectó ninguno de estos problemas conocidos.',
    scopeMcp: (n) => `Análisis estático de las ${n} herramientas que expone el servidor MCP: nombres, descripciones, parámetros y anotaciones. En esta parte no se ejecutó ninguna herramienta.`,
    scopeCalled: (list) => `Además, se llamó una vez a las herramientas que se declaran de solo lectura y no reciben parámetros (${list}) para revisar si su respuesta trae instrucciones plantadas.`,
    scopeAgent: (n) => `Se enviaron ${n} mensajes de prueba al chat. Cada uno intenta que el agente siga instrucciones no confiables y lleva un código aleatorio; si el código vuelve en la respuesta, el agente obedeció.`,
    disclaimer: 'Este informe cubre solo las pruebas descritas, en la fecha indicada. Un resultado limpio no garantiza que un sistema sea seguro. Las pruebas se hicieron únicamente sobre sistemas del cliente o con su autorización.',
  },
};

// For agent findings the useful "where" is the probe that succeeded.
const whereOf = (f) => (f.tool === '(agent)' ? `${f.tool} · ${f.id.replace(/^agent-/, '')}` : f.tool);

// Several matches of the same rule on the same tool become one card with all the evidence.
function group(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = `${f.id}|${f.tool}`;
    if (!map.has(key)) map.set(key, { ...f, evidences: [] });
    if (f.evidence) map.get(key).evidences.push(f.evidence);
  }
  return [...map.values()].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));
}

export function toHtml(scan, { lang = 'en', client = '', date = new Date() } = {}) {
  const t = T[lang] ?? T.en;
  // Count grouped issues so the totals match the cards the client reads.
  const items = group(scan.findings);
  const c = counts(items);
  const overall = ORDER.find((s) => c[s]) ?? 'none';
  const fmtDate = date.toLocaleDateString(lang === 'es' ? 'es-CR' : 'en-US', { day: 'numeric', month: 'long', year: 'numeric' });

  const scope = [];
  if (scan.kind === 'mcp') {
    scope.push(t.scopeMcp(scan.tools.length));
    if (scan.called?.length) scope.push(t.scopeCalled(scan.called.map((x) => x.tool).join(', ')));
  } else scope.push(t.scopeAgent(scan.results.length));

  const card = (f, i) => {
    const g = guidance(f.id, lang) ?? { title: f.title, explain: f.detail, fix: '' };
    return `<article class="card sev-${f.severity}">
      <header><span class="num">${String(i + 1).padStart(2, '0')}</span><span class="pill">${t.sev[f.severity]}</span><h3>${esc(g.title)}</h3></header>
      <dl>
        <dt>${t.where}</dt><dd class="mono">${esc(whereOf(f))}</dd>
        <dt>OWASP</dt><dd>${esc(f.owasp)}</dd>
      </dl>
      <h4>${t.what}</h4><p>${esc(g.explain)}</p>
      ${g.fix ? `<h4>${t.fix}</h4><p>${esc(g.fix)}</p>` : ''}
      ${f.evidences.length ? `<h4>${t.evidence}</h4><pre>${f.evidences.map(esc).join('\n')}</pre>` : ''}
    </article>`;
  };

  return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8" />
<title>${esc(t.doc)} — ${esc(scan.target)}</title>
<style>
  @font-face { font-family: Geist; src: url(${asset('geist-latin.woff2', 'font/woff2')}) format('woff2'); font-weight: 100 900; }
  @font-face { font-family: 'Geist Mono'; src: url(${asset('geist-mono-latin.woff2', 'font/woff2')}) format('woff2'); font-weight: 100 900; }
  @page { size: A4; margin: 16mm 16mm 18mm; }
  :root {
    --ink: #0b0d10; --muted: #5b6472; --hairline: #e3e6eb; --mist: #f5f6f8;
    --critical: #a21caf; --high: #dc2626; --medium: #d97706; --low: #0891b2; --none: #16a34a;
    --iris: #8247ff; --magenta: #f47bff; --ember: #ff8a3d;
  }
  * { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { margin: 0 auto; max-width: 820px; padding: 0 16px; font-family: Geist, sans-serif; font-size: 9.8pt; line-height: 1.55; color: var(--ink); background: #fff; }
  .mono, pre, code { font-family: 'Geist Mono', monospace; }
  .bar { height: 5px; border-radius: 99px; background: linear-gradient(90deg, var(--iris), var(--magenta), var(--ember)); margin-top: 8px; }
  .top { display: flex; justify-content: space-between; align-items: flex-start; padding: 18px 0 14px; }
  .brand { display: flex; gap: 10px; align-items: center; }
  .brand img { width: 40px; height: 40px; }
  .brand b { display: block; font-size: 15pt; letter-spacing: 0.18em; }
  .brand span { color: var(--muted); font-size: 8.5pt; }
  .title { text-align: right; }
  .title h1 { margin: 0; font-size: 20pt; letter-spacing: -0.02em; }
  .meta { display: grid; grid-template-columns: auto 1fr; gap: 2px 14px; margin-top: 6px; font-size: 8.8pt; color: var(--muted); text-align: left; }
  .meta dd { margin: 0; color: var(--ink); word-break: break-all; }
  .meta dt { text-align: right; }
  h2 { font-size: 12pt; margin: 22px 0 8px; display: flex; gap: 8px; align-items: center; }
  h2 .idx { font-family: 'Geist Mono'; font-size: 8pt; background: var(--ink); color: #fff; border-radius: 6px; padding: 1px 6px; }
  .risk { display: grid; grid-template-columns: 1.3fr repeat(4, 1fr); gap: 8px; margin-top: 8px; }
  .risk > div { border: 1px solid var(--hairline); border-radius: 12px; padding: 10px 12px; }
  .risk .overall { background: var(--ink); color: #fff; border: 0; }
  .risk .overall small { color: #b8bec8; }
  .risk small { display: block; font-size: 7.8pt; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
  .risk b { font-size: 18pt; font-family: 'Geist Mono'; }
  .risk .overall b { font-family: Geist; font-size: 15pt; }
  .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 6px; }
  p { margin: 4px 0 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 9pt; }
  th { text-align: left; font-family: 'Geist Mono'; font-size: 7.5pt; letter-spacing: 0.08em; text-transform: uppercase; color: var(--muted); border-bottom: 1.5px solid var(--ink); padding: 5px 6px; }
  td { border-bottom: 1px solid var(--hairline); padding: 6px; vertical-align: top; }
  .pill { display: inline-block; font-size: 7.6pt; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: #fff; border-radius: 99px; padding: 1px 8px; }
  ${[...ORDER, 'none'].map((s) => `.sev-${s} .pill, .pill.sev-${s} { background: var(--${s}); } .dot.sev-${s} { background: var(--${s}); }`).join('\n  ')}
  .card { border: 1px solid var(--hairline); border-left: 4px solid var(--muted); border-radius: 12px; padding: 12px 14px; margin: 10px 0; break-inside: avoid; }
  ${ORDER.map((s) => `.card.sev-${s} { border-left-color: var(--${s}); }`).join('\n  ')}
  .card header { display: flex; gap: 8px; align-items: center; }
  .card .num { font-family: 'Geist Mono'; color: var(--muted); font-size: 8.5pt; }
  .card h3 { margin: 0; font-size: 10.8pt; }
  .card dl { display: grid; grid-template-columns: auto 1fr; gap: 1px 12px; margin: 8px 0 4px; font-size: 8.6pt; color: var(--muted); }
  .card dd { margin: 0; color: var(--ink); }
  .card h4 { margin: 8px 0 0; font-size: 8pt; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
  pre { background: var(--mist); border-radius: 8px; padding: 8px 10px; font-size: 8pt; white-space: pre-wrap; word-break: break-word; margin: 4px 0 0; }
  .ok { color: var(--none); font-weight: 600; } .bad { color: var(--high); font-weight: 600; }
  @media print { .new-page { break-before: page; margin-top: 0; } }
  footer { margin-top: 26px; padding-top: 10px; border-top: 1px solid var(--hairline); color: var(--muted); font-size: 8pt; }
</style>
</head>
<body>
  <div class="bar"></div>
  <div class="top">
    <div class="brand"><img src="${asset('avenzoq-mark-transparent.png', 'image/png')}" alt="" /><div><b>AVENZOQ</b><span>Probe · AI Security</span></div></div>
    <div class="title">
      <h1>${esc(t.doc)}</h1>
      <dl class="meta">
        ${client ? `<dt>${t.client}</dt><dd>${esc(client)}</dd>` : ''}
        <dt>${t.target}</dt><dd class="mono">${esc(scan.target)}</dd>
        <dt>${t.type}</dt><dd>${scan.kind === 'mcp' ? `${t.mcp}${scan.server ? ` · ${esc(scan.server)}` : ''}` : t.agent}</dd>
        <dt>${t.date}</dt><dd>${fmtDate}</dd>
      </dl>
    </div>
  </div>

  <div class="risk">
    <div class="overall"><small>${t.overall}</small><b><span class="dot sev-${overall}"></span>${t.sev[overall]}</b></div>
    ${ORDER.map((s) => `<div><small><span class="dot sev-${s}"></span>${t.sev[s]}</small><b>${c[s]}</b></div>`).join('')}
  </div>

  <h2><span class="idx">01</span>${t.summary}</h2>
  <p>${t.found(items.length, c)}</p>

  <h2><span class="idx">02</span>${t.scope}</h2>
  ${scope.map((s) => `<p>${esc(s)}</p>`).join('')}

  ${
    scan.results
      ? `<h2><span class="idx">03</span>${t.probes}</h2>
  <table><thead><tr><th>#</th><th>Probe</th><th></th></tr></thead><tbody>
  ${scan.results.map((r, i) => `<tr><td class="mono">${i + 1}</td><td class="mono">${esc(r.probe)}</td><td class="${r.status === 'resisted' ? 'ok' : 'bad'}">${t.result[r.status]}</td></tr>`).join('')}
  </tbody></table>`
      : ''
  }

  ${
    items.length
      ? `<h2><span class="idx">${scan.results ? '04' : '03'}</span>${t.overview}</h2>
  <table><thead><tr><th>#</th><th></th><th>${t.where}</th><th></th></tr></thead><tbody>
  ${items.map((f, i) => `<tr><td class="mono">${String(i + 1).padStart(2, '0')}</td><td><span class="pill sev-${f.severity}">${t.sev[f.severity]}</span></td><td class="mono">${esc(whereOf(f))}</td><td>${esc((guidance(f.id, lang) ?? f).title)}</td></tr>`).join('')}
  </tbody></table>

  <h2 class="new-page"><span class="idx">${scan.results ? '05' : '04'}</span>${t.details}</h2>
  ${items.map(card).join('')}`
      : ''
  }

  <footer>${esc(t.disclaimer)}<br />AVENZOQ Probe · avenzoq.com</footer>
</body>
</html>`;
}

function findChrome() {
  const candidates = [
    process.env.CHROME_PATH,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p));
}

export function htmlToPdf(htmlPath, pdfPath) {
  const chrome = findChrome();
  if (!chrome) throw new Error('PDF output needs Google Chrome or Chromium; set CHROME_PATH to its executable');
  execFileSync(chrome, ['--headless', '--disable-gpu', '--no-pdf-header-footer', `--print-to-pdf=${pdfPath}`, pathToFileURL(htmlPath).href], {
    stdio: 'ignore',
  });
}
