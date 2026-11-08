// Generates the "authorization to test" document a client signs before a security
// assessment, so every engagement starts with written permission. This is a
// starting template, not legal advice: the footer says to have a lawyer review it.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const assets = join(dirname(fileURLToPath(import.meta.url)), '..', 'assets');
const asset = (file, type) => `data:${type};base64,${readFileSync(join(assets, file)).toString('base64')}`;
const esc = (v = '') => String(v).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

const T = {
  en: {
    doc: 'Authorization to perform a security assessment',
    intro: (tester) => `This document authorizes ${tester} ("the Tester") to perform a security assessment of the systems listed below, under the terms stated here.`,
    hClient: 'Client',
    hScope: 'Systems in scope',
    hOut: 'Explicitly out of scope',
    hWindow: 'Testing window',
    hTerms: 'Terms',
    client: 'Organization',
    authby: 'Authorized by',
    role: 'Role / title',
    tester: 'Tester',
    from: 'From',
    to: 'To',
    scopeNote: 'Only the systems listed above may be tested. Anything not listed is out of scope.',
    terms: [
      'The Client confirms it owns or is legally entitled to authorize testing of every system in scope.',
      'The Tester will only run non-destructive checks and will not exfiltrate, alter or destroy real data.',
      'The Tester will stop on request and report any critical issue found without delay.',
      'Findings are confidential and shared only with the Client.',
      'A clean result does not guarantee that a system is secure; it means the listed checks found nothing.',
    ],
    sign: 'Signatures',
    signClient: 'For the Client',
    signTester: 'For the Tester',
    name: 'Name',
    date: 'Date',
    signature: 'Signature',
    disclaimer: 'This is a template, not legal advice. Have it reviewed by a lawyer before use.',
    tbd: '____________________',
  },
  es: {
    doc: 'Autorización para realizar una evaluación de seguridad',
    intro: (tester) => `Este documento autoriza a ${tester} ("la Parte Evaluadora") a realizar una evaluación de seguridad de los sistemas que se enumeran a continuación, bajo los términos aquí establecidos.`,
    hClient: 'Cliente',
    hScope: 'Sistemas dentro del alcance',
    hOut: 'Explícitamente fuera del alcance',
    hWindow: 'Ventana de pruebas',
    hTerms: 'Términos',
    client: 'Organización',
    authby: 'Autorizado por',
    role: 'Cargo',
    tester: 'Parte evaluadora',
    from: 'Desde',
    to: 'Hasta',
    scopeNote: 'Solo pueden probarse los sistemas enumerados arriba. Todo lo que no esté en la lista queda fuera del alcance.',
    terms: [
      'El Cliente confirma que es propietario de cada sistema dentro del alcance o que está legalmente facultado para autorizar su prueba.',
      'La Parte Evaluadora solo ejecutará pruebas no destructivas y no extraerá, alterará ni destruirá datos reales.',
      'La Parte Evaluadora se detendrá si se le solicita e informará sin demora cualquier hallazgo crítico.',
      'Los hallazgos son confidenciales y se comparten únicamente con el Cliente.',
      'Un resultado limpio no garantiza que un sistema sea seguro: significa que las pruebas enumeradas no encontraron nada.',
    ],
    sign: 'Firmas',
    signClient: 'Por el Cliente',
    signTester: 'Por la Parte Evaluadora',
    name: 'Nombre',
    date: 'Fecha',
    signature: 'Firma',
    disclaimer: 'Esto es una plantilla, no asesoría legal. Hazla revisar por un abogado antes de usarla.',
    tbd: '____________________',
  },
};

// Scope accepts a comma- or newline-separated list of systems.
const asList = (v) => (v ? String(v).split(/[\n,]/).map((s) => s.trim()).filter(Boolean) : []);

function fields(opts, t) {
  return {
    tester: opts.tester || 'AVENZOQ',
    client: opts.client || t.tbd,
    authby: opts.authby || t.tbd,
    role: opts.role || t.tbd,
    scope: asList(opts.scope ?? opts.target),
    out: asList(opts.exclude),
    from: opts.start || t.tbd,
    to: opts.end || t.tbd,
  };
}

export function authorizationMarkdown(opts = {}, lang = 'es') {
  const t = T[lang] ?? T.es;
  const f = fields(opts, t);
  const list = (items) => (items.length ? items.map((s) => `- ${s}`).join('\n') : `- ${t.tbd}`);
  return [
    `# ${t.doc}`,
    '',
    t.intro(f.tester),
    '',
    `## ${t.hClient}`,
    `- **${t.client}:** ${f.client}`,
    `- **${t.authby}:** ${f.authby}`,
    `- **${t.role}:** ${f.role}`,
    `- **${t.tester}:** ${f.tester}`,
    '',
    `## ${t.hScope}`,
    list(f.scope),
    '',
    `## ${t.hOut}`,
    list(f.out),
    '',
    `> ${t.scopeNote}`,
    '',
    `## ${t.hWindow}`,
    `- **${t.from}:** ${f.from}`,
    `- **${t.to}:** ${f.to}`,
    '',
    `## ${t.hTerms}`,
    ...t.terms.map((s, i) => `${i + 1}. ${s}`),
    '',
    `## ${t.sign}`,
    '',
    `**${t.signClient}** — ${t.name}: ${t.tbd}  ·  ${t.date}: ${t.tbd}  ·  ${t.signature}: ${t.tbd}`,
    '',
    `**${t.signTester}** — ${t.name}: ${t.tbd}  ·  ${t.date}: ${t.tbd}  ·  ${t.signature}: ${t.tbd}`,
    '',
    '---',
    '',
    `_${t.disclaimer}_`,
    '',
  ].join('\n');
}

export function authorizationHtml(opts = {}, lang = 'es') {
  const t = T[lang] ?? T.es;
  const f = fields(opts, t);
  const list = (items) => `<ul>${(items.length ? items : [t.tbd]).map((s) => `<li>${esc(s)}</li>`).join('')}</ul>`;
  const sigRow = (label) =>
    `<div class="sig"><b>${esc(label)}</b><div class="lines"><span>${t.name}</span><span>${t.date}</span><span>${t.signature}</span></div></div>`;
  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8" /><title>${esc(t.doc)}</title>
<style>
  @font-face { font-family: Geist; src: url(${asset('geist-latin.woff2', 'font/woff2')}) format('woff2'); font-weight: 100 900; }
  @page { size: A4; margin: 18mm 18mm 20mm; }
  * { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { margin: 0 auto; max-width: 760px; padding: 0 16px; font-family: Geist, sans-serif; font-size: 10.5pt; line-height: 1.6; color: #0b0d10; }
  .bar { height: 5px; border-radius: 99px; background: linear-gradient(90deg, #8247ff, #f47bff, #ff8a3d); margin-top: 8px; }
  .top { display: flex; gap: 10px; align-items: center; padding: 16px 0 6px; }
  .top img { width: 38px; height: 38px; } .top b { font-size: 14pt; letter-spacing: 0.18em; }
  .top span { color: #5b6472; font-size: 8.5pt; display: block; }
  h1 { font-size: 17pt; letter-spacing: -0.01em; margin: 14px 0 4px; }
  h2 { font-size: 11pt; margin: 18px 0 4px; padding-bottom: 3px; border-bottom: 1.5px solid #0b0d10; }
  ul { margin: 4px 0; padding-left: 18px; } li { margin: 2px 0; }
  blockquote { margin: 8px 0; padding: 8px 12px; background: #f5f6f8; border-radius: 8px; color: #5b6472; }
  ol { padding-left: 18px; } ol li { margin: 4px 0; }
  .sig { margin: 14px 0; break-inside: avoid; }
  .sig .lines { display: grid; grid-template-columns: 2fr 1fr 2fr; gap: 16px; margin-top: 22px; }
  .sig .lines span { border-top: 1px solid #0b0d10; padding-top: 4px; font-size: 8.5pt; color: #5b6472; }
  footer { margin-top: 24px; padding-top: 10px; border-top: 1px solid #e3e6eb; color: #5b6472; font-size: 8.5pt; }
</style></head>
<body>
  <div class="bar"></div>
  <div class="top"><img src="${asset('avenzoq-mark-transparent.png', 'image/png')}" alt="" /><div><b>AVENZOQ</b><span>Probe · AI Security</span></div></div>
  <h1>${esc(t.doc)}</h1>
  <p>${esc(t.intro(f.tester))}</p>
  <h2>${esc(t.hClient)}</h2>
  <ul><li><b>${esc(t.client)}:</b> ${esc(f.client)}</li><li><b>${esc(t.authby)}:</b> ${esc(f.authby)}</li><li><b>${esc(t.role)}:</b> ${esc(f.role)}</li><li><b>${esc(t.tester)}:</b> ${esc(f.tester)}</li></ul>
  <h2>${esc(t.hScope)}</h2>
  ${list(f.scope)}
  <h2>${esc(t.hOut)}</h2>
  ${list(f.out)}
  <blockquote>${esc(t.scopeNote)}</blockquote>
  <h2>${esc(t.hWindow)}</h2>
  <ul><li><b>${esc(t.from)}:</b> ${esc(f.from)}</li><li><b>${esc(t.to)}:</b> ${esc(f.to)}</li></ul>
  <h2>${esc(t.hTerms)}</h2>
  <ol>${t.terms.map((s) => `<li>${esc(s)}</li>`).join('')}</ol>
  <h2>${esc(t.sign)}</h2>
  ${sigRow(t.signClient)}
  ${sigRow(t.signTester)}
  <footer>${esc(t.disclaimer)}<br />AVENZOQ Probe · avenzoq.com</footer>
</body></html>`;
}
