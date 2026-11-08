// Renders the public State of MCP Security report (Markdown + branded HTML/PDF,
// English and Spanish) from the aggregate numbers. Only aggregates appear here;
// server names never do.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const asset = (file, type) => `data:${type};base64,${readFileSync(join(root, 'assets', file)).toString('base64')}`;
const esc = (v = '') => String(v).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const pct = (n, d) => (d ? Math.round((n / d) * 100) : 0);

const T = {
  en: {
    title: 'State of MCP Security',
    eyebrow: 'AVENZOQ Research',
    draft: 'DRAFT · NOT FOR PUBLICATION',
    period: (d) => `Scan date: ${d}`,
    kpi: { servers: 'servers scanned', tools: 'tools analyzed', attacks: 'hidden attacks found', exec: 'servers expose code execution' },
    s1: 'Summary',
    summary: (s) => [
      `We scanned ${s.started} widely used public MCP servers (${s.tools} tools) in an isolated sandbox. **None of them contained hidden instructions** aimed at AI agents: no tool poisoning, no planted prompt injection.`,
      `What we did find is **power**. ${pct(s.n('capability-exec'), s.started)}% of the servers expose tools that run code or SQL, ${pct(s.n('capability-destructive'), s.started)}% can delete data, and ${pct(s.n('exfiltration-path'), s.started)}% combine access to private data with a way to send it out. None of this is a bug in those projects; it is what they are for. But it is exactly what an attacker would try to trigger through prompt injection.`,
      'The lesson for teams adopting agents: the risk is less in the servers themselves and more in **what an agent is allowed to do with them** when it reads untrusted text.',
    ],
    s2: 'Results',
    head: ['Finding', 'Servers', 'Share'],
    note: 'Capability rows describe what an agent could be tricked into doing. They are not vulnerabilities. Only the first row is evidence of an attack.',
    labels: {
      attack: 'Hidden instructions in tool metadata (attack)',
      'capability-exec': 'Tool that runs code or commands',
      'capability-destructive': 'Tool that deletes data',
      'capability-financial': 'Tool that moves money',
      'exfiltration-path': 'Private data + outbound channel on one server',
      'annotation-mismatch': 'Tool marked read-only that changes state',
      'missing-annotations': 'High-impact tool without a risk annotation',
      'unconstrained-input': 'Free-form path, URL, command or query parameter',
      'tool-steering': 'Description steers the agent ("always use this tool")',
    },
    s3: 'What we learned',
    learned: (s) => [
      `**Tool descriptions are instructions.** One server tells the agent it "should always default to using this tool" and to call a feedback tool "immediately" after searching. It is a product choice, not an attack, but it shows how easily text alone redirects an agent. The same channel is what tool-poisoning attacks use.`,
      `**Free-form parameters are everywhere.** ${pct(s.n('unconstrained-input'), s.started)}% of servers accept an unrestricted path, URL, command or query. If an injected instruction reaches the agent, these parameters let it point the tool anywhere.`,
      `**Annotations are underused.** Hints such as \`destructiveHint\` let clients ask for confirmation before risky calls, yet ${pct(s.n('missing-annotations'), s.started)}% of servers ship high-impact tools without them.`,
      '**Automated scanners need real-world testing.** Our first pass flagged harmless phrases ("drag and drop", "terminal state", search syntax) as risks. We reviewed every critical and high finding by hand, fixed the rules and re-ran the scan. The numbers in this report come from the corrected version.',
    ],
    s4: 'Recommendations',
    recs: [
      '**For teams using agents:** give each agent only the tools it needs; require human approval for tools that run code, delete data, send information out or move money; and treat everything the agent reads (email, web pages, tool output) as untrusted.',
      '**For MCP server authors:** keep descriptions factual (say what the tool does, not what the agent must do); set `readOnlyHint` and `destructiveHint` accurately; and validate paths, URLs and commands on the server.',
      '**For everyone:** pin server versions and re-scan when they change, since a server that was safe when approved can change later (a "rug pull").',
    ],
    s5: 'Method',
    method: (s) => [
      `Targets: ${s.targets} widely used public MCP servers on npm. ${s.started} started without credentials; ${s.targets - s.started} needed an API key or did not start within 30 seconds and are not included.`,
      'Isolation: each server ran in a locked-down container (read-only filesystem, no Linux capabilities, CPU, memory and process limits, no host folders). Third-party code never ran on our machines.',
      'Analysis: Probe listed each server\'s tools and applied its static rules. **No tool was called**, so nothing was read, written or sent on anyone\'s behalf.',
      `Accuracy: Probe's rules score ${s.f1} F1 on its public benchmark (development set). Every critical and high finding was reviewed by a person.`,
      'Disclosure: had we found a real vulnerability, we would have reported it privately to the maintainer and waited up to 90 days before naming the project.',
    ],
    s6: 'Limits',
    limits: (s) => [
      `This is a small sample (${s.started} servers). Servers that need credentials, often the most powerful ones, are missing.`,
      'Static analysis sees what a server declares, not what it does at runtime or what its tools return.',
      'Pattern rules can miss reworded attacks; the optional LLM judge was not used in this run.',
    ],
    footer: (v) => `Research by AVENZOQ with Probe ${v}, an open-source scanner for MCP servers and AI agents: github.com/MaikolSoro/probe · avenzoq.com`,
  },
  es: {
    title: 'Estado de la seguridad MCP',
    eyebrow: 'AVENZOQ Research',
    draft: 'BORRADOR · NO PUBLICAR',
    period: (d) => `Fecha del escaneo: ${d}`,
    kpi: { servers: 'servidores escaneados', tools: 'herramientas analizadas', attacks: 'ataques escondidos encontrados', exec: 'de los servidores ejecutan código' },
    s1: 'Resumen',
    summary: (s) => [
      `Escaneamos ${s.started} servidores MCP públicos muy usados (${s.tools} herramientas) en un entorno aislado. **Ninguno tenía instrucciones escondidas** dirigidas a agentes de IA: ni envenenamiento de herramientas ni inyección de instrucciones plantada.`,
      `Lo que sí encontramos es **poder**. El ${pct(s.n('capability-exec'), s.started)} % de los servidores tiene herramientas que ejecutan código o SQL, el ${pct(s.n('capability-destructive'), s.started)} % puede borrar datos y el ${pct(s.n('exfiltration-path'), s.started)} % combina acceso a datos privados con una forma de enviarlos afuera. Nada de esto es una falla de esos proyectos: es su función. Pero es justo lo que un atacante intentaría activar con una inyección de instrucciones.`,
      'La lección para los equipos que adoptan agentes: el riesgo está menos en los servidores y más en **lo que se le permite hacer al agente** con ellos cuando lee texto no confiable.',
    ],
    s2: 'Resultados',
    head: ['Hallazgo', 'Servidores', 'Porcentaje'],
    note: 'Las filas de capacidades describen lo que un agente podría ser engañado para hacer. No son vulnerabilidades. Solo la primera fila sería evidencia de un ataque.',
    labels: {
      attack: 'Instrucciones escondidas en las herramientas (ataque)',
      'capability-exec': 'Herramienta que ejecuta código o comandos',
      'capability-destructive': 'Herramienta que borra datos',
      'capability-financial': 'Herramienta que mueve dinero',
      'exfiltration-path': 'Datos privados + canal de salida en el mismo servidor',
      'annotation-mismatch': 'Herramienta "solo lectura" que sí cambia cosas',
      'missing-annotations': 'Herramienta de alto impacto sin anotación de riesgo',
      'unconstrained-input': 'Parámetro libre de ruta, URL, comando o consulta',
      'tool-steering': 'La descripción dirige al agente ("usa siempre esta herramienta")',
    },
    s3: 'Lo que aprendimos',
    learned: (s) => [
      '**Las descripciones de las herramientas son instrucciones.** Un servidor le dice al agente que "siempre" use su herramienta por defecto y que llame a otra "inmediatamente" después de buscar. Es una decisión del producto, no un ataque, pero muestra lo fácil que es redirigir a un agente solo con texto. Es el mismo canal que usan los ataques de envenenamiento de herramientas.',
      `**Los parámetros libres están en todas partes.** El ${pct(s.n('unconstrained-input'), s.started)} % de los servidores acepta una ruta, URL, comando o consulta sin restricciones. Si una instrucción inyectada llega al agente, esos parámetros le permiten dirigir la herramienta a cualquier lugar.`,
      `**Las anotaciones se usan poco.** Indicadores como \`destructiveHint\` permiten que el cliente pida confirmación antes de una acción riesgosa, pero el ${pct(s.n('missing-annotations'), s.started)} % de los servidores tiene herramientas de alto impacto sin ellos.`,
      '**Los escáneres automáticos necesitan pruebas reales.** En la primera pasada, nuestro escáner marcó frases inofensivas ("drag and drop", "terminal state", sintaxis de búsqueda) como riesgos. Revisamos a mano cada hallazgo crítico y alto, corregimos las reglas y volvimos a escanear. Las cifras de este informe vienen de la versión corregida.',
    ],
    s4: 'Recomendaciones',
    recs: [
      '**Para equipos que usan agentes:** denle a cada agente solo las herramientas que necesita; exijan aprobación humana para herramientas que ejecutan código, borran datos, envían información afuera o mueven dinero; y traten como no confiable todo lo que el agente lee (correos, páginas web, respuestas de herramientas).',
      '**Para quienes crean servidores MCP:** mantengan las descripciones objetivas (qué hace la herramienta, no qué debe hacer el agente); usen `readOnlyHint` y `destructiveHint` correctamente; y validen rutas, URLs y comandos en el servidor.',
      '**Para todos:** fijen las versiones de los servidores y vuelvan a escanear cuando cambien: un servidor seguro al aprobarlo puede cambiar después (un "rug pull").',
    ],
    s5: 'Método',
    method: (s) => [
      `Objetivos: ${s.targets} servidores MCP públicos muy usados en npm. ${s.started} arrancaron sin credenciales; ${s.targets - s.started} necesitaban una clave de API o no arrancaron en 30 segundos y no están incluidos.`,
      'Aislamiento: cada servidor corrió en un contenedor bloqueado (sistema de archivos de solo lectura, sin privilegios, con límites de CPU, memoria y procesos, sin acceso a carpetas del equipo). El código de terceros nunca corrió en nuestras máquinas.',
      'Análisis: Probe listó las herramientas de cada servidor y aplicó sus reglas estáticas. **No se llamó a ninguna herramienta**, así que no se leyó, escribió ni envió nada en nombre de nadie.',
      `Precisión: las reglas de Probe obtienen un F1 de ${s.f1} en su benchmark público (set de desarrollo). Cada hallazgo crítico y alto lo revisó una persona.`,
      'Divulgación: si hubiéramos encontrado una vulnerabilidad real, la habríamos reportado en privado al autor y esperado hasta 90 días antes de nombrar el proyecto.',
    ],
    s6: 'Límites',
    limits: (s) => [
      `Es una muestra pequeña (${s.started} servidores). Faltan los que necesitan credenciales, que suelen ser los más poderosos.`,
      'El análisis estático ve lo que el servidor declara, no lo que hace en ejecución ni lo que devuelven sus herramientas.',
      'Las reglas por patrones pueden no detectar ataques reformulados; en esta corrida no se usó el juez con IA opcional.',
    ],
    footer: (v) => `Investigación de AVENZOQ con Probe ${v}, escáner open source para servidores MCP y agentes de IA: github.com/MaikolSoro/probe · avenzoq.com`,
  },
};

const ORDER = ['attack', 'capability-exec', 'capability-destructive', 'capability-financial', 'exfiltration-path', 'annotation-mismatch', 'missing-annotations', 'unconstrained-input', 'tool-steering'];

export function renderMd(s, lang, { draft = true } = {}) {
  const t = T[lang];
  const bullets = (arr) => arr.map((x) => `- ${x}`).join('\n');
  return [
    `# ${t.title} · ${s.month}`,
    '',
    `**${t.eyebrow}** · ${t.period(s.date)}${draft ? ` · ⚠️ ${t.draft}` : ''}`,
    '',
    `| ${s.started} ${t.kpi.servers} | ${s.tools} ${t.kpi.tools} | ${s.n('attack')} ${t.kpi.attacks} | ${pct(s.n('capability-exec'), s.started)}% ${t.kpi.exec} |`,
    '|---|---|---|---|',
    '',
    `## ${t.s1}`,
    '',
    t.summary(s).join('\n\n'),
    '',
    `## ${t.s2}`,
    '',
    `| ${t.head.join(' | ')} |`,
    '|---|---|---|',
    ...ORDER.map((id) => `| ${t.labels[id]} | ${s.n(id)} | ${pct(s.n(id), s.started)}% |`),
    '',
    `> ${t.note}`,
    '',
    `## ${t.s3}`,
    '',
    bullets(t.learned(s)),
    '',
    `## ${t.s4}`,
    '',
    bullets(t.recs),
    '',
    `## ${t.s5}`,
    '',
    bullets(t.method(s)),
    '',
    `## ${t.s6}`,
    '',
    bullets(t.limits(s)),
    '',
    '---',
    '',
    `_${t.footer(s.version)}_`,
    '',
  ].join('\n');
}

const md2html = (text) => esc(text).replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>').replace(/`(.+?)`/g, '<code>$1</code>');

export function renderHtml(s, lang, { draft = true } = {}) {
  const t = T[lang];
  const list = (arr) => `<ul>${arr.map((x) => `<li>${md2html(x)}</li>`).join('')}</ul>`;
  const bar = (id) => {
    const p = pct(s.n(id), s.started);
    return `<tr class="${id === 'attack' ? 'attack' : ''}"><td>${esc(t.labels[id])}</td><td class="num">${s.n(id)}</td><td class="barcell"><div class="barwrap"><div class="bar"><span style="width:${Math.max(p, 1)}%"></span></div><b>${p}%</b></div></td></tr>`;
  };
  return `<!doctype html>
<html lang="${lang}"><head><meta charset="utf-8"><title>${esc(t.title)} · ${esc(s.month)}</title>
<style>
  @font-face { font-family: Geist; src: url(${asset('geist-latin.woff2', 'font/woff2')}) format('woff2'); font-weight: 100 900; }
  @font-face { font-family: 'Geist Mono'; src: url(${asset('geist-mono-latin.woff2', 'font/woff2')}) format('woff2'); font-weight: 100 900; }
  @page { size: A4; margin: 14mm 0 16mm; }
  @page :first { margin: 0; }
  :root { --ink:#0b0d10; --muted:#5b6472; --hair:#e3e6eb; --iris:#8247ff; --magenta:#f47bff; --ember:#ff8a3d; --ok:#16a34a; }
  * { box-sizing: border-box; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { margin: 0; font-family: Geist, sans-serif; color: var(--ink); font-size: 10pt; line-height: 1.6; }
  .cover { background: #0b0d10; color: #fff; padding: 22mm 18mm 16mm; position: relative; overflow: hidden; }
  .cover::before { content: ''; position: absolute; inset: 0; background: radial-gradient(60% 80% at 15% 0%, rgba(130,71,255,.45), transparent 70%), radial-gradient(50% 70% at 100% 100%, rgba(244,123,255,.25), transparent 70%); }
  .cover > * { position: relative; }
  .brand { display: flex; align-items: center; gap: 10px; font: 600 9pt 'Geist Mono'; letter-spacing: .2em; color: #b8bec8; text-transform: uppercase; }
  .brand img { width: 30px; }
  .draft { display: inline-block; margin-top: 14px; border: 1px solid #ff8a3d; color: #ff8a3d; font: 600 8pt 'Geist Mono'; letter-spacing: .14em; padding: 3px 10px; border-radius: 99px; }
  h1 { font-size: 36pt; line-height: 1.05; letter-spacing: -.03em; margin: 16px 0 6px; }
  h1 span { background: linear-gradient(90deg, var(--iris), var(--magenta), var(--ember)); -webkit-background-clip: text; color: transparent; }
  .period { color: #b8bec8; font: 9pt 'Geist Mono'; }
  .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 22px; }
  .kpis div { background: rgba(255,255,255,.06); border: 1px solid rgba(255,255,255,.12); border-radius: 12px; padding: 12px; }
  .kpis b { display: block; font-size: 24pt; letter-spacing: -.02em; }
  .kpis div:nth-child(3) b { color: #4ade80; }
  .kpis span { color: #b8bec8; font-size: 8.5pt; }
  main { padding: 8mm 18mm 0; }
  h2 { font-size: 13pt; margin: 18px 0 6px; display: flex; gap: 8px; align-items: center; }
  h2 i { font: 600 8pt 'Geist Mono'; font-style: normal; background: var(--ink); color: #fff; border-radius: 6px; padding: 1px 6px; }
  p, li { margin: 4px 0; }
  ul { padding-left: 18px; margin: 4px 0; }
  code { font-family: 'Geist Mono'; font-size: 8.5pt; background: #f2f3f5; padding: 0 4px; border-radius: 4px; }
  table { width: 100%; border-collapse: collapse; margin-top: 6px; font-size: 9.2pt; }
  td { border-bottom: 1px solid var(--hair); padding: 6px 4px; vertical-align: middle; }
  td.num { width: 40px; text-align: right; font-family: 'Geist Mono'; color: var(--muted); }
  td.barcell { width: 46%; }
  .barwrap { display: flex; gap: 8px; align-items: center; }
  .bar { flex: 1; height: 8px; background: #f0f1f4; border-radius: 99px; overflow: hidden; }
  .bar span { display: block; height: 100%; background: linear-gradient(90deg, var(--iris), var(--magenta)); border-radius: 99px; }
  tr.attack td { font-weight: 600; } tr.attack .bar span { background: var(--ok); }
  .note { color: var(--muted); font-size: 8.6pt; border-left: 3px solid var(--hair); padding-left: 10px; margin-top: 8px; }
  h2 { break-after: avoid; } li, tr { break-inside: avoid; }
  footer { margin-top: 18px; padding-top: 10px; border-top: 1px solid var(--hair); color: var(--muted); font-size: 8.4pt; }
</style></head><body>
  <div class="cover">
    <div class="brand"><img src="${asset('avenzoq-mark-transparent.png', 'image/png')}" alt="">${esc(t.eyebrow)}</div>
    ${draft ? `<div class="draft">${esc(t.draft)}</div>` : ''}
    <h1>${esc(t.title)}<br><span>${esc(s.month)}</span></h1>
    <div class="period">${esc(t.period(s.date))}</div>
    <div class="kpis">
      <div><b>${s.started}</b><span>${esc(t.kpi.servers)}</span></div>
      <div><b>${s.tools}</b><span>${esc(t.kpi.tools)}</span></div>
      <div><b>${s.n('attack')}</b><span>${esc(t.kpi.attacks)}</span></div>
      <div><b>${pct(s.n('capability-exec'), s.started)}%</b><span>${esc(t.kpi.exec)}</span></div>
    </div>
  </div>
  <main>
    <section><h2><i>01</i>${esc(t.s1)}</h2>${t.summary(s).map((x) => `<p>${md2html(x)}</p>`).join('')}</section>
    <section><h2><i>02</i>${esc(t.s2)}</h2><table>${ORDER.map(bar).join('')}</table><p class="note">${esc(t.note)}</p></section>
    <section><h2><i>03</i>${esc(t.s3)}</h2>${list(t.learned(s))}</section>
    <section><h2><i>04</i>${esc(t.s4)}</h2>${list(t.recs)}</section>
    <section><h2><i>05</i>${esc(t.s5)}</h2>${list(t.method(s))}</section>
    <section><h2><i>06</i>${esc(t.s6)}</h2>${list(t.limits(s))}</section>
    <footer>${md2html(t.footer(s.version))}</footer>
  </main>
</body></html>`;
}
