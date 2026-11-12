// HTML and Markdown: visible text, CSS-hidden elements, comments, <meta> content
// and alt/title/aria-label attributes.
import { decodeXml } from './shared.mjs';

// Strong: the text is on the page but nobody can see it. Weak: common in normal
// pages (menus, modals, fade-in animations, white text on a coloured button,
// gradient text), so it only matters when the text carries instructions.
const HIDE_STRONG = /font-size\s*:\s*0(?![.\d]*[1-9])|(?:left|top|text-indent)\s*:\s*-\d{3,}/i;
const HIDE_WEAK = /display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d]*[1-9])|(?:^|[;\s])color\s*:\s*(?:#fff(?:fff)?\b|white\b|transparent\b)/i;
const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);

function closeOf(html, name, from) {
  const re = new RegExp(`<(/?)${name}\\b[^>]*>`, 'gi');
  re.lastIndex = from;
  let depth = 1;
  for (let m; (m = re.exec(html)); ) {
    if (m[1]) {
      if (--depth === 0) return m.index;
    } else if (!m[0].endsWith('/>')) depth++;
  }
  return html.length;
}

const stripTags = (s) => decodeXml(s.replace(/<[^>]+>/g, ' '));

export function htmlSegments(source) {
  const segments = [];
  let html = source.replace(/<(script|style|noscript)\b[\s\S]*?<\/\1\s*>/gi, ' ');
  html = html.replace(/<!--([\s\S]*?)-->/g, (_, c) => {
    segments.push({ text: c, hidden: 'comment', where: 'comment' });
    return ' ';
  });
  for (const m of html.matchAll(/<meta\b[^>]*\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
    segments.push({ text: decodeXml(m[1] ?? m[2]), hidden: 'metadata', where: '<meta>' });
  }
  for (const m of html.matchAll(/<[a-z][^>]*?\s(?:alt|title|aria-label)\s*=\s*(?:"([^"]*)"|'([^']*)')/gi)) {
    segments.push({ text: decodeXml(m[1] ?? m[2]), hidden: 'attribute', where: 'attribute' });
  }

  const ranges = [];
  for (const m of html.matchAll(/<([a-z][\w-]*)\b([^>]*)>/gi)) {
    const [tag, name, attrs] = m;
    if (VOID.has(name.toLowerCase()) || tag.endsWith('/>')) continue;
    if (ranges.some(([a, b]) => m.index >= a && m.index < b)) continue; // inside an element already reported
    const style = /\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(attrs);
    const css = style?.[1] ?? style?.[2] ?? '';
    const strong = HIDE_STRONG.test(css);
    if (!strong && !HIDE_WEAK.test(css) && !/\shidden(?=[\s=>]|$)/i.test(attrs)) continue;
    const end = closeOf(html, name, m.index + tag.length);
    ranges.push([m.index, end]);
    segments.push({ text: stripTags(html.slice(m.index + tag.length, end)), hidden: 'css', strong, where: `<${name}>` });
  }

  let visible = html;
  for (const [a, b] of [...ranges].sort((x, y) => y[0] - x[0])) visible = visible.slice(0, a) + ' ' + visible.slice(b);
  segments.unshift({ text: stripTags(visible), hidden: null, where: 'text' });
  return { segments };
}
