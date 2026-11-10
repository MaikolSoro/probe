// Static scan of documents an AI will read (PDF, Word, PowerPoint, Excel, HTML,
// Markdown, text): instructions hidden with white or tiny text, invisible
// rendering, hidden formatting, CSS, comments, metadata or invisible Unicode.
// This is indirect prompt injection planted before a document reaches a RAG
// pipeline or an assistant. Files are parsed as data; nothing is executed or
// opened in another program, and there are no dependencies beyond node:zlib.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, basename, extname } from 'node:path';
import { inflateSync, inflateRawSync, constants as zlib } from 'node:zlib';
import { injectionSignals, OWASP } from './rules.mjs';

export const DOC_EXT = new Set(['.pdf', '.docx', '.pptx', '.xlsx', '.html', '.htm', '.md', '.markdown', '.txt', '.csv']);
const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build']);
const MAX_FILE = 50 * 1024 * 1024;
// A small compressed stream can expand enormously (zip bomb), so cap every inflate.
const MAX_INFLATE = 64 * 1024 * 1024;
const MAX_FINDINGS_PER_FILE = 25;

// How the text was hidden, as it reads in a finding title ("White text tells the model…").
const REASON = {
  white: 'white text',
  tiny: 'tiny text (under 1–2 pt)',
  invisible: 'invisible text (PDF render mode 3)',
  vanish: 'text formatted as hidden',
  css: 'text hidden with CSS or the hidden attribute',
  comment: 'a comment',
  metadata: 'document metadata',
  attribute: 'an alt, title or aria-label attribute',
  tags: 'invisible Unicode tag characters',
  'hidden-slide': 'a hidden slide',
  notes: 'speaker notes',
};

// --- shared helpers -------------------------------------------------------

const decodeXml = (s) =>
  s.replace(/&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (m, e) => {
    const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[e];
    if (named) return named;
    const code = e[1] === 'x' ? parseInt(e.slice(2), 16) : Number(e.slice(1));
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
  });
const xmlText = (s) => decodeXml(s.replace(/<[^>]+>/g, ' '));

const utf16be = (buf) => {
  const b = Buffer.from(buf.subarray(0, buf.length - (buf.length % 2)));
  return b.swap16().toString('utf16le');
};
const hexUtf16 = (hex) => {
  if (hex.length <= 2) return String.fromCharCode(parseInt(hex || '0', 16));
  return utf16be(Buffer.from(hex.padStart(Math.ceil(hex.length / 4) * 4, '0'), 'hex'));
};

// Consecutive runs with the same visibility become one segment, so a hidden
// sentence split across formatting runs is still read as one sentence.
function merge(runs, where) {
  const out = [];
  for (const r of runs) {
    if (!r.text) continue;
    const last = out.at(-1);
    if (last && last.hidden === r.hidden) last.text += r.text;
    else out.push({ text: r.text, hidden: r.hidden ?? null, strong: !!r.strong, where });
  }
  return out;
}

// --- ZIP (OOXML containers) ------------------------------------------------

function unzip(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a valid Office file (no ZIP directory)');
  const entries = new Map();
  let p = buf.readUInt32LE(eocd + 16);
  for (let n = buf.readUInt16LE(eocd + 10); n > 0 && buf.readUInt32LE(p) === 0x02014b50; n--) {
    const nameLen = buf.readUInt16LE(p + 28);
    entries.set(buf.toString('utf8', p + 46, p + 46 + nameLen), {
      method: buf.readUInt16LE(p + 10),
      size: buf.readUInt32LE(p + 20),
      local: buf.readUInt32LE(p + 42),
    });
    p += 46 + nameLen + buf.readUInt16LE(p + 30) + buf.readUInt16LE(p + 32);
  }
  return {
    names: [...entries.keys()],
    text(name) {
      const e = entries.get(name);
      if (!e) return '';
      const start = e.local + 30 + buf.readUInt16LE(e.local + 26) + buf.readUInt16LE(e.local + 28);
      const data = buf.subarray(start, start + e.size);
      return (e.method === 0 ? data : inflateRawSync(data, { maxOutputLength: MAX_INFLATE })).toString('utf8');
    },
  };
}

const byNumber = (a, b) => Number(/\d+/.exec(a)?.[0] ?? 0) - Number(/\d+/.exec(b)?.[0] ?? 0);

function docxSegments(zip) {
  const segments = [];
  const parts = zip.names.filter((n) => /^word\/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$/.test(n));
  for (const part of parts) {
    const runs = [];
    for (const [p] of zip.text(part).matchAll(/<w:p[ >][\s\S]*?<\/w:p>/g)) {
      for (const [, rPr = '', body] of p.matchAll(/<w:r(?:\s[^>]*)?>(?:<w:rPr>([\s\S]*?)<\/w:rPr>)?([\s\S]*?)<\/w:r>/g)) {
        const text = [...body.matchAll(/<w:t(?:\s[^>]*)?>([^<]*)<\/w:t>|<w:(?:tab|br)\b[^>]*\/>/g)]
          .map((m) => (m[1] !== undefined ? decodeXml(m[1]) : ' '))
          .join('');
        if (!text) continue;
        const on = (tag) => new RegExp(`<w:${tag}(?:\\s+w:val="(?!0"|false")[^"]*")?\\s*/>`).test(rPr);
        const size = Number(/<w:sz w:val="(\d+)"/.exec(rPr)?.[1] ?? 24) / 2; // half-points
        const white = /<w:color w:val="FFFFFF"/i.test(rPr);
        const hidden = on('vanish') || on('specVanish') ? 'vanish' : size < 2 ? 'tiny' : white ? 'white' : null;
        runs.push({ text, hidden, strong: hidden === 'vanish' || hidden === 'tiny' });
      }
      runs.push({ text: '\n', hidden: runs.at(-1)?.hidden ?? null });
    }
    segments.push(...merge(runs, part.replace(/^word\/|\.xml$/g, '')));
  }
  for (const [, c] of zip.text('word/comments.xml').matchAll(/<w:comment\b[^>]*>([\s\S]*?)<\/w:comment>/g)) {
    segments.push({ text: xmlText(c), hidden: 'comment', where: 'comments' });
  }
  return segments;
}

function pptxSegments(zip) {
  const segments = [];
  const slides = zip.names.filter((n) => /^ppt\/slides\/slide\d+\.xml$/.test(n)).sort(byNumber);
  for (const part of slides) {
    const xml = zip.text(part);
    const where = `slide ${/\d+/.exec(part.slice(11))[0]}`;
    const hiddenSlide = /<p:sld\b[^>]*\sshow="(0|false)"/.test(xml);
    const runs = [];
    for (const [, attrs = '', props = '', text] of xml.matchAll(/<a:r>(?:<a:rPr\b([^>]*?)(?:\/>|>([\s\S]*?)<\/a:rPr>))?[\s\S]*?<a:t>([^<]*)<\/a:t>[\s\S]*?<\/a:r>/g)) {
      const size = Number(/\bsz="(\d+)"/.exec(attrs)?.[1] ?? 1800) / 100; // hundredths of a point
      const white = /<a:solidFill>\s*<a:srgbClr val="FFFFFF"/i.test(props);
      const hidden = hiddenSlide ? 'hidden-slide' : size < 2 ? 'tiny' : white ? 'white' : null;
      runs.push({ text: `${decodeXml(text)} `, hidden, strong: hidden === 'hidden-slide' || hidden === 'tiny' });
    }
    segments.push(...merge(runs, where));
  }
  for (const part of zip.names.filter((n) => /^ppt\/notesSlides\/notesSlide\d+\.xml$/.test(n))) {
    const text = [...zip.text(part).matchAll(/<a:t>([^<]*)<\/a:t>/g)].map((m) => decodeXml(m[1])).join(' ');
    segments.push({ text, hidden: 'notes', where: part.slice(4) });
  }
  return segments;
}

function xlsxSegments(zip) {
  const strings = [...zip.text('xl/sharedStrings.xml').matchAll(/<t(?:\s[^>]*)?>([^<]*)<\/t>/g)].map((m) => decodeXml(m[1]));
  const inline = zip.names
    .filter((n) => /^xl\/worksheets\/sheet\d+\.xml$/.test(n))
    .flatMap((n) => [...zip.text(n).matchAll(/<is>[\s\S]*?<t(?:\s[^>]*)?>([^<]*)<\/t>/g)].map((m) => decodeXml(m[1])));
  const segments = [{ text: [...strings, ...inline].join('\n'), hidden: null, where: 'cells' }];
  for (const part of zip.names.filter((n) => /^xl\/(comments\d*|threadedComments\/[^/]+)\.xml$/.test(n))) {
    segments.push({ text: xmlText(zip.text(part)), hidden: 'comment', where: 'comments' });
  }
  return segments;
}

function officeSegments(buf, ext) {
  const zip = unzip(buf);
  const segments = ext === '.docx' ? docxSegments(zip) : ext === '.pptx' ? pptxSegments(zip) : xlsxSegments(zip);
  for (const part of ['docProps/core.xml', 'docProps/custom.xml']) {
    const text = xmlText(zip.text(part));
    if (text.trim()) segments.push({ text, hidden: 'metadata', where: part });
  }
  return { segments };
}

// --- HTML and Markdown -----------------------------------------------------

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

function htmlSegments(source) {
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

// --- PDF ------------------------------------------------------------------

const DELIM = new Set([...' \t\r\n\f\0/[]()<>{}%']);
const SPACE = new Set([...' \t\r\n\f\0']);

// A minimal tokenizer for PDF objects and content streams: strings, names,
// numbers, arrays and operators. Inline image data (BI … ID … EI) is skipped.
function* pdfTokens(s) {
  const n = s.length;
  let i = 0;
  while (i < n) {
    const c = s[i];
    if (SPACE.has(c)) {
      i++;
    } else if (c === '%') {
      while (i < n && s[i] !== '\n' && s[i] !== '\r') i++;
    } else if (c === '(') {
      const out = [];
      let depth = 1;
      let j = i + 1;
      while (j < n) {
        const ch = s[j];
        if (ch === '\\') {
          const nx = s[j + 1] ?? '';
          if (nx >= '0' && nx <= '7') {
            let k = j + 1;
            let oct = '';
            while (k < j + 4 && s[k] >= '0' && s[k] <= '7') oct += s[k++];
            out.push(parseInt(oct, 8) & 255);
            j = k;
            continue;
          }
          if (nx === '\r' || nx === '\n') {
            j += nx === '\r' && s[j + 2] === '\n' ? 3 : 2;
            continue;
          }
          const esc = { n: 10, r: 13, t: 9, b: 8, f: 12 }[nx];
          out.push(esc ?? nx.charCodeAt(0) & 255);
          j += 2;
          continue;
        }
        if (ch === '(') depth++;
        else if (ch === ')' && --depth === 0) {
          j++;
          break;
        }
        out.push(ch.charCodeAt(0) & 255);
        j++;
      }
      yield { t: 'str', v: Buffer.from(out) };
      i = j;
    } else if (c === '<' && s[i + 1] === '<') {
      yield { t: 'op', v: '<<' };
      i += 2;
    } else if (c === '>' && s[i + 1] === '>') {
      yield { t: 'op', v: '>>' };
      i += 2;
    } else if (c === '<') {
      const j = s.indexOf('>', i);
      const hex = s.slice(i + 1, j < 0 ? n : j).replace(/[^0-9A-Fa-f]/g, '');
      yield { t: 'str', v: Buffer.from(hex.length % 2 ? `${hex}0` : hex, 'hex') };
      i = j < 0 ? n : j + 1;
    } else if (c === '[' || c === ']') {
      yield { t: c };
      i++;
    } else if (c === '/') {
      let j = i + 1;
      while (j < n && !DELIM.has(s[j])) j++;
      yield { t: 'name', v: s.slice(i + 1, j) };
      i = j;
    } else {
      let j = i;
      while (j < n && !DELIM.has(s[j])) j++;
      if (j === i) {
        i++;
        continue;
      }
      const w = s.slice(i, j);
      i = j;
      if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(w)) yield { t: 'num', v: Number(w) };
      else if (w === 'ID') {
        const ei = /\sEI(?=[\s]|$)/g;
        ei.lastIndex = i;
        const m = ei.exec(s);
        i = m ? m.index + m[0].length : n;
      } else yield { t: 'op', v: w };
    }
  }
}

function decodeStream(dict, data) {
  // Images and embedded fonts never carry readable text.
  if (/\/Subtype\s*\/Image\b|\/(DCTDecode|JPXDecode|CCITTFaxDecode|JBIG2Decode)\b|\/Length[123]\b/.test(dict)) return null;
  if (/\/FlateDecode\b/.test(dict)) {
    try {
      return inflateSync(data, { maxOutputLength: MAX_INFLATE });
    } catch {
      try {
        return inflateSync(data, { finishFlush: zlib.Z_SYNC_FLUSH, maxOutputLength: MAX_INFLATE });
      } catch {
        return null;
      }
    }
  }
  return /\/Filter\b/.test(dict) ? null : data; // LZW, ASCII85 and others are rare in current files
}

function pdfObjects(raw) {
  const objs = new Map();
  const re = /(\d+)\s+\d+\s+obj\b/g;
  for (let m; (m = re.exec(raw)); ) {
    const start = m.index + m[0].length;
    const endobj = raw.indexOf('endobj', start);
    const sm = /\bstream\r?\n/g;
    sm.lastIndex = start;
    const s = sm.exec(raw);
    let body;
    let stream = null;
    let end;
    if (s && (endobj < 0 || s.index < endobj)) {
      body = raw.slice(start, s.index);
      const dataStart = s.index + s[0].length;
      // A direct /Length is safer than searching: binary data may contain "endstream".
      const len = /\/Length\s+(\d+)\b(?!\s+\d+\s+R)/.exec(body);
      let dataEnd = len ? dataStart + Number(len[1]) : -1;
      if (dataEnd < 0 || dataEnd > raw.length || !/^\s*endstream/.test(raw.slice(dataEnd, dataEnd + 20))) dataEnd = raw.indexOf('endstream', dataStart);
      if (dataEnd < 0) break;
      stream = decodeStream(body, Buffer.from(raw.slice(dataStart, dataEnd), 'latin1'));
      end = raw.indexOf('endobj', dataEnd);
      if (end < 0) end = dataEnd;
    } else {
      if (endobj < 0) break;
      body = raw.slice(start, endobj);
      end = endobj;
    }
    objs.set(Number(m[1]), { body, stream });
    re.lastIndex = end;
  }
  // PDF 1.5+ packs small objects (fonts, metadata, annotations) into object streams.
  for (const [, o] of [...objs]) {
    if (!o.stream || !/\/Type\s*\/ObjStm\b/.test(o.body)) continue;
    const count = Number(/\/N\s+(\d+)/.exec(o.body)?.[1] ?? 0);
    const first = Number(/\/First\s+(\d+)/.exec(o.body)?.[1] ?? 0);
    const text = o.stream.toString('latin1');
    const head = text.slice(0, first).trim().split(/\s+/).map(Number);
    for (let i = 0; i < count; i++) {
      const num = head[2 * i];
      const from = first + head[2 * i + 1];
      const to = i + 1 < count ? first + head[2 * i + 3] : text.length;
      if (Number.isFinite(num) && !objs.has(num)) objs.set(num, { body: text.slice(from, to), stream: null });
    }
  }
  return objs;
}

const refOf = (body, key) => Number(new RegExp(`/${key}\\s+(\\d+)\\s+\\d+\\s+R`).exec(body)?.[1]);

function parseCMap(text) {
  const map = new Map();
  const cs = /begincodespacerange\s*<([0-9A-Fa-f]+)>/.exec(text);
  const bytes = cs ? Math.max(1, cs[1].length / 2) : 1;
  for (const [, block] of text.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
    for (const [, src, dst] of block.matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>/g)) map.set(parseInt(src, 16), hexUtf16(dst));
  }
  for (const [, block] of text.matchAll(/beginbfrange([\s\S]*?)endbfrange/g)) {
    for (const [, lo, hi, dst] of block.matchAll(/<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]*>|\[[^\]]*\])/g)) {
      const a = parseInt(lo, 16);
      const b = parseInt(hi, 16);
      if (b < a || b - a > 65535) continue;
      if (dst.startsWith('[')) {
        [...dst.matchAll(/<([0-9A-Fa-f]*)>/g)].forEach((x, i) => map.set(a + i, hexUtf16(x[1])));
      } else {
        const base = hexUtf16(dst.slice(1, -1));
        for (let i = 0; i <= b - a; i++) map.set(a + i, base.slice(0, -1) + String.fromCharCode(base.charCodeAt(base.length - 1) + i));
      }
    }
  }
  return { map, bytes };
}

function decodePdfString(buf, font) {
  const cmap = font?.cmap;
  if (cmap) {
    let out = '';
    for (let i = 0; i + cmap.bytes <= buf.length; i += cmap.bytes) out += cmap.map.get(buf.readUIntBE(i, cmap.bytes)) ?? '';
    return out;
  }
  if (buf[0] === 0xfe && buf[1] === 0xff) return utf16be(buf.subarray(2));
  return buf.toString('latin1');
}

// How far a string moves the pen, in text-space units, from the font's glyph
// widths. Null when the font has no width table (the 14 standard fonts).
function advanceOf(buf, font, size) {
  if (!font?.widths.size) return null;
  let w = 0;
  for (let i = 0; i + font.bytes <= buf.length; i += font.bytes) w += font.widths.get(buf.readUIntBE(i, font.bytes)) ?? font.dw;
  return (w / 1000) * size;
}

// Walks a content stream and returns its text runs, each tagged with how it is
// hidden: white fill, render mode 3 (invisible) or an effective size under 1 pt.
function pdfText(content, fonts) {
  const runs = [];
  let st = { white: false, mode: 0, size: 12, scale: 1, ctm: 1, font: null };
  const stack = [];
  let ops = [];
  let arr = null;
  let line = null; // last Tm origin, to tell a new line from the next glyph on the same line
  let adv = 0; // pen movement since the start of the current line, or NaN when unknown
  // Many generators (Chrome among them) place glyph by glyph and draw spaces as glyphs,
  // so a move is a word break only when it leaves a gap wider than a fifth of an em.
  const isGap = (move, scale) => (Number.isFinite(adv) ? move - adv * scale > 0.2 * st.size * scale : move > st.size * scale);
  const sep = () => {
    const last = runs.at(-1);
    if (last && !/\s$/.test(last.text)) last.text += ' ';
  };
  const push = (buf) => {
    adv += advanceOf(buf, st.font, st.size) ?? NaN;
    const text = decodePdfString(buf, st.font);
    if (!text) return;
    const size = st.size * st.scale * st.ctm;
    const hidden = size < 1 ? 'tiny' : st.mode === 3 ? 'invisible' : st.white ? 'white' : null;
    const last = runs.at(-1);
    if (last && last.hidden === hidden) last.text += text;
    else runs.push({ text, hidden, strong: hidden === 'tiny' });
  };
  for (const tk of pdfTokens(content)) {
    if (tk.t === '[') {
      arr = [];
      continue;
    }
    if (tk.t === ']') {
      ops.push({ t: 'arr', v: arr ?? [] });
      arr = null;
      continue;
    }
    if (arr) {
      arr.push(tk);
      continue;
    }
    if (tk.t !== 'op') {
      ops.push(tk);
      continue;
    }
    const nums = ops.filter((o) => o.t === 'num').map((o) => o.v);
    const whiteOf = (v) => (v.length === 1 ? v[0] >= 0.95 : v.length === 3 ? v.every((x) => x >= 0.95) : v.length === 4 ? v.every((x) => x <= 0.05) : false);
    switch (tk.v) {
      case 'q':
        stack.push({ ...st });
        break;
      case 'Q':
        st = stack.pop() ?? st;
        break;
      case 'cm':
        st.ctm *= Math.hypot(nums[2] ?? 0, nums[3] ?? 1) || 1;
        break;
      case 'BT':
        st.scale = 1;
        line = null;
        adv = 0;
        sep();
        break;
      case 'Tf':
        st.font = fonts.get(ops.find((o) => o.t === 'name')?.v) ?? null;
        st.size = Math.abs(nums.at(-1) ?? st.size);
        break;
      case 'Tm': {
        st.scale = Math.hypot(nums[2] ?? 0, nums[3] ?? 1) || 1;
        const [e = 0, f = 0] = nums.slice(4);
        // Some generators place every glyph with its own Tm on the same baseline.
        if (!line || Math.abs(f - line.f) >= 0.5 || e < line.e || isGap(e - line.e, st.scale)) sep();
        line = { e, f };
        adv = 0;
        break;
      }
      case 'Tr':
        st.mode = nums[0] ?? 0;
        break;
      case 'g':
      case 'rg':
      case 'k':
      case 'sc':
      case 'scn':
        st.white = whiteOf(nums);
        break;
      case 'cs':
        st.white = false; // a new colour space starts at its default, black
        break;
      case 'Td':
      case 'TD': {
        const [tx = 0, ty = 0] = nums.slice(-2);
        if (ty !== 0 || tx < 0 || isGap(tx, 1)) sep();
        if (line) line = { e: line.e + tx * st.scale, f: line.f + ty * st.scale };
        adv = 0;
        break;
      }
      case 'T*':
        adv = 0;
        sep();
        break;
      case 'ET':
        sep();
        break;
      case 'Tj': {
        const s = ops.find((o) => o.t === 'str');
        if (s) push(s.v);
        break;
      }
      case "'":
      case '"': {
        adv = 0;
        sep();
        const s = ops.findLast((o) => o.t === 'str');
        if (s) push(s.v);
        break;
      }
      case 'TJ':
        for (const el of ops.find((o) => o.t === 'arr')?.v ?? []) {
          if (el.t === 'str') push(el.v);
          else if (el.t === 'num') {
            adv -= (el.v / 1000) * st.size;
            if (el.v < -200) sep(); // a large kerning gap is a word space
          }
        }
        break;
    }
    ops = [];
  }
  return runs;
}

// The first array in s, with nested arrays kept (for /W, /Widths, /DescendantFonts).
function firstArray(s = '') {
  const stack = [];
  let out = [];
  for (const tk of pdfTokens(s)) {
    if (tk.t === '[') {
      const a = [];
      if (stack.length) stack.at(-1).push(a);
      else out = a;
      stack.push(a);
    } else if (tk.t === ']') {
      stack.pop();
      if (!stack.length) break;
    } else if (stack.length && tk.t === 'num') stack.at(-1).push(tk.v);
  }
  return out;
}

// An array value given inline or as a reference to another object.
function arrayOf(objs, body, key) {
  const m = new RegExp(`/${key}\\s*(?:(\\d+)\\s+\\d+\\s+R|(?=\\[))`).exec(body);
  if (!m) return [];
  return firstArray(m[1] ? objs.get(Number(m[1]))?.body : body.slice(m.index + m[0].length));
}

// Unicode map and glyph widths of a font, used to decode text and to tell word
// gaps from glyph-by-glyph positioning.
function fontInfo(objs, body) {
  const stream = objs.get(refOf(body, 'ToUnicode'))?.stream;
  const cmap = stream ? parseCMap(stream.toString('latin1')) : null;
  const type0 = /\/Subtype\s*\/Type0\b/.test(body);
  const font = { cmap, bytes: cmap?.bytes ?? (type0 ? 2 : 1), widths: new Map(), dw: 1000 };
  if (type0) {
    const desc = objs.get(arrayOf(objs, body, 'DescendantFonts')[0])?.body ?? '';
    font.dw = Number(/\/DW\s+(\d+)/.exec(desc)?.[1] ?? 1000);
    const w = arrayOf(objs, desc, 'W');
    for (let i = 0; i < w.length; ) {
      if (Array.isArray(w[i + 1])) {
        w[i + 1].forEach((v, k) => font.widths.set(w[i] + k, v));
        i += 2;
      } else {
        for (let c = w[i]; c <= w[i + 1] && c - w[i] < 65536; c++) font.widths.set(c, w[i + 2]);
        i += 3;
      }
    }
  } else {
    const first = Number(/\/FirstChar\s+(\d+)/.exec(body)?.[1] ?? 0);
    arrayOf(objs, body, 'Widths').forEach((v, k) => font.widths.set(first + k, v));
    font.dw = 0;
  }
  return font;
}

function firstString(s) {
  const tk = pdfTokens(s).next().value;
  return tk?.t === 'str' ? decodePdfString(tk.v) : '';
}

function pdfSegments(buf) {
  const objs = pdfObjects(buf.toString('latin1'));
  const fontsByObj = new Map();
  for (const [num, o] of objs) if (/\/Type\s*\/Font\b/.test(o.body)) fontsByObj.set(num, fontInfo(objs, o.body));
  const fontNames = (body) => {
    const res = objs.get(refOf(body, 'Resources'))?.body ?? body;
    const dict = objs.get(refOf(res, 'Font'))?.body ?? /\/Font\s*<<([\s\S]*?)>>/.exec(res)?.[1] ?? '';
    const map = new Map();
    for (const [, name, num] of dict.matchAll(/\/([^\s/<>[\]()]+)\s+(\d+)\s+\d+\s+R/g)) map.set(name, fontsByObj.get(Number(num)) ?? null);
    return map;
  };
  // Fonts from every resource dictionary, for content whose page does not list its own.
  const global = new Map();
  for (const [, o] of objs) for (const [k, v] of fontNames(o.body)) if (!global.has(k)) global.set(k, v);

  const pageOf = new Map();
  let page = 0;
  for (const [, o] of objs) {
    if (!/\/Type\s*\/Page\b/.test(o.body)) continue;
    page++;
    const own = fontNames(o.body);
    const c = /\/Contents\s*(?:(\d+)\s+\d+\s+R|\[([^\]]*)\])/.exec(o.body);
    const refs = c ? (c[1] ? [c[1]] : [...c[2].matchAll(/(\d+)\s+\d+\s+R/g)].map((x) => x[1])) : [];
    for (const r of refs) pageOf.set(Number(r), { page, fonts: own.size ? own : global });
  }

  const segments = [];
  let textStreams = 0;
  let visible = '';
  let images = false;
  for (const [num, o] of objs) {
    if (/\/Subtype\s*\/Image\b/.test(o.body)) images = true;
    if (!o.stream || /\/Type\s*\/(ObjStm|XRef|Metadata)\b/.test(o.body)) continue;
    const s = o.stream.toString('latin1');
    if (!/\bBT\b/.test(s) || !/(Tj|TJ|'|")/.test(s)) continue;
    textStreams++;
    const info = pageOf.get(num);
    const own = /\/Subtype\s*\/Form\b/.test(o.body) ? fontNames(o.body) : null;
    const runs = pdfText(s, own?.size ? own : info?.fonts ?? global);
    for (const r of runs) if (!r.hidden) visible += r.text;
    segments.push(...merge(runs, info ? `page ${info.page}` : 'form'));
  }

  for (const [, o] of objs) {
    if (/\/Type\s*\/Sig\b/.test(o.body)) continue; // signature /Contents is binary
    for (const m of o.body.matchAll(/\/(Title|Author|Subject|Keywords)\s*(?=\(|<[0-9A-Fa-f])/g)) {
      segments.push({ text: firstString(o.body.slice(m.index + m[0].length)), hidden: 'metadata', where: `/${m[1]}` });
    }
    for (const m of o.body.matchAll(/\/Contents\s*(?=\(|<[0-9A-Fa-f])/g)) {
      segments.push({ text: firstString(o.body.slice(m.index + m[0].length)), hidden: 'comment', where: 'annotation' });
    }
    if (/\/Type\s*\/Metadata\b/.test(o.body) && o.stream) {
      segments.push({ text: xmlText(o.stream.toString('utf8')), hidden: 'metadata', where: 'XMP' });
    }
  }

  // Fonts without a Unicode map come out as glyph codes: say so instead of reporting clean.
  const letters = (visible.match(/[\p{L}\p{N}\s.,;:!?'"()-]/gu) ?? []).length;
  let unreadable = null;
  if (textStreams && visible.length >= 20 && letters / visible.length < 0.6) unreadable = 'Some text uses a font encoding Probe cannot decode';
  else if (!textStreams && images) unreadable = 'No text layer (scanned or image-only PDF)';
  return { segments, unreadable };
}

// --- analysis ---------------------------------------------------------------

// Zero-width joiners (emoji) and a leading byte-order mark are normal in documents.
const ZERO_WIDTH = /[​‌‎‏‪-‮⁠-⁤]/g;
const TAG_CHARS = /[\u{E0000}-\u{E007F}]+/gu;
const fromTags = (s) => [...s].map((c) => String.fromCodePoint(c.codePointAt(0) - 0xe0000)).join('');

// Documents embed images and long data, and the invisible-character check is
// done separately, so only instruction-like signals count here.
function signalsOf(text, hidden) {
  return injectionSignals(text).filter((s) => !/invisible Unicode|encoded blob/.test(s.why) && (hidden || !/external image/.test(s.why)));
}

const clip = (s, n = 160) => (s.length > n ? `${s.slice(0, n)}…` : s);

export function checkSegments(file, segments) {
  const findings = [];
  const seen = new Set();
  const add = (f) => {
    const key = `${f.id}|${f.evidence}`;
    if (seen.has(key) || findings.length >= MAX_FINDINGS_PER_FILE) return;
    seen.add(key);
    findings.push({ owasp: OWASP.LLM01, tool: file, ...f });
  };

  let zeroWidth = 0;
  const all = [];
  for (const seg of segments) {
    let text = seg.text ?? '';
    // Unicode tag characters spell ASCII that people cannot see ("ASCII smuggling").
    text = text.replace(TAG_CHARS, (m) => {
      all.push({ text: fromTags(m), hidden: 'tags', strong: true, where: seg.where });
      return '';
    });
    zeroWidth += (text.match(ZERO_WIDTH) ?? []).length;
    // NFKC folds ligatures and full-width letters ("ﬁle", "ｉｇｎｏｒｅ") that would slip past the patterns.
    all.push({ ...seg, text: text.replace(ZERO_WIDTH, '').replace(/^﻿/, '').normalize('NFKC').replace(/\s+/g, ' ').trim() });
  }

  for (const seg of all) {
    if (!seg.text) continue;
    const where = seg.where ? `${seg.where} · ` : '';
    const sig = signalsOf(seg.text, !!seg.hidden);
    if (sig.length && seg.hidden) {
      const reason = REASON[seg.hidden];
      add({
        id: 'doc-hidden-instructions',
        severity: 'critical',
        title: `${reason[0].toUpperCase()}${reason.slice(1)} ${sig[0].why}`,
        detail: `Text a person reading "${file}" does not see (${reason}) carries instructions for an AI. An assistant or RAG pipeline that ingests this document reads it as part of its context.`,
        evidence: `${where}${reason}: "${clip(seg.text)}"`,
      });
    } else if (sig.length) {
      const at = seg.text.indexOf(sig[0].evidence);
      add({
        id: 'doc-injection',
        severity: 'high',
        title: `Document text ${sig[0].why}`,
        detail: `"${file}" contains text aimed at an AI model. If the document is about prompt injection this may be a legitimate example; otherwise, do not feed it to an assistant until it is cleaned.`,
        evidence: `${where}"${clip(seg.text.slice(Math.max(0, at - 40)))}"`,
      });
    } else if (seg.hidden && seg.strong && seg.text.length >= 20) {
      add({
        id: 'doc-hidden-text',
        severity: 'low',
        title: `Document contains ${REASON[seg.hidden]}`,
        detail: 'No instructions were recognized in it, but people cannot see this text while an AI reads it. Review it by hand.',
        evidence: `${where}"${clip(seg.text, 120)}"`,
      });
    }
  }

  if (zeroWidth >= 3) {
    add({
      id: 'doc-invisible-characters',
      severity: 'medium',
      title: `Document contains ${zeroWidth} invisible zero-width or direction-control characters`,
      detail: 'These characters can split words so filters miss them, or hide text from reviewers. Normal in some right-to-left text; otherwise worth a look.',
      evidence: `${zeroWidth} characters`,
    });
  }
  return findings;
}

// Exported for debugging and for a future LLM-judge pass over document text.
export function extractDocument(file) {
  const ext = extname(file).toLowerCase();
  const buf = readFileSync(file);
  if (ext === '.pdf') return pdfSegments(buf);
  if (ext === '.docx' || ext === '.pptx' || ext === '.xlsx') return officeSegments(buf, ext);
  const text = buf.toString('utf8');
  if (['.html', '.htm', '.md', '.markdown'].includes(ext)) return htmlSegments(text);
  return { segments: [{ text, hidden: null, where: 'text' }] };
}

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) walk(full, out);
    else if (DOC_EXT.has(extname(name).toLowerCase()) && st.size <= MAX_FILE) out.push(full);
  }
  return out;
}

export function scanDocs(root) {
  const isDir = statSync(root).isDirectory();
  if (!isDir && !DOC_EXT.has(extname(root).toLowerCase())) {
    throw new Error(`unsupported document type "${extname(root) || basename(root)}" (supported: ${[...DOC_EXT].join(' ')})`);
  }
  const files = isDir ? walk(root) : [root];
  const findings = [];
  for (const file of files) {
    const rel = relative(root, file) || basename(file);
    let result;
    try {
      result = extractDocument(file);
    } catch (err) {
      result = { segments: [], unreadable: `Could not be parsed (${err.message})` };
    }
    findings.push(...checkSegments(rel, result.segments));
    if (result.unreadable) {
      findings.push({
        id: 'doc-unreadable',
        severity: 'low',
        owasp: OWASP.LLM01,
        title: 'Part of the document could not be checked',
        detail: 'Probe could not read all of its text, so this result does not cover it. An AI with OCR or vision may still read what Probe could not. Review it by hand.',
        evidence: result.unreadable,
        tool: rel,
      });
    }
  }
  return { target: root, kind: 'docs', files: files.length, findings };
}
