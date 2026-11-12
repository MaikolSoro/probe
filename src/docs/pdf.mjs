// PDF without dependencies: objects and object streams, Flate streams, a
// content-stream tokenizer with the text state (fonts, colour, render mode,
// size), ToUnicode CMaps and glyph widths, plus metadata and annotations.
import { inflateSync, constants as zlib } from 'node:zlib';
import { MAX_INFLATE, xmlText, utf16be, hexUtf16, merge } from './shared.mjs';

const DELIM = new Set([...' \t\r\n\f\0/[]()<>{}%']);
const SPACE = new Set([...' \t\r\n\f\0']);

// A minimal tokenizer for PDF objects and content streams: strings, names,
// numbers, arrays and operators. Inline image data (BI … ID … EI) is skipped.
/** @returns {Generator<{ t: string, v?: any }>} */
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

export function pdfSegments(buf) {
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
