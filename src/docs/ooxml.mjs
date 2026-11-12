// Office Open XML (DOCX, PPTX, XLSX): a built-in ZIP reader plus the text runs
// of each part, tagged with how they are hidden (hidden formatting, white or
// tiny text, hidden slides), and comments, speaker notes and metadata.
import { inflateRawSync } from 'node:zlib';
import { MAX_INFLATE, decodeXml, xmlText, merge } from './shared.mjs';

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

export function officeSegments(buf, ext) {
  const zip = unzip(buf);
  const segments = ext === '.docx' ? docxSegments(zip) : ext === '.pptx' ? pptxSegments(zip) : xlsxSegments(zip);
  for (const part of ['docProps/core.xml', 'docProps/custom.xml']) {
    const text = xmlText(zip.text(part));
    if (text.trim()) segments.push({ text, hidden: 'metadata', where: part });
  }
  return { segments };
}
