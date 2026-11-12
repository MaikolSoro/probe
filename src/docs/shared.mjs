// Helpers shared by the document parsers.

// A small compressed stream can expand enormously (zip bomb), so cap every inflate.
export const MAX_INFLATE = 64 * 1024 * 1024;

export const decodeXml = (s) =>
  s.replace(/&(amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);/g, (m, e) => {
    const named = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[e];
    if (named) return named;
    const code = e[1] === 'x' ? parseInt(e.slice(2), 16) : Number(e.slice(1));
    return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : m;
  });
export const xmlText = (s) => decodeXml(s.replace(/<[^>]+>/g, ' '));

export const utf16be = (buf) => {
  const b = Buffer.from(buf.subarray(0, buf.length - (buf.length % 2)));
  return b.swap16().toString('utf16le');
};
export const hexUtf16 = (hex) => {
  if (hex.length <= 2) return String.fromCharCode(parseInt(hex || '0', 16));
  return utf16be(Buffer.from(hex.padStart(Math.ceil(hex.length / 4) * 4, '0'), 'hex'));
};

// Consecutive runs with the same visibility become one segment, so a hidden
// sentence split across formatting runs is still read as one sentence.
export function merge(runs, where) {
  const out = [];
  for (const r of runs) {
    if (!r.text) continue;
    const last = out.at(-1);
    if (last && last.hidden === r.hidden) last.text += r.text;
    else out.push({ text: r.text, hidden: r.hidden ?? null, strong: !!r.strong, where });
  }
  return out;
}
