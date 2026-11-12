// Static scan of documents an AI will read (PDF, Word, PowerPoint, Excel, HTML,
// Markdown, text): instructions hidden with white or tiny text, invisible
// rendering, hidden formatting, CSS, comments, metadata or invisible Unicode.
// This is indirect prompt injection planted before a document reaches a RAG
// pipeline or an assistant. Files are parsed as data; nothing is executed or
// opened in another program, and there are no dependencies beyond node:zlib.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, basename, extname } from 'node:path';
import { injectionSignals, OWASP } from './rules.mjs';
import { pdfSegments } from './docs/pdf.mjs';
import { officeSegments } from './docs/ooxml.mjs';
import { htmlSegments } from './docs/html.mjs';

export const DOC_EXT = new Set(['.pdf', '.docx', '.pptx', '.xlsx', '.html', '.htm', '.md', '.markdown', '.txt', '.csv']);
const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build']);
const MAX_FILE = 50 * 1024 * 1024;
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
