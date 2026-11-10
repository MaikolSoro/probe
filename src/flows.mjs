// Toxic flows across MCP servers. Each server can look harmless on its own,
// but an agent connected to all of them combines their tools: one reads private
// data, another sends things out, a third brings in content from strangers.
// That combination is what an injected instruction needs to exfiltrate data.
import { capabilitiesOf, words, firstSentence, OWASP } from './rules.mjs';

// Tools that pull in content written by third parties (web pages, email,
// issues, chat), which is where injected instructions arrive from.
const SOURCE = /\b(fetch(es)?|browse|browser|scrape|crawl|web ?pages?|web ?search|search (the )?web|url|inbox|emails?|mails?|messages?|issues?|pull requests?|comments?|reviews?|posts?|tickets?|slack|discord|rss|feeds?)\b/i;
const READS = /\b(get|gets|read|reads|list|lists|search|searches|fetch|fetches|browse|scrape|crawl|retrieve|retrieves|query|open|view|download)\b/i;

export function readsUntrusted(tool) {
  const text = `${words(tool.name)} ${firstSentence(tool.description)}`;
  return SOURCE.test(text) && READS.test(text);
}

const list = (items) => {
  const names = [...new Set(items.map((i) => `${i.server} › ${i.tool}`))];
  return names.length > 3 ? `${names.slice(0, 3).join(', ')} +${names.length - 3} more` : names.join(', ');
};

// servers: [{ name, definitions: [{ name, description, ... }] }] for the servers that started.
export function checkFlows(servers) {
  const tools = servers.flatMap((s) =>
    (s.definitions ?? []).map((t) => ({ server: s.name, tool: t.name, caps: capabilitiesOf(t), untrusted: readsUntrusted(t) })),
  );
  const readers = tools.filter((t) => t.caps.includes('private_read'));
  const senders = tools.filter((t) => t.caps.includes('outbound'));
  // The same-server case is already reported as exfiltration-path; this is about mixing servers.
  const pairs = readers.filter((r) => senders.some((s) => s.server !== r.server));
  if (!pairs.length) return [];
  const outs = senders.filter((s) => pairs.some((r) => r.server !== s.server));
  const sources = tools.filter((t) => t.untrusted);
  const trifecta = sources.length > 0;
  const evidence = [`reads private data: ${list(pairs)}`, `sends out: ${list(outs)}`];
  if (trifecta) evidence.push(`reads untrusted content: ${list(sources)}`);
  return [
    {
      id: 'cross-server-flow',
      severity: trifecta ? 'high' : 'medium',
      owasp: OWASP.LLM02,
      title: trifecta
        ? 'Untrusted content, private data and an outbound channel meet across servers'
        : 'Private data on one server can leave through another',
      detail: trifecta
        ? 'An agent using these servers together reads content written by strangers, can read private data and can send data out. Those three together let an instruction hidden in a web page or email exfiltrate data, even though no single server has all three.'
        : 'An agent using these servers together can read private data with one server and send it out with another. An injected instruction only needs both to be connected to the same agent.',
      evidence: evidence.join(' | '),
      tool: '(config)',
    },
  ];
}
