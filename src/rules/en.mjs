// English injection patterns. A pack only holds data: for each rule key in
// RULES (../rules.mjs) it lists patterns, and the engine joins the patterns
// that every language pack gives for the same key into one rule.

export default {
  lang: 'en',
  patterns: {
    'ignore-instructions': [/ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|messages)/i],
    'pseudo-tags': [/<\s*\/?\s*(important|system|secret|instructions?)\s*>/i],
    'hide-from-user': [/(do not|don't|never) (tell|mention|inform|reveal to|show) (the )?user/i],
    // Chaining hints ("before using this tool, call list_x") are normal; reading or sending data first is not.
    'steer-other-tools': [/before (using|calling) (this|any other) tool[^.]{0,80}\b(read|send|include|pass|attach|upload)\b/i],
    'override-other-tools': [
      /(whenever|every time|each time|when) (the )?[\w.-]+ tool is (used|called)|(never|do not|don't) call [\w.-]+ directly|\b(supersedes|replaces|overrides) (the |all )?(other )?(tools?|servers?)\b/i,
    ],
    // Must move *data* (conversation, files, secrets…) somewhere; "include a word in the URL" is search syntax.
    'move-data': [
      /\b(send|forward|copy|include|append|put|pass)\b (the |all |its |their |your )?(full |entire |whole )?(conversation|chat|history|context|contents?|data|messages|secrets?|keys?|tokens?|credentials|files?|documents?)\b[^.]{0,40}\b(to|in|into|as) (the )?(sidenote|notes?|parameter|field|http|url|webhook)/i,
    ],
    'image-exfil': [/!\[[^\]]*\]\(https?:\/\//i],
    'ask-credentials': [
      /\b(ask|request|prompt) (the user|them|the customer) for (their |the |a )?[\w ]{0,25}(password|passcode|pin|otp|2fa|verification code|seed phrase|card number)/i,
    ],
    'address-model': [/\b(note|message|instructions?) (to|for) the (ai|assistant|model|llm)\b|\bfrom now on,? you (are|must|will)\b|\byou are now in\b/i],
    'encoded-blob': [/[A-Za-z0-9+/]{80,}={0,2}/],
    steering: [
      /\b((you )?(should|must) always|always) (default to )?(us(e|ing)|call(ing)?|prefer(ring)?) this tool\b|\b(call|use|run) this (tool )?(immediately|first|right after|before any)\b|\b(call|use) this immediately\b|\bthis is the (most powerful|best|only|preferred) [\w\s-]{0,30}tool\b|\b(instead of|rather than|over) (using )?(any |all )?other (\w+ )?tools\b|\bprefer this tool\b/i,
    ],
  },
  // "read ~/.ssh/id_rsa": a verb that acts on a secret, followed by the secret.
  // Mentioning a secret is fine ("lists API key names"); acting on it is what matters.
  secretVerbs: ['read', 'send', 'pass', 'include', 'attach', 'upload', 'copy', 'forward', 'cat', 'leak'],
  secretTargets: [String.raw`~\/\.ssh`, String.raw`\.ssh\b`, 'id_rsa', String.raw`(?<![\w.-])\.env(?![\w.])`, String.raw`\.aws\/credentials`, String.raw`api[_ -]?keys?`, 'private key', 'credentials'],
};
