// Portuguese injection patterns. Same shape as en.mjs.

export default {
  lang: 'pt',
  patterns: {
    // "não diga ao usuário".
    'hide-from-user': [/\bnão (diga|conte|informe|mencione)\b[^.]{0,30}\b(usuária|usuário|cliente)\b/i],
  },
  secretVerbs: ['leia', 'envie', 'anexe', 'inclua', 'copie'],
  secretTargets: [],
};
