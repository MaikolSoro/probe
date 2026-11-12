// Spanish injection patterns. Same shape as en.mjs; keys a pack leaves out
// simply have no patterns in this language yet.

export default {
  lang: 'es',
  patterns: {
    // "no le digas (nada) al usuario".
    'hide-from-user': [/\b(no le digas|no le menciones|no informes|sin decirle)\b[^.]{0,30}\b(usuario|cliente)\b/i],
  },
  secretVerbs: ['lee', 'leer', 'envía', 'envia', 'enviar', 'adjunta', 'incluye', 'copia', 'sube'],
  secretTargets: [],
};
