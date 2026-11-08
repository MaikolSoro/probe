// Plain-language explanation and fix for each finding id, in English and Spanish.
// Used by the client-facing HTML/PDF report; the terminal output stays technical.

const G = {
  'tool-poisoning': {
    en: {
      title: 'Hidden instructions in a tool description',
      explain: 'The model reads tool descriptions as trusted instructions. This one contains text that can make an agent leak data or misuse other tools without the user noticing.',
      fix: 'Remove any instruction-like text from the description. Review third-party MCP servers before installing them, pin their versions and re-scan after every update.',
    },
    es: {
      title: 'Instrucciones escondidas en la descripción de una herramienta',
      explain: 'El modelo lee las descripciones de las herramientas como instrucciones de confianza. Esta contiene texto que puede hacer que un agente filtre datos o use mal otras herramientas sin que el usuario lo note.',
      fix: 'Elimina de la descripción todo texto que parezca una instrucción. Revisa los servidores MCP de terceros antes de instalarlos, fija sus versiones y vuelve a escanear después de cada actualización.',
    },
  },
  'invisible-characters': {
    en: {
      title: 'Invisible characters in tool metadata',
      explain: 'Invisible Unicode characters can hide text from human reviewers while the model still reads it.',
      fix: 'Strip zero-width and bidirectional control characters from tool names and descriptions, and reject them in validation.',
    },
    es: {
      title: 'Caracteres invisibles en los datos de una herramienta',
      explain: 'Los caracteres Unicode invisibles pueden ocultar texto a quien revisa el código, mientras el modelo sí lo lee.',
      fix: 'Elimina los caracteres de ancho cero y de control de dirección de los nombres y descripciones, y recházalos al validar.',
    },
  },
  'long-description': {
    en: {
      title: 'Unusually long tool description',
      explain: 'Long descriptions are a common place to hide instructions.',
      fix: 'Keep descriptions short and factual, and review this one manually.',
    },
    es: {
      title: 'Descripción de herramienta demasiado larga',
      explain: 'Las descripciones largas son un lugar común para esconder instrucciones.',
      fix: 'Mantén las descripciones cortas y concretas, y revisa esta a mano.',
    },
  },
  'capability-exec': {
    en: {
      title: 'Tool can execute code or commands',
      explain: 'If an attacker controls any text the agent reads (an email, a web page, a document), they may be able to make it run commands.',
      fix: 'Remove the tool if it is not essential. Otherwise run it in a sandbox, allow only specific commands and require human approval for every call.',
    },
    es: {
      title: 'La herramienta puede ejecutar código o comandos',
      explain: 'Si un atacante controla cualquier texto que lea el agente (un correo, una página web, un documento), podría hacer que ejecute comandos.',
      fix: 'Elimina la herramienta si no es indispensable. Si lo es, ejecútala en un entorno aislado, permite solo comandos específicos y exige aprobación humana en cada uso.',
    },
  },
  'capability-destructive': {
    en: {
      title: 'Tool can delete or destroy data',
      explain: 'An injected instruction could trigger irreversible deletions.',
      fix: 'Use soft deletes, require human approval and keep tested backups.',
    },
    es: {
      title: 'La herramienta puede borrar datos',
      explain: 'Una instrucción inyectada podría provocar borrados irreversibles.',
      fix: 'Usa borrado lógico (recuperable), exige aprobación humana y mantén respaldos probados.',
    },
  },
  'capability-financial': {
    en: {
      title: 'Tool can move money',
      explain: 'An agent that pays, refunds or transfers can be talked into sending money to an attacker.',
      fix: 'Set amount limits, require human approval and confirm new recipients through a second channel.',
    },
    es: {
      title: 'La herramienta puede mover dinero',
      explain: 'Un agente que paga, reembolsa o transfiere puede ser engañado para enviar dinero a un atacante.',
      fix: 'Pon límites de monto, exige aprobación humana y confirma los destinatarios nuevos por otro canal.',
    },
  },
  'capability-outbound': {
    en: {
      title: 'Tool can send information outside',
      explain: 'Email, HTTP or messaging tools are the channel an attacker uses to get stolen data out.',
      fix: 'Allow only known recipients or domains and require approval for anything external.',
    },
    es: {
      title: 'La herramienta puede enviar información hacia afuera',
      explain: 'Las herramientas de correo, HTTP o mensajería son el canal que usa un atacante para sacar los datos robados.',
      fix: 'Permite solo destinatarios o dominios conocidos y exige aprobación para cualquier envío externo.',
    },
  },
  'capability-write': {
    en: {
      title: 'Tool can modify data',
      explain: 'Write access lets an injected instruction change records.',
      fix: 'Give the tool the narrowest scope possible and log every change.',
    },
    es: {
      title: 'La herramienta puede modificar datos',
      explain: 'El acceso de escritura permite que una instrucción inyectada cambie registros.',
      fix: 'Dale a la herramienta el alcance más reducido posible y registra cada cambio.',
    },
  },
  'annotation-mismatch': {
    en: {
      title: 'Tool marked read-only but changes things',
      explain: 'Clients may skip confirmation for tools marked read-only.',
      fix: 'Correct the readOnlyHint and destructiveHint annotations.',
    },
    es: {
      title: 'Herramienta marcada como solo lectura que sí cambia cosas',
      explain: 'Los clientes pueden omitir la confirmación en herramientas marcadas como solo lectura.',
      fix: 'Corrige las anotaciones readOnlyHint y destructiveHint.',
    },
  },
  'missing-annotations': {
    en: {
      title: 'High-impact tool without a risk annotation',
      explain: 'Without destructiveHint, clients cannot know they should ask before calling it.',
      fix: 'Set destructiveHint: true so clients request confirmation.',
    },
    es: {
      title: 'Herramienta de alto impacto sin anotación de riesgo',
      explain: 'Sin destructiveHint, los clientes no saben que deben pedir confirmación antes de usarla.',
      fix: 'Agrega destructiveHint: true para que los clientes pidan confirmación.',
    },
  },
  'unconstrained-input': {
    en: {
      title: 'Free-form sensitive parameter',
      explain: 'A path, URL, command or query that accepts anything lets an injected instruction point the tool wherever it wants.',
      fix: 'Validate on the server with an allowlist, a pattern or a length limit.',
    },
    es: {
      title: 'Parámetro sensible sin restricciones',
      explain: 'Una ruta, URL, comando o consulta que acepta cualquier valor permite que una instrucción inyectada dirija la herramienta a donde quiera.',
      fix: 'Valida en el servidor con una lista permitida, un patrón o un límite de longitud.',
    },
  },
  'exfiltration-path': {
    en: {
      title: 'Private data and an outbound channel together',
      explain: 'With both on one server, a single injected instruction can read private data and send it out.',
      fix: 'Split these tools across separate agents or servers, or require approval for every outbound call.',
    },
    es: {
      title: 'Datos privados y un canal de salida juntos',
      explain: 'Con ambos en el mismo servidor, una sola instrucción inyectada puede leer datos privados y enviarlos afuera.',
      fix: 'Separa estas herramientas en agentes o servidores distintos, o exige aprobación en cada envío externo.',
    },
  },
  'tool-output-injection': {
    en: {
      title: 'Instructions planted in tool output',
      explain: 'This tool returns content (reviews, emails, web pages) with text aimed at the AI. The agent reads it and may obey it (indirect prompt injection).',
      fix: 'Treat tool output as data, never as instructions. Mark it as untrusted, filter instruction-like text and limit what the agent can do while processing external content.',
    },
    es: {
      title: 'Instrucciones plantadas en la respuesta de una herramienta',
      explain: 'Esta herramienta devuelve contenido (reseñas, correos, páginas web) con texto dirigido a la IA. El agente lo lee y puede obedecerlo (inyección indirecta).',
      fix: 'Trata la respuesta de las herramientas como datos, nunca como instrucciones. Márcala como no confiable, filtra el texto que parezca instrucción y limita lo que el agente puede hacer mientras procesa contenido externo.',
    },
  },
  'agent-markdown-exfiltration': {
    en: {
      title: 'Data exfiltration through markdown images',
      explain: 'The agent produced an image link to an external address. When the chat renders it, the browser sends that data to the attacker.',
      fix: 'Do not render images or links from model output, or allow only your own domains.',
    },
    es: {
      title: 'Fuga de datos con imágenes en markdown',
      explain: 'El agente generó un enlace de imagen hacia una dirección externa. Cuando el chat lo muestra, el navegador le envía esos datos al atacante.',
      fix: 'No muestres imágenes ni enlaces generados por el modelo, o permite solo tus propios dominios.',
    },
  },
  'agent-system-prompt-leak': {
    en: {
      title: 'The agent reveals its system prompt',
      explain: 'Its internal instructions can be extracted, including any secret, price rule or discount code they contain.',
      fix: 'Never put secrets in the system prompt and assume it can leak. Enforce rules in code, not only in the prompt.',
    },
    es: {
      title: 'El agente revela sus instrucciones internas',
      explain: 'Se pueden extraer sus instrucciones internas, incluido cualquier secreto, regla de precios o código de descuento que contengan.',
      fix: 'Nunca pongas secretos en las instrucciones del sistema y asume que se pueden filtrar. Aplica las reglas en el código, no solo en el prompt.',
    },
  },
  agent: {
    en: {
      title: 'The agent obeys injected instructions',
      explain: 'The agent followed instructions that arrived inside the user message, an email or a document. Anyone who can put text in front of it can control what it says and does.',
      fix: 'Separate instructions from data, keep secrets out of the prompt, give the agent the least permissions possible, require human approval for sensitive actions and re-test regularly.',
    },
    es: {
      title: 'El agente obedece instrucciones inyectadas',
      explain: 'El agente siguió instrucciones que llegaron dentro del mensaje del usuario, de un correo o de un documento. Cualquiera que pueda ponerle texto enfrente puede controlar lo que dice y hace.',
      fix: 'Separa las instrucciones de los datos, no pongas secretos en el prompt, dale al agente los permisos mínimos, exige aprobación humana en acciones sensibles y vuelve a probar con regularidad.',
    },
  },
};

export function guidance(id, lang = 'en') {
  const entry = G[id] ?? (id.startsWith('agent-') ? G.agent : null);
  return entry ? entry[lang] ?? entry.en : null;
}
