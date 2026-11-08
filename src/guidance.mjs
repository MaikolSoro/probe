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
  'skill-hide-from-user': {
    en: {
      title: 'Instruction file tells the agent to hide something',
      explain: 'A skill or instruction file asks the agent to keep something from the user. Legitimate skills have no reason to do that.',
      fix: 'Do not install it until you understand why. Remove the text or ask the author.',
    },
    es: {
      title: 'Un archivo de instrucciones le pide al agente ocultar algo',
      explain: 'Una skill o archivo de instrucciones le pide al agente que le oculte algo al usuario. Una skill legítima no tiene por qué hacerlo.',
      fix: 'No la instales hasta entender por qué. Elimina ese texto o consulta al autor.',
    },
  },
  'skill-exfiltration': {
    en: {
      title: 'Instruction file asks the agent to send secrets',
      explain: 'The text tells the agent to send keys, tokens or credential files somewhere. With your permissions, the agent can do it.',
      fix: 'Do not install it. Report it to the author or the marketplace.',
    },
    es: {
      title: 'Un archivo de instrucciones pide enviar secretos',
      explain: 'El texto le pide al agente que envíe llaves, tokens o archivos de credenciales a algún lugar. Con tus permisos, el agente puede hacerlo.',
      fix: 'No la instales. Repórtala al autor o al marketplace.',
    },
  },
  'skill-sensitive-write': {
    en: {
      title: 'Writes to shell profiles, SSH keys or credentials',
      explain: 'Changing these files can give someone persistent access or run code every time you open a terminal.',
      fix: 'Read the exact command and only run it if you understand and accept the change.',
    },
    es: {
      title: 'Escribe en perfiles de la terminal, llaves SSH o credenciales',
      explain: 'Cambiar estos archivos puede dar acceso permanente a alguien o ejecutar código cada vez que abres una terminal.',
      fix: 'Lee el comando exacto y ejecútalo solo si entiendes y aceptas el cambio.',
    },
  },
  'skill-pipe-to-shell': {
    en: {
      title: 'Downloads and runs a remote script',
      explain: 'Piping a download straight into a shell runs whatever the server sends that day, without review.',
      fix: 'Download the script, read it, pin a version or checksum, then run it.',
    },
    es: {
      title: 'Descarga y ejecuta un script remoto',
      explain: 'Enviar una descarga directo a la terminal ejecuta lo que el servidor mande ese día, sin revisión.',
      fix: 'Descarga el script, léelo, fija una versión o checksum y después ejecútalo.',
    },
  },
  'skill-encoded-blob': {
    en: {
      title: 'Encoded content inside instructions',
      explain: 'Long encoded strings can hide instructions that reviewers cannot read.',
      fix: 'Decode it and check what it says before installing.',
    },
    es: {
      title: 'Contenido codificado dentro de las instrucciones',
      explain: 'Las cadenas codificadas largas pueden esconder instrucciones que nadie puede leer a simple vista.',
      fix: 'Decodifícala y revisa qué dice antes de instalar.',
    },
  },
  'skill-hook-command': {
    en: {
      title: 'Hook runs commands automatically',
      explain: 'Hooks run on agent events (every prompt, every tool call) without asking.',
      fix: 'Make sure every hook command is expected and comes from a source you trust.',
    },
    es: {
      title: 'Un hook ejecuta comandos automáticamente',
      explain: 'Los hooks se ejecutan en eventos del agente (cada mensaje, cada herramienta) sin preguntar.',
      fix: 'Verifica que cada comando de hook sea esperado y venga de una fuente de confianza.',
    },
  },
  'skill-broad-tools': {
    en: {
      title: 'Skill pre-approves unrestricted Bash',
      explain: 'The agent can run any shell command while this skill is active, without asking.',
      fix: 'Restrict allowed-tools to specific commands, for example Bash(git status:*).',
    },
    es: {
      title: 'La skill aprueba de antemano cualquier comando Bash',
      explain: 'Mientras la skill está activa, el agente puede ejecutar cualquier comando sin preguntar.',
      fix: 'Limita allowed-tools a comandos específicos, por ejemplo Bash(git status:*).',
    },
  },
  'skill-mcp-install': {
    en: {
      title: 'Adds an MCP server',
      explain: 'The package installs or configures an MCP server, which gives the agent new tools.',
      fix: 'Scan that server with probe mcp before enabling it.',
    },
    es: {
      title: 'Agrega un servidor MCP',
      explain: 'El paquete instala o configura un servidor MCP, que le da herramientas nuevas al agente.',
      fix: 'Escanea ese servidor con probe mcp antes de activarlo.',
    },
  },
  'config-plaintext-secret': {
    en: {
      title: 'Secret in plain text in the MCP config',
      explain: 'Any program or tool that can read this file gets the credential.',
      fix: 'Rotate the credential and load it from the system keychain or an environment variable.',
    },
    es: {
      title: 'Secreto en texto plano en la configuración MCP',
      explain: 'Cualquier programa o herramienta que lea este archivo obtiene la credencial.',
      fix: 'Cambia la credencial y cárgala desde el llavero del sistema o una variable de entorno.',
    },
  },
  'config-unpinned-package': {
    en: {
      title: 'MCP server without a pinned version',
      explain: 'Each start may run a newer, or hijacked, release without you noticing.',
      fix: 'Pin an exact version (package@1.2.3) and re-scan after updating.',
    },
    es: {
      title: 'Servidor MCP sin versión fija',
      explain: 'Cada inicio puede ejecutar una versión más nueva, o secuestrada, sin que lo notes.',
      fix: 'Fija una versión exacta (paquete@1.2.3) y vuelve a escanear al actualizar.',
    },
  },
  'config-insecure-transport': {
    en: {
      title: 'Remote MCP server over plain HTTP',
      explain: 'Tool results and tokens travel unencrypted.',
      fix: 'Use an HTTPS endpoint.',
    },
    es: {
      title: 'Servidor MCP remoto sin cifrar (HTTP)',
      explain: 'Los resultados de las herramientas y los tokens viajan sin cifrar.',
      fix: 'Usa un endpoint HTTPS.',
    },
  },
  'llm-tool-poisoning': {
    en: { title: 'Hidden instructions in a tool (found by the LLM judge)', explain: 'The pattern rules did not match, but the AI reviewer found instructions aimed at the agent in this tool description, usually reworded to avoid detection.', fix: 'Read the description and remove any instruction to the agent. Do not use the server until it is fixed.' },
    es: { title: 'Instrucciones escondidas en una herramienta (detectadas por el juez IA)', explain: 'Las reglas de patrones no lo detectaron, pero el revisor con IA encontró instrucciones dirigidas al agente en esta descripción, normalmente redactadas para evadir la detección.', fix: 'Lee la descripción y elimina toda instrucción al agente. No uses el servidor hasta corregirlo.' },
  },
  'llm-output-injection': {
    en: { title: 'Instructions planted in tool output (found by the LLM judge)', explain: 'The AI reviewer found text aimed at the agent in what this tool returns.', fix: 'Treat tool output as data, filter instruction-like content and limit the agent while it processes external content.' },
    es: { title: 'Instrucciones plantadas en la respuesta de una herramienta (juez IA)', explain: 'El revisor con IA encontró texto dirigido al agente en lo que devuelve esta herramienta.', fix: 'Trata la respuesta como datos, filtra el contenido que parezca instrucción y limita al agente mientras procesa contenido externo.' },
  },
  'llm-skill-injection': {
    en: { title: 'Instructions aimed at the agent in a skill (LLM judge)', explain: 'The AI reviewer found text in this file that tries to steer the agent in ways the user would not expect.', fix: 'Do not install it until the text is explained or removed.' },
    es: { title: 'Instrucciones dirigidas al agente en una skill (juez IA)', explain: 'El revisor con IA encontró texto en este archivo que intenta dirigir al agente de formas que el usuario no esperaría.', fix: 'No la instales hasta que ese texto se explique o se elimine.' },
  },
  'tool-definition-changed': {
    en: { title: 'Tool changed after it was approved (rug pull)', explain: 'The tool definition no longer matches the pinned version. Malicious updates usually arrive this way, after users already trust the server.', fix: 'Compare the old and new definitions. If the change is expected, accept it with --update-pins; if not, remove the server.' },
    es: { title: 'La herramienta cambió después de aprobada (rug pull)', explain: 'La definición ya no coincide con la versión fijada. Las actualizaciones maliciosas suelen llegar así, cuando el servidor ya tiene la confianza de los usuarios.', fix: 'Compara la definición anterior con la nueva. Si el cambio es esperado, acéptalo con --update-pins; si no, quita el servidor.' },
  },
  'tool-added': {
    en: { title: 'New tool since approval', explain: 'The server gained a tool that was not reviewed.', fix: 'Review it, then accept with --update-pins.' },
    es: { title: 'Herramienta nueva desde la aprobación', explain: 'El servidor agregó una herramienta que no fue revisada.', fix: 'Revísala y acéptala con --update-pins.' },
  },
  'tool-removed': {
    en: { title: 'Tool removed since approval', explain: 'A previously approved tool is gone. Usually harmless.', fix: 'Confirm the server is the one you expect.' },
    es: { title: 'Herramienta eliminada desde la aprobación', explain: 'Una herramienta aprobada ya no está. Normalmente no es un problema.', fix: 'Confirma que el servidor sea el que esperas.' },
  },
  'agent-tool': {
    en: { title: 'Injected text made the agent use a tool', explain: 'Instructions hidden in content the agent was processing made it call a tool (send email, read files, move money) for the attacker. In production, that action would really happen.', fix: 'Require human approval for sensitive tools, give the agent only the tools it needs, and never let content it reads decide which tools to call.' },
    es: { title: 'Un texto inyectado hizo que el agente usara una herramienta', explain: 'Instrucciones escondidas en el contenido que procesaba el agente lo llevaron a usar una herramienta (enviar correo, leer archivos, mover dinero) a favor del atacante. En producción, esa acción ocurriría de verdad.', fix: 'Exige aprobación humana para herramientas sensibles, dale al agente solo las herramientas que necesita y nunca dejes que el contenido que lee decida qué herramientas usar.' },
  },
  'tool-steering': {
    en: { title: "Tool description steers the agent's choices", explain: 'The description tells the agent which tool to prefer or what to call next ("always use this tool", "call this immediately after"). It is usually a product decision, not an attack, but it is the same mechanism an attacker would use.', fix: 'Keep descriptions factual: say what the tool does, not what the agent must do. Decide tool priority in your agent or system prompt, not in third-party descriptions.' },
    es: { title: 'La descripción de la herramienta dirige las decisiones del agente', explain: 'La descripción le dice al agente qué herramienta preferir o qué llamar después ("siempre usa esta herramienta", "llama a esto inmediatamente después"). Suele ser una decisión del producto, no un ataque, pero es el mismo mecanismo que usaría un atacante.', fix: 'Mantén las descripciones objetivas: que digan qué hace la herramienta, no qué debe hacer el agente. Define la prioridad de herramientas en tu agente o en tu prompt de sistema, no en descripciones de terceros.' },
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
  const entry = G[id] ?? (id.startsWith('agent-tool-') ? G['agent-tool'] : id.startsWith('agent-') ? G.agent : null);
  return entry ? entry[lang] ?? entry.en : null;
}
