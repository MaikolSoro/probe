# Disclosure template

**Subject:** Security report for <package>: <one-line summary>

Hi <maintainer>,

I'm <name> from AVENZOQ. While researching the security of public MCP servers with our open-source scanner, Probe (https://github.com/MaikolSoro/probe), I found an issue in **<package> <version>** that I'd like to report privately before anything is published.

**Summary**
<What the issue is, in one or two sentences.>

**Where**
Tool: `<tool name>`. Field: description / input schema / output.

**Why it matters**
<The impact in the context of AI agents. For example: "An agent that loads this server reads the description as trusted instructions and may send the user's SSH key in the `notes` parameter without the user noticing.">

**Evidence**
```
<the exact text or definition, and the Probe output>
```

**How to reproduce**
1. `npx @avenzoq/probe mcp -- npx -y <package>@<version>`
2. <Anything else needed.>

**Suggested fix**
<For example: remove the instruction-like text from the description, add `destructiveHint`, or constrain the `path` parameter.>

**Disclosure timeline**
I'll keep this private for 90 days (until <date>) or until a fix is released, whichever comes first, and I'm happy to extend that if you need more time. When we publish, we'll credit your fix unless you prefer otherwise.

Thanks for your work on <package>.
<name> · info@avenzoq.com
