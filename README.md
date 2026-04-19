# mcp-red-team

Adversarial security testing framework for MCP (Model Context Protocol) servers.

```
────────────────────────────────────────────────────────────
  mcp-red-team — MCP Adversarial Security Scanner
────────────────────────────────────────────────────────────
  Target : node server.js
  Tools  : 4 (read_file, run_shell, send_data, get_config)
  Time   : 412ms
────────────────────────────────────────────────────────────

  Security Score: 0/100  FAIL
   1 CRITICAL   3 HIGH  8 MED  0 LOW  2 INFO

   CRIT  Prompt injection pattern in tool manifest [read_file]
         Tool "read_file" description contains: IGNORE PREVIOUS INSTRUCTIONS...

   HIGH  Potential data exfiltration chain
         Server exposes both data-reading tools and network-sending tools...
```

## What it tests

### Static manifest analysis

- **Prompt injection** — tool names/descriptions containing `ignore previous instructions`, role-play directives, hidden instruction blocks, zero-width characters
- **Tool confusion** — pairs of tools with high name+description similarity (Jaro-Winkler) that an LLM might confuse, especially when one is destructive and one is read-only
- **Exfiltration chains** — tools that read sensitive data (files, env, secrets) co-existing with tools that send data externally
- **Schema gaps** — untyped parameters, undescribed parameters, empty schemas

### Dynamic behavioral tests

- **Command injection** — canary-based detection; strips reflected input to avoid false positives
- **Path traversal** — `../../etc/passwd` variants; checks for `/etc/passwd` content in response
- **Output injection** — sends LLM instruction payloads as tool inputs; checks if they're reflected unsanitized into tool output (which would inject into the LLM's context)
- **Oversized input** — 500KB string; checks for DoS/missing length validation
- **Error leakage** — all tests check errors for stack traces, absolute paths, and credential patterns (`sk-`, `AKIA`, `ghp_`, JWT tokens, etc.)
- **SQL injection** — checks for raw DB error messages indicating unsanitized queries
- **Unicode edge cases** — RTL override, BOM, null bytes, zalgo text

### LLM-as-adversary (optional)

Uses Claude Opus to simulate an LLM being manipulated by the tool manifest. Catches subtle adversarial framing, trust escalation attempts, and social engineering that regex can't.

## Install

```bash
git clone https://github.com/paramxclaudedev/mcp-red-team
cd mcp-red-team
pnpm install
pnpm build
```

Or use directly with `tsx`:

```bash
pnpm dev -- --stdio "node server.js"
```

## Usage

```bash
# Scan a stdio MCP server
node dist/index.js --stdio "python server.py"
node dist/index.js --stdio "node build/server.js"

# Scan an SSE MCP server
node dist/index.js --sse http://localhost:3000

# With Claude-powered manifest analysis
node dist/index.js --stdio "python server.py" --llm --anthropic-key sk-ant-...
# or set ANTHROPIC_API_KEY in env

# Write a markdown report
node dist/index.js --stdio "node server.js" --output report.md

# Write a JSON report
node dist/index.js --stdio "node server.js" --output report.json

# Skip dynamic behavioral tests (manifest analysis only, much faster)
node dist/index.js --stdio "node server.js" --skip-behavioral

# Adjust per-tool timeout (default 5000ms)
node dist/index.js --stdio "node server.js" --timeout 10000
```

## Exit codes

| Code | Meaning                              |
| ---- | ------------------------------------ |
| `0`  | No critical or high findings         |
| `1`  | High findings only                   |
| `2`  | Critical findings present            |
| `3`  | Scan failed (connection error, etc.) |

Use in CI: `node dist/index.js --stdio "..." && echo "safe"` or check exit code.

## Test against the vulnerable example server

```bash
node dist/index.js --stdio "node examples/vulnerable-server.mjs"
```

The example server contains intentional vulnerabilities for testing: prompt injection in tool descriptions, confusable tool pairs, command execution, output reflection, and an exfiltration chain.

## Attack categories

| ID prefix | Category                            |
| --------- | ----------------------------------- |
| `MI-`     | Manifest / prompt injection         |
| `MS-`     | Schema gap                          |
| `MC-`     | Tool confusion / exfiltration chain |
| `BC-`     | Behavioral: command injection       |
| `BP-`     | Behavioral: path traversal          |
| `BD-`     | Behavioral: DoS / oversized input   |
| `BO-`     | Behavioral: output injection        |
| `BE-`     | Behavioral: error leakage           |
| `BS-`     | Behavioral: SQL injection           |
| `LA-`     | LLM adversarial analysis            |

## Severity scoring

Score starts at 100. Deductions: Critical −25, High −10, Medium −5, Low −2. Floor 0.

## Contributing

New attack ideas, payload improvements, and MCP server adapters welcome.
