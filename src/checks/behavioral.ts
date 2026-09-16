import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { Finding, ToolDef } from "../types.js";
import {
  commandInjectionPayloads,
  PATH_TRAVERSAL_PAYLOADS,
  PASSWD_CONTENT_SIGNATURES,
  SQL_INJECTION_PAYLOADS,
  UNICODE_PAYLOADS,
  OUTPUT_INJECTION_PAYLOADS,
  OVERSIZED_STRING,
  CREDENTIAL_PATTERNS,
  STACK_TRACE_PATTERNS,
} from "./payloads.js";

let findingCounter = 0;
const id = (prefix: string) =>
  `${prefix}-${String(++findingCounter).padStart(3, "0")}`;

export async function checkBehavioral(
  client: Client,
  tools: ToolDef[],
  timeout: number,
  verbose: boolean,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const tool of tools) {
    const stringParams = getStringParams(tool);
    if (stringParams.length === 0) continue;

    if (verbose)
      process.stderr.write(
        `  Testing ${tool.name} (${stringParams.length} string params)\n`,
      );

    findings.push(
      ...(await testCommandInjection(client, tool, stringParams, timeout)),
    );
    findings.push(
      ...(await testPathTraversal(client, tool, stringParams, timeout)),
    );
    findings.push(
      ...(await testOversizedInput(client, tool, stringParams, timeout)),
    );
    findings.push(
      ...(await testOutputInjection(client, tool, stringParams, timeout)),
    );
    findings.push(
      ...(await testUnicodeEdgeCases(client, tool, stringParams, timeout)),
    );
    findings.push(
      ...(await testSQLInjection(client, tool, stringParams, timeout)),
    );
  }

  return findings;
}

function getStringParams(tool: ToolDef): string[] {
  const props = tool.inputSchema?.properties ?? {};
  return Object.entries(props)
    .filter(([, schema]) => !schema.type || schema.type === "string")
    .map(([name]) => name);
}

async function callTool(
  client: Client,
  toolName: string,
  args: Record<string, unknown>,
  timeout: number,
): Promise<{ content: string; isError: boolean; timedOut: boolean }> {
  try {
    const result = await Promise.race([
      client.callTool({ name: toolName, arguments: args }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("TIMEOUT")), timeout),
      ),
    ]);

    const content = JSON.stringify(
      (result as { content?: unknown }).content ?? result,
    );
    return {
      content,
      isError: (result as { isError?: boolean }).isError === true,
      timedOut: false,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg === "TIMEOUT")
      return { content: "TIMEOUT", isError: true, timedOut: true };
    return { content: msg, isError: true, timedOut: false };
  }
}

export function stripReflections(content: string, payload: string): string {
  const escaped = JSON.stringify(payload).slice(1, -1);
  return content
    .replaceAll(payload, "[REDACTED]")
    .replaceAll(escaped, "[REDACTED]");
}

function buildArgs(
  tool: ToolDef,
  param: string,
  value: string,
): Record<string, unknown> {
  const props = tool.inputSchema?.properties ?? {};
  const args: Record<string, unknown> = {};
  for (const [name, schema] of Object.entries(props)) {
    if (name === param) {
      args[name] = value;
    } else {
      args[name] = defaultForType(schema.type as string | undefined);
    }
  }
  return args;
}

function defaultForType(type?: string): unknown {
  switch (type) {
    case "number":
    case "integer":
      return 0;
    case "boolean":
      return false;
    case "array":
      return [];
    case "object":
      return {};
    default:
      return "test";
  }
}

async function testCommandInjection(
  client: Client,
  tool: ToolDef,
  params: string[],
  timeout: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const canary =
    "PWNED_RT_" + Math.random().toString(36).slice(2, 8).toUpperCase();

  for (const param of params.slice(0, 2)) {
    for (const payload of commandInjectionPayloads(canary)) {
      const args = buildArgs(tool, param, payload);
      const result = await callTool(client, tool.name, args, timeout);

      // Strip every reflection of the payload before looking for the canary, so a
      // server that merely echoes its input is not reported as executing it.
      // replaceAll (not replace) because one response can reflect the payload more
      // than once — error message plus resolved path, say. The content has been
      // JSON-stringified, so a payload containing a newline comes back escaped;
      // strip that form too or the escaped reflection reads as a real execution.
      const realExecution = stripReflections(
        result.content,
        payload,
      ).includes(canary);

      if (realExecution) {
        findings.push({
          id: id("BC"),
          severity: "critical",
          category: "behavioral",
          title: `Command injection confirmed in tool "${tool.name}"`,
          description: `Parameter "${param}" executed shell payload ${JSON.stringify(payload)}. Canary "${canary}" appeared in response outside the reflected input.`,
          evidence: result.content.slice(0, 500),
          tool: tool.name,
          remediation:
            "Never pass user input to shell commands. Use parameterized APIs. Sandbox tool execution.",
        });
        return findings;
      }

      findings.push(
        ...scrapeErrorLeakage(
          tool.name,
          param,
          result.content,
          "command injection",
        ),
      );
    }
  }

  return findings;
}

async function testPathTraversal(
  client: Client,
  tool: ToolDef,
  params: string[],
  timeout: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const param of params.slice(0, 2)) {
    for (const payload of PATH_TRAVERSAL_PAYLOADS) {
      const args = buildArgs(tool, param, payload);
      const result = await callTool(client, tool.name, args, timeout);

      if (PASSWD_CONTENT_SIGNATURES.some((sig) => sig.test(result.content))) {
        findings.push({
          id: id("BP"),
          severity: "critical",
          category: "behavioral",
          title: `Path traversal confirmed in tool "${tool.name}"`,
          description: `Parameter "${param}" read /etc/passwd or similar via path traversal.`,
          evidence: result.content.slice(0, 500),
          tool: tool.name,
          remediation:
            "Canonicalize paths and enforce a chroot/base-directory whitelist.",
        });
        return findings;
      }

      findings.push(
        ...scrapeErrorLeakage(
          tool.name,
          param,
          result.content,
          "path traversal",
        ),
      );
    }
  }

  return findings;
}

async function testOversizedInput(
  client: Client,
  tool: ToolDef,
  params: string[],
  timeout: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const param = params[0];

  const args = buildArgs(tool, param, OVERSIZED_STRING);
  const result = await callTool(client, tool.name, args, timeout);

  if (result.timedOut) {
    findings.push({
      id: id("BD"),
      severity: "high",
      category: "behavioral",
      title: `Potential DoS via oversized input in tool "${tool.name}"`,
      description: `Tool did not respond within ${timeout}ms when parameter "${param}" received a 500KB string.`,
      tool: tool.name,
      remediation:
        "Enforce maximum input length at the tool boundary before any processing.",
    });
  } else if (!result.isError) {
    findings.push({
      id: id("BD"),
      severity: "medium",
      category: "behavioral",
      title: `Tool "${tool.name}" silently accepts 500KB input`,
      description: `Parameter "${param}" accepted a 500,000-character string without error. No length validation detected.`,
      tool: tool.name,
      remediation:
        "Add explicit maximum length validation and return a clear error for oversized inputs.",
    });
  }

  return findings;
}

async function testOutputInjection(
  client: Client,
  tool: ToolDef,
  params: string[],
  timeout: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const param of params.slice(0, 1)) {
    for (const payload of OUTPUT_INJECTION_PAYLOADS.slice(0, 2)) {
      const args = buildArgs(tool, param, payload);
      const result = await callTool(client, tool.name, args, timeout);

      const echoed = OUTPUT_INJECTION_PAYLOADS.some((p) =>
        result.content.includes(p.slice(0, 30)),
      );
      if (echoed && !result.isError) {
        findings.push({
          id: id("BO"),
          severity: "high",
          category: "output-injection",
          title: `Tool "${tool.name}" echoes injected content into output`,
          description: `Parameter "${param}" input was reflected into the tool response without sanitization. An adversarial caller could inject instructions into the LLM context via tool responses.`,
          evidence: result.content.slice(0, 300),
          tool: tool.name,
          remediation:
            "Sanitize or reject inputs containing LLM instruction patterns before reflecting them in output.",
        });
      }
    }
  }

  return findings;
}

async function testUnicodeEdgeCases(
  client: Client,
  tool: ToolDef,
  params: string[],
  timeout: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const param of params.slice(0, 1)) {
    for (const payload of UNICODE_PAYLOADS) {
      const args = buildArgs(tool, param, payload);
      const result = await callTool(client, tool.name, args, timeout);
      findings.push(
        ...scrapeErrorLeakage(
          tool.name,
          param,
          result.content,
          `unicode (${JSON.stringify(payload)})`,
        ),
      );
    }
  }

  return findings;
}

async function testSQLInjection(
  client: Client,
  tool: ToolDef,
  params: string[],
  timeout: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];

  for (const param of params.slice(0, 2)) {
    for (const payload of SQL_INJECTION_PAYLOADS.slice(0, 2)) {
      const args = buildArgs(tool, param, payload);
      const result = await callTool(client, tool.name, args, timeout);

      const sqlErrorPatterns = [
        /sql syntax/i,
        /sqlite3\.OperationalError/i,
        /PG::SyntaxError/i,
        /You have an error in your SQL syntax/i,
        /unclosed quotation mark/i,
        /ORA-\d{5}/,
      ];

      for (const pattern of sqlErrorPatterns) {
        if (pattern.test(result.content)) {
          findings.push({
            id: id("BS"),
            severity: "high",
            category: "behavioral",
            title: `SQL error exposed in tool "${tool.name}"`,
            description: `Parameter "${param}" triggered a raw SQL error message, indicating unsanitized input reaches a database query.`,
            evidence: result.content.slice(0, 400),
            tool: tool.name,
            remediation:
              "Use parameterized queries. Never interpolate user input into SQL strings. Suppress raw DB errors.",
          });
        }
      }

      findings.push(
        ...scrapeErrorLeakage(
          tool.name,
          param,
          result.content,
          "SQL injection",
        ),
      );
    }
  }

  return findings;
}

function scrapeErrorLeakage(
  toolName: string,
  param: string,
  content: string,
  testType: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const pattern of CREDENTIAL_PATTERNS) {
    const match = pattern.exec(content);
    if (match) {
      findings.push({
        id: id("BE"),
        severity: "critical",
        category: "error-leakage",
        title: `Credential exposed in tool "${toolName}" error response`,
        description: `During ${testType} test on parameter "${param}", the tool response contained what appears to be a credential.`,
        evidence: content.slice(
          Math.max(0, match.index - 20),
          match.index + 60,
        ),
        tool: toolName,
        remediation:
          "Scrub all secret patterns from error messages. Use structured error codes instead of raw exceptions.",
      });
    }
  }

  for (const pattern of STACK_TRACE_PATTERNS) {
    if (pattern.test(content)) {
      findings.push({
        id: id("BE"),
        severity: "medium",
        category: "error-leakage",
        title: `Stack trace / internal path leaked in tool "${toolName}"`,
        description: `During ${testType} test on parameter "${param}", the error response contained internal file paths or stack traces.`,
        evidence: content.slice(0, 300),
        tool: toolName,
        remediation:
          "Catch exceptions at the tool boundary. Return generic error messages to callers.",
      });
      break;
    }
  }

  return findings;
}
