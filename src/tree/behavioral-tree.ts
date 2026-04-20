import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type {
  AttackTree,
  Category,
  Finding,
  ScanOptions,
  ToolDef,
} from "../types.js";
import { StreamEmitter } from "../stream/emitter.js";
import { addNode, finishNode } from "./tree.js";
import {
  COMMAND_INJECTION_PAYLOADS,
  PATH_TRAVERSAL_PAYLOADS,
  OUTPUT_INJECTION_PAYLOADS,
  UNICODE_PAYLOADS,
  SQL_INJECTION_PAYLOADS,
  OVERSIZED_STRING,
  CREDENTIAL_PATTERNS,
  STACK_TRACE_PATTERNS,
} from "../checks/payloads.js";

let counter = 0;
const id = (p: string) => `${p}-${String(++counter).padStart(3, "0")}`;

interface Variant {
  id: string;
  label: string;
  payload: string;
  subCategory: "command" | "path" | "oversized" | "output" | "unicode" | "sql";
}

function variantsFor(cat: Category): Variant[] {
  if (cat === "behavioral") {
    return [
      ...COMMAND_INJECTION_PAYLOADS.slice(0, 3).map((p, i) => ({
        id: `cmd-${i}`,
        label: `cmd-injection: ${p}`,
        payload: p,
        subCategory: "command" as const,
      })),
      ...PATH_TRAVERSAL_PAYLOADS.slice(0, 3).map((p, i) => ({
        id: `path-${i}`,
        label: `path-traversal: ${p}`,
        payload: p,
        subCategory: "path" as const,
      })),
      {
        id: "oversized-0",
        label: "oversized-input: 500KB",
        payload: OVERSIZED_STRING,
        subCategory: "oversized" as const,
      },
      ...SQL_INJECTION_PAYLOADS.slice(0, 2).map((p, i) => ({
        id: `sql-${i}`,
        label: `sql-injection: ${p}`,
        payload: p,
        subCategory: "sql" as const,
      })),
    ];
  }
  if (cat === "output-injection") {
    return OUTPUT_INJECTION_PAYLOADS.slice(0, 2).map((p, i) => ({
      id: `out-${i}`,
      label: `output-injection: ${p.slice(0, 40)}`,
      payload: p,
      subCategory: "output" as const,
    }));
  }
  if (cat === "error-leakage") {
    return UNICODE_PAYLOADS.map((p, i) => ({
      id: `uni-${i}`,
      label: `unicode: ${JSON.stringify(p).slice(0, 24)}`,
      payload: p,
      subCategory: "unicode" as const,
    }));
  }
  return [];
}

export async function runBehavioralTree(
  category: Category,
  parentId: string,
  tree: AttackTree,
  client: Client,
  tools: ToolDef[],
  options: ScanOptions,
  emitter: StreamEmitter,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const variants = variantsFor(category);

  for (const tool of tools) {
    const stringParams = getStringParams(tool);
    if (stringParams.length === 0) continue;

    const toolNode = addNode(tree, parentId, {
      kind: "variant",
      label: `tool: ${tool.name}`,
      category,
      tool: tool.name,
      status: "running",
    });

    let toolHit = false;

    for (let vi = 0; vi < variants.length; vi++) {
      const v = variants[vi];
      if (toolHit && options.stopOnHit) break;

      const param = stringParams[0];
      const args = buildArgs(tool, param, v.payload);
      const started = Date.now();

      const attemptNode = addNode(tree, toolNode.id, {
        kind: "attempt",
        label: v.label,
        category,
        tool: tool.name,
        payloadLabel: v.id,
        payload: v.payload,
        input: args,
        status: "running",
      });

      const result = await callTool(client, tool.name, args, options.timeout);
      const latency = Date.now() - started;

      const { finding, outcome } = evaluate(
        category,
        v,
        tool,
        param,
        result,
        options.timeout,
      );

      finishNode(tree, attemptNode.id, {
        status:
          outcome === "fail" ? "hit" : outcome === "error" ? "error" : "miss",
        output: result.content.slice(0, 1000),
        verdict: finding ? finding.title : "no issue detected",
        findingIds: finding ? [finding.id] : [],
      });

      emitter.emit({
        kind: "attempt",
        nodeId: attemptNode.id,
        parentId: toolNode.id,
        category,
        tool: tool.name,
        attemptNumber: vi + 1,
        totalAttempts: variants.length,
        payloadLabel: v.label,
        outcome,
        latencyMs: latency,
      });

      if (finding) {
        findings.push(finding);
        emitter.emit({
          kind: "finding",
          nodeId: attemptNode.id,
          category,
          tool: tool.name,
          severity: finding.severity,
          findingId: finding.id,
          message: finding.title,
        });
        toolHit = true;
      }
    }

    finishNode(tree, toolNode.id, {
      status: toolHit ? "hit" : "miss",
    });
  }

  return findings;
}

function getStringParams(tool: ToolDef): string[] {
  const props = tool.inputSchema?.properties ?? {};
  return Object.entries(props)
    .filter(([, schema]) => !schema.type || schema.type === "string")
    .map(([name]) => name);
}

function buildArgs(
  tool: ToolDef,
  param: string,
  value: string,
): Record<string, unknown> {
  const props = tool.inputSchema?.properties ?? {};
  const args: Record<string, unknown> = {};
  for (const [name, schema] of Object.entries(props)) {
    if (name === param) args[name] = value;
    else args[name] = defaultForType(schema.type as string | undefined);
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

function evaluate(
  category: Category,
  v: Variant,
  tool: ToolDef,
  param: string,
  result: { content: string; isError: boolean; timedOut: boolean },
  timeout: number,
): { finding?: Finding; outcome: "pass" | "fail" | "error" | "skip" } {
  if (v.subCategory === "command") {
    const canary = result.content.match(/PWNED_RT_[A-Z0-9]{6}/);
    if (canary) {
      return {
        outcome: "fail",
        finding: {
          id: id("BC"),
          severity: "critical",
          category: "behavioral",
          title: `Command injection confirmed in tool "${tool.name}"`,
          description: `Parameter "${param}" executed shell payload.`,
          evidence: result.content.slice(0, 500),
          tool: tool.name,
          remediation:
            "Never pass user input to shell commands. Use parameterized APIs. Sandbox tool execution.",
        },
      };
    }
    const leak = leakage(tool.name, param, result.content, "command injection");
    if (leak) return { outcome: "fail", finding: leak };
    return { outcome: result.isError ? "error" : "pass" };
  }

  if (v.subCategory === "path") {
    if (
      /root:x:0:0/.test(result.content) ||
      /\/bin\/bash/.test(result.content)
    ) {
      return {
        outcome: "fail",
        finding: {
          id: id("BP"),
          severity: "critical",
          category: "behavioral",
          title: `Path traversal confirmed in tool "${tool.name}"`,
          description: `Parameter "${param}" read /etc/passwd via path traversal.`,
          evidence: result.content.slice(0, 500),
          tool: tool.name,
          remediation:
            "Canonicalize paths and enforce a chroot/base-directory whitelist.",
        },
      };
    }
    const leak = leakage(tool.name, param, result.content, "path traversal");
    if (leak) return { outcome: "fail", finding: leak };
    return { outcome: result.isError ? "error" : "pass" };
  }

  if (v.subCategory === "oversized") {
    if (result.timedOut) {
      return {
        outcome: "fail",
        finding: {
          id: id("BD"),
          severity: "high",
          category: "behavioral",
          title: `Potential DoS via oversized input in tool "${tool.name}"`,
          description: `Tool did not respond within ${timeout}ms when parameter "${param}" received a 500KB string.`,
          tool: tool.name,
          remediation:
            "Enforce maximum input length at the tool boundary before any processing.",
        },
      };
    }
    if (!result.isError) {
      return {
        outcome: "fail",
        finding: {
          id: id("BD"),
          severity: "medium",
          category: "behavioral",
          title: `Tool "${tool.name}" silently accepts 500KB input`,
          description: `Parameter "${param}" accepted a 500,000-character string without error.`,
          tool: tool.name,
          remediation:
            "Add explicit maximum length validation and return a clear error for oversized inputs.",
        },
      };
    }
    return { outcome: "pass" };
  }

  if (v.subCategory === "output") {
    const echoed = OUTPUT_INJECTION_PAYLOADS.some((p) =>
      result.content.includes(p.slice(0, 30)),
    );
    if (echoed && !result.isError) {
      return {
        outcome: "fail",
        finding: {
          id: id("BO"),
          severity: "high",
          category: "output-injection",
          title: `Tool "${tool.name}" echoes injected content into output`,
          description: `Parameter "${param}" input was reflected into the tool response without sanitization.`,
          evidence: result.content.slice(0, 300),
          tool: tool.name,
          remediation:
            "Sanitize or reject inputs containing LLM instruction patterns before reflecting them in output.",
        },
      };
    }
    return { outcome: result.isError ? "error" : "pass" };
  }

  if (v.subCategory === "unicode") {
    const leak = leakage(tool.name, param, result.content, "unicode");
    if (leak) return { outcome: "fail", finding: leak };
    return { outcome: "pass" };
  }

  if (v.subCategory === "sql") {
    const sqlErr =
      /sql syntax|sqlite3\.OperationalError|PG::SyntaxError|unclosed quotation mark|ORA-\d{5}/i.test(
        result.content,
      );
    if (sqlErr) {
      return {
        outcome: "fail",
        finding: {
          id: id("BS"),
          severity: "high",
          category: "behavioral",
          title: `SQL error exposed in tool "${tool.name}"`,
          description: `Parameter "${param}" triggered a raw SQL error message.`,
          evidence: result.content.slice(0, 400),
          tool: tool.name,
          remediation:
            "Use parameterized queries. Never interpolate user input into SQL strings. Suppress raw DB errors.",
        },
      };
    }
    const leak = leakage(tool.name, param, result.content, "SQL injection");
    if (leak) return { outcome: "fail", finding: leak };
    return { outcome: "pass" };
  }

  return { outcome: "pass" };
}

function leakage(
  toolName: string,
  param: string,
  content: string,
  testType: string,
): Finding | undefined {
  for (const pattern of CREDENTIAL_PATTERNS) {
    const match = pattern.exec(content);
    if (match) {
      return {
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
      };
    }
  }
  for (const pattern of STACK_TRACE_PATTERNS) {
    if (pattern.test(content)) {
      return {
        id: id("BE"),
        severity: "medium",
        category: "error-leakage",
        title: `Stack trace / internal path leaked in tool "${toolName}"`,
        description: `During ${testType} test on parameter "${param}", the error response contained internal file paths or stack traces.`,
        evidence: content.slice(0, 300),
        tool: toolName,
        remediation:
          "Catch exceptions at the tool boundary. Return generic error messages to callers.",
      };
    }
  }
  return undefined;
}
