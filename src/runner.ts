import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { ScanOptions, ScanResult, ScanSummary, ToolDef } from "./types.js";
import { checkManifest, checkBehavioral, checkLLM } from "./checks/index.js";

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const start = Date.now();

  const client = new Client(
    { name: "mcp-red-team", version: "0.1.0" },
    { capabilities: {} },
  );

  let transport;
  if (options.transport === "sse" && options.sseUrl) {
    transport = new SSEClientTransport(new URL(options.sseUrl));
  } else {
    transport = new StdioClientTransport({
      command: options.command,
      args: options.args,
    });
  }

  await client.connect(transport);

  const toolsResponse = await client.listTools();
  const tools: ToolDef[] = toolsResponse.tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema as ToolDef["inputSchema"],
  }));

  const findings = checkManifest(tools);

  if (!options.skipBehavioral) {
    const behavioralFindings = await checkBehavioral(
      client,
      tools,
      options.timeout,
      options.verbose,
    );
    findings.push(...behavioralFindings);
  }

  if (options.llmAnalysis && options.anthropicKey) {
    const llmFindings = await checkLLM(tools, options.anthropicKey);
    findings.push(...llmFindings);
  }

  await client.close();

  const summary = buildSummary(findings);
  const target =
    options.transport === "sse"
      ? options.sseUrl!
      : `${options.command} ${options.args.join(" ")}`;

  return {
    target,
    timestamp: new Date().toISOString(),
    durationMs: Date.now() - start,
    tools,
    findings,
    summary,
  };
}

function buildSummary(findings: ReturnType<typeof checkManifest>): ScanSummary {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;

  const deductions =
    counts.critical * 25 +
    counts.high * 10 +
    counts.medium * 5 +
    counts.low * 2;
  const score = Math.max(0, 100 - deductions);

  return { ...counts, score };
}
