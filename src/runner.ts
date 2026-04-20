import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type {
  ScanOptions,
  ScanResult,
  ScanSummary,
  ToolDef,
  Finding,
} from "./types.js";
import { StreamEmitter } from "./stream/emitter.js";
import { newTree } from "./tree/tree.js";
import { planAndExecute } from "./tree/planner.js";
import { saveCase, loadCase, defaultCasePath } from "./tree/case.js";
import { replayNode, ForkOptions } from "./tree/replay.js";

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const start = Date.now();
  const emitter = new StreamEmitter(options.stream);

  const client = new Client(
    { name: "mcp-red-team", version: "0.1.0" },
    { capabilities: {} },
  );

  const transport =
    options.transport === "sse" && options.sseUrl
      ? new SSEClientTransport(new URL(options.sseUrl))
      : new StdioClientTransport({
          command: options.command,
          args: options.args,
        });

  await client.connect(transport);

  const toolsResponse = await client.listTools();
  const tools: ToolDef[] = toolsResponse.tools.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema: t.inputSchema as ToolDef["inputSchema"],
  }));

  const target =
    options.transport === "sse"
      ? options.sseUrl!
      : `${options.command} ${options.args.join(" ")}`;

  emitter.emit({ kind: "scan-start", message: target });

  let findings: Finding[] = [];
  let tree = newTree(target);

  if (options.replayCase) {
    const caseFile = loadCase(options.replayCase);
    if (options.forkNode) {
      const fork: ForkOptions = {
        nodeId: options.forkNode,
        mutation: (options.forkVariant as ForkOptions["mutation"]) ?? "raw",
      };
      const res = await replayNode(caseFile, client, options, emitter, fork);
      tree = res.tree;
      findings = res.findings;
    } else {
      // straight replay — re-execute every attempt node in-order against the live target
      tree = newTree(target);
      const attempts = Object.values(caseFile.tree.nodes).filter(
        (n) => n.kind === "attempt" && n.tool && n.input,
      );
      for (const a of attempts) {
        const res = await replayNode(caseFile, client, options, emitter, {
          nodeId: a.id,
          mutation: "raw",
        });
        tree = res.tree;
      }
    }
  } else {
    findings = await planAndExecute(tree, client, tools, options, emitter);
  }

  await client.close();

  const summary = buildSummary(findings);
  emitter.emit({
    kind: "scan-end",
    message: `score=${summary.score} crit=${summary.critical} high=${summary.high}`,
  });

  const result: ScanResult = {
    target,
    timestamp: new Date().toISOString(),
    durationMs: Date.now() - start,
    tools,
    findings,
    summary,
    tree,
  };

  const casePath = options.caseFile ?? defaultCasePath(tree.caseId);
  saveCase(casePath, {
    version: "1",
    caseId: tree.caseId,
    target,
    createdAt: tree.createdAt,
    tree,
    events: emitter.all(),
    findings,
    summary,
  });

  return result;
}

function buildSummary(findings: Finding[]): ScanSummary {
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
