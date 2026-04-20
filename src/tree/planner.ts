import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type {
  AttackTree,
  Category,
  Finding,
  ScanOptions,
  ToolDef,
} from "../types.js";
import { StreamEmitter } from "../stream/emitter.js";
import { addNode, categoriesForTools, finishNode } from "./tree.js";
import { checkManifest } from "../checks/manifest.js";
import { checkLLM } from "../checks/llm.js";
import { runBehavioralTree } from "./behavioral-tree.js";

export async function planAndExecute(
  tree: AttackTree,
  client: Client,
  tools: ToolDef[],
  options: ScanOptions,
  emitter: StreamEmitter,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const rootId = tree.rootId;

  // probe phase
  const probeId = addNode(tree, rootId, {
    kind: "probe",
    label: "probe surface",
    status: "running",
  }).id;
  emitter.emit({
    kind: "probe",
    nodeId: probeId,
    totalAttempts: tools.length,
    message: `found ${tools.length} tools`,
  });
  finishNode(tree, probeId, {
    status: "miss",
    verdict: `${tools.length} tools, ${tools.reduce(
      (n, t) => n + Object.keys(t.inputSchema?.properties ?? {}).length,
      0,
    )} params`,
  });

  const plan = categoriesForTools(tools);

  for (const { category, applicable, reason } of plan) {
    const catNode = addNode(tree, rootId, {
      kind: "category",
      label: category,
      category,
      status: applicable ? "running" : "skipped",
      verdict: reason,
    });

    emitter.emit({
      kind: "branch-open",
      nodeId: catNode.id,
      category,
      message: reason,
    });

    if (!applicable) {
      finishNode(tree, catNode.id, { status: "skipped" });
      emitter.emit({
        kind: "branch-close",
        nodeId: catNode.id,
        category,
        outcome: "skip",
        message: "skipped",
      });
      continue;
    }

    const catFindings = await runCategory(
      category,
      catNode.id,
      tree,
      client,
      tools,
      options,
      emitter,
    );
    findings.push(...catFindings);

    const hit = catFindings.some(
      (f) => f.severity === "critical" || f.severity === "high",
    );
    finishNode(tree, catNode.id, {
      status: hit ? "hit" : "miss",
      findingIds: catFindings.map((f) => f.id),
    });

    emitter.emit({
      kind: "branch-close",
      nodeId: catNode.id,
      category,
      outcome: hit ? "fail" : "pass",
      message: `${catFindings.length} finding(s)`,
    });

    if (hit && options.stopOnHit) {
      emitter.emit({
        kind: "branch-close",
        message: "stop-on-hit triggered — halting tree",
      });
      break;
    }
  }

  return findings;
}

async function runCategory(
  category: Category,
  parentId: string,
  tree: AttackTree,
  client: Client,
  tools: ToolDef[],
  options: ScanOptions,
  emitter: StreamEmitter,
): Promise<Finding[]> {
  if (category === "prompt-injection" || category === "schema") {
    const all = checkManifest(tools);
    const filtered = all.filter((f) =>
      category === "prompt-injection"
        ? f.category === "prompt-injection"
        : f.category === "schema",
    );
    for (const f of filtered) {
      const n = addNode(tree, parentId, {
        kind: "attempt",
        label: f.title,
        category: f.category,
        tool: f.tool,
        status: "hit",
        findingIds: [f.id],
        output: f.evidence,
      });
      emitter.emit({
        kind: "finding",
        nodeId: n.id,
        category: f.category,
        tool: f.tool,
        severity: f.severity,
        findingId: f.id,
        message: f.title,
      });
    }
    return filtered;
  }

  if (category === "tool-confusion") {
    const all = checkManifest(tools);
    const filtered = all.filter((f) => f.category === "tool-confusion");
    for (const f of filtered) {
      const n = addNode(tree, parentId, {
        kind: "attempt",
        label: f.title,
        category: f.category,
        status: "hit",
        findingIds: [f.id],
        output: f.evidence,
      });
      emitter.emit({
        kind: "finding",
        nodeId: n.id,
        category: f.category,
        severity: f.severity,
        findingId: f.id,
        message: f.title,
      });
    }
    return filtered;
  }

  if (
    category === "behavioral" ||
    category === "output-injection" ||
    category === "error-leakage"
  ) {
    if (options.skipBehavioral) return [];
    return runBehavioralTree(
      category,
      parentId,
      tree,
      client,
      tools,
      options,
      emitter,
    );
  }

  if (category === "llm-analysis") {
    if (!options.llmAnalysis || !options.anthropicKey) return [];
    const n = addNode(tree, parentId, {
      kind: "attempt",
      label: "claude-opus-4-7 adversarial analysis",
      category: "llm-analysis",
      status: "running",
    });
    const out = await checkLLM(tools, options.anthropicKey);
    for (const f of out) {
      emitter.emit({
        kind: "finding",
        nodeId: n.id,
        category: "llm-analysis",
        tool: f.tool,
        severity: f.severity,
        findingId: f.id,
        message: f.title,
      });
    }
    finishNode(tree, n.id, {
      status: out.length ? "hit" : "miss",
      findingIds: out.map((f) => f.id),
    });
    return out;
  }

  return [];
}
