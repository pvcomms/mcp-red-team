import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import type { AttackTree, Finding, ScanOptions, TreeNode } from "../types.js";
import type { CaseFile } from "./case.js";
import { StreamEmitter } from "../stream/emitter.js";
import { addNode, finishNode } from "./tree.js";

export interface ForkOptions {
  nodeId: string;
  mutation: "base64" | "url-encode" | "double-url" | "reverse" | "raw";
  overridePayload?: string;
}

export function mutate(
  payload: string,
  mutation: ForkOptions["mutation"],
): string {
  if (mutation === "base64")
    return Buffer.from(payload, "utf8").toString("base64");
  if (mutation === "url-encode") return encodeURIComponent(payload);
  if (mutation === "double-url")
    return encodeURIComponent(encodeURIComponent(payload));
  if (mutation === "reverse") return payload.split("").reverse().join("");
  return payload;
}

export async function replayNode(
  caseFile: CaseFile,
  client: Client,
  options: ScanOptions,
  emitter: StreamEmitter,
  fork?: ForkOptions,
): Promise<{ tree: AttackTree; findings: Finding[] }> {
  const wantId = fork?.nodeId ?? options.forkNode;
  const targetNode: TreeNode | undefined = wantId
    ? caseFile.tree.nodes[wantId]
    : undefined;

  if (!targetNode) {
    throw new Error(`node not found in case file: ${wantId}`);
  }

  if (targetNode.kind !== "attempt" || !targetNode.tool || !targetNode.input) {
    throw new Error(
      `can only replay/fork attempt nodes with tool + input (got ${targetNode.kind})`,
    );
  }

  const tree = structuredClone(caseFile.tree);
  tree.nodes[tree.rootId].children = [...tree.nodes[tree.rootId].children];

  const forkNode = addNode(tree, tree.rootId, {
    kind: "attempt",
    label: `fork of ${targetNode.id}: ${fork?.mutation ?? "raw"}`,
    category: targetNode.category,
    tool: targetNode.tool,
    payloadLabel: `fork-${fork?.mutation ?? "raw"}`,
    status: "running",
  });

  const mutated =
    fork?.overridePayload ??
    (fork
      ? mutate(targetNode.payload ?? "", fork.mutation)
      : (targetNode.payload ?? ""));

  // substitute the mutated payload into the same arg slot
  const origArgs = targetNode.input;
  const args: Record<string, unknown> = { ...origArgs };
  for (const k of Object.keys(args)) {
    if (args[k] === targetNode.payload) args[k] = mutated;
  }

  const started = Date.now();
  emitter.emit({
    kind: "branch-open",
    nodeId: forkNode.id,
    category: targetNode.category,
    tool: targetNode.tool,
    message: `replay/fork via ${fork?.mutation ?? "raw"}`,
  });

  try {
    const result = await Promise.race([
      client.callTool({ name: targetNode.tool, arguments: args }),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error("TIMEOUT")), options.timeout),
      ),
    ]);
    const content = JSON.stringify(
      (result as { content?: unknown }).content ?? result,
    );
    const isError = (result as { isError?: boolean }).isError === true;
    const latency = Date.now() - started;

    finishNode(tree, forkNode.id, {
      status: "miss",
      output: content.slice(0, 1000),
      input: args,
      payload: mutated,
      verdict: isError ? "error" : "completed",
    });

    emitter.emit({
      kind: "attempt",
      nodeId: forkNode.id,
      category: targetNode.category,
      tool: targetNode.tool,
      payloadLabel: `fork-${fork?.mutation ?? "raw"}`,
      outcome: isError ? "error" : "pass",
      latencyMs: latency,
    });

    // mini comparison diagnostic
    const origHit = (targetNode.findingIds ?? []).length > 0;
    emitter.emit({
      kind: "branch-close",
      nodeId: forkNode.id,
      message: `original=${origHit ? "hit" : "miss"} fork=${isError ? "error" : "miss"}`,
    });

    return { tree, findings: [] };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    finishNode(tree, forkNode.id, { status: "error", verdict: msg });
    emitter.emit({
      kind: "attempt",
      nodeId: forkNode.id,
      category: targetNode.category,
      tool: targetNode.tool,
      outcome: "error",
      message: msg,
    });
    return { tree, findings: [] };
  }
}
