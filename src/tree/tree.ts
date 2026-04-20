import { randomUUID } from "crypto";
import type { AttackTree, TreeNode, Category } from "../types.js";

export function newTree(target: string): AttackTree {
  const rootId = "root";
  const now = new Date().toISOString();
  return {
    rootId,
    caseId: randomUUID(),
    target,
    createdAt: now,
    nodes: {
      [rootId]: {
        id: rootId,
        kind: "root",
        label: `scan ${target}`,
        status: "running",
        startedAt: now,
        children: [],
      },
    },
  };
}

export function addNode(
  tree: AttackTree,
  parentId: string,
  init: Omit<
    TreeNode,
    "id" | "parentId" | "children" | "status" | "startedAt"
  > & {
    status?: TreeNode["status"];
  },
): TreeNode {
  const id = `${init.kind[0]}${Object.keys(tree.nodes).length}`;
  const node: TreeNode = {
    id,
    parentId,
    children: [],
    status: init.status ?? "pending",
    startedAt: new Date().toISOString(),
    ...init,
  };
  tree.nodes[id] = node;
  tree.nodes[parentId].children.push(id);
  return node;
}

export function finishNode(
  tree: AttackTree,
  id: string,
  patch: Partial<TreeNode>,
): void {
  const n = tree.nodes[id];
  if (!n) return;
  Object.assign(n, patch, { endedAt: new Date().toISOString() });
  if (n.startedAt && n.endedAt) {
    n.latencyMs = Date.parse(n.endedAt) - Date.parse(n.startedAt);
  }
}

export function walk(tree: AttackTree, id: string): TreeNode[] {
  const out: TreeNode[] = [];
  const stack = [id];
  while (stack.length) {
    const cur = stack.pop()!;
    const n = tree.nodes[cur];
    if (!n) continue;
    out.push(n);
    stack.push(...n.children);
  }
  return out;
}

export function findNodeByLabel(
  tree: AttackTree,
  label: string,
): TreeNode | undefined {
  return Object.values(tree.nodes).find(
    (n) => n.id === label || n.label === label,
  );
}

export function categoriesForTools(
  tools: { name: string; description?: string }[],
): {
  category: Category;
  applicable: boolean;
  reason: string;
}[] {
  const joined = tools
    .map((t) => `${t.name} ${t.description ?? ""}`)
    .join(" ")
    .toLowerCase();

  const hasString = tools.length > 0;
  const looksFilePath = /file|path|dir|read|load|open/.test(joined);
  const looksShell = /exec|shell|run|cmd|command|spawn/.test(joined);
  const looksSql = /sql|query|db|database|select|table/.test(joined);
  const looksNet = /http|url|fetch|request|send|post/.test(joined);

  return [
    {
      category: "prompt-injection",
      applicable: true,
      reason: "always — manifest is always in scope",
    },
    {
      category: "schema",
      applicable: true,
      reason: "always — schema is always in scope",
    },
    {
      category: "tool-confusion",
      applicable: tools.length >= 2,
      reason:
        tools.length >= 2
          ? "two+ tools — confusion check applicable"
          : "only one tool — no confusion possible",
    },
    {
      category: "behavioral",
      applicable: hasString && (looksShell || looksFilePath),
      reason:
        looksShell || looksFilePath
          ? "shell/file signature detected in manifest"
          : "no shell/file signature — unlikely to be vulnerable",
    },
    {
      category: "output-injection",
      applicable: hasString,
      reason: hasString ? "string params present" : "no string params",
    },
    {
      category: "error-leakage",
      applicable: hasString,
      reason: hasString ? "any tool call can leak errors" : "no callable tools",
    },
    {
      category: "llm-analysis",
      applicable: tools.some((t) => (t.description?.length ?? 0) > 50),
      reason: "only worth calling Claude when descriptions carry signal",
    },
  ];
}
