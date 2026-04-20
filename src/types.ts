export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Category =
  | "prompt-injection"
  | "tool-confusion"
  | "behavioral"
  | "output-injection"
  | "error-leakage"
  | "schema"
  | "llm-analysis";

export interface Finding {
  id: string;
  severity: Severity;
  category: Category;
  title: string;
  description: string;
  evidence?: string;
  tool?: string;
  remediation: string;
}

export interface ToolDef {
  name: string;
  description?: string;
  inputSchema: {
    type: string;
    properties?: Record<
      string,
      { type?: string; description?: string; [key: string]: unknown }
    >;
    required?: string[];
  };
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  score: number;
}

export interface ScanResult {
  target: string;
  timestamp: string;
  durationMs: number;
  tools: ToolDef[];
  findings: Finding[];
  summary: ScanSummary;
  tree?: AttackTree;
}

export type StreamMode = "off" | "pretty" | "json";

export interface StreamEvent {
  ts: string;
  seq: number;
  kind:
    | "scan-start"
    | "probe"
    | "branch-open"
    | "attempt"
    | "branch-close"
    | "finding"
    | "scan-end";
  category?: Category | "probe" | "tree";
  tool?: string;
  nodeId?: string;
  parentId?: string;
  attemptNumber?: number;
  totalAttempts?: number;
  payloadLabel?: string;
  outcome?: "pass" | "fail" | "error" | "skip";
  severity?: Severity;
  latencyMs?: number;
  message?: string;
  findingId?: string;
}

export interface TreeNode {
  id: string;
  parentId?: string;
  kind: "root" | "probe" | "category" | "variant" | "attempt";
  label: string;
  category?: Category | "probe" | "tree";
  tool?: string;
  payloadLabel?: string;
  payload?: string;
  status: "pending" | "running" | "hit" | "miss" | "error" | "skipped";
  startedAt?: string;
  endedAt?: string;
  latencyMs?: number;
  input?: Record<string, unknown>;
  output?: string;
  verdict?: string;
  findingIds?: string[];
  children: string[];
}

export interface AttackTree {
  rootId: string;
  nodes: Record<string, TreeNode>;
  caseId: string;
  target: string;
  createdAt: string;
}

export interface ScanOptions {
  command: string;
  args: string[];
  transport: "stdio" | "sse";
  sseUrl?: string;
  llmAnalysis: boolean;
  anthropicKey?: string;
  outputFile?: string;
  verbose: boolean;
  timeout: number;
  skipBehavioral: boolean;
  stream: StreamMode;
  stopOnHit: boolean;
  caseFile?: string;
  replayCase?: string;
  forkNode?: string;
  forkVariant?: string;
}
