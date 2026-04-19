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
}
