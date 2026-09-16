import type { Finding, ToolDef } from "../types.js";
import {
  PROMPT_INJECTION_PATTERNS,
  HIDDEN_INSTRUCTION_PATTERNS,
} from "./payloads.js";

let findingCounter = 0;
const id = (prefix: string) =>
  `${prefix}-${String(++findingCounter).padStart(3, "0")}`;

export function checkManifest(tools: ToolDef[]): Finding[] {
  const findings: Finding[] = [];

  for (const tool of tools) {
    findings.push(...checkToolDescription(tool));
    findings.push(...checkInputSchema(tool));
  }

  findings.push(...checkToolConfusion(tools));
  findings.push(...checkExfiltrationChain(tools));

  return findings;
}

function checkToolDescription(tool: ToolDef): Finding[] {
  const findings: Finding[] = [];
  const text = `${tool.name} ${tool.description ?? ""}`;

  for (const pattern of PROMPT_INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({
        id: id("MI"),
        severity: "critical",
        category: "prompt-injection",
        title: "Prompt injection pattern in tool manifest",
        description: `Tool "${tool.name}" description contains a pattern that could manipulate an LLM into ignoring prior instructions.`,
        evidence: `Matched: ${pattern.toString()} in: "${text.slice(0, 200)}"`,
        tool: tool.name,
        remediation:
          "Remove or rewrite the tool description to avoid instruction-like language.",
      });
    }
  }

  for (const pattern of HIDDEN_INSTRUCTION_PATTERNS) {
    if (pattern.test(text)) {
      findings.push({
        id: id("MI"),
        severity: "critical",
        category: "prompt-injection",
        title: "Hidden instruction block in tool description",
        description: `Tool "${tool.name}" description contains a hidden instruction pattern (code block, separator, or tag).`,
        evidence: `Matched: ${pattern.toString()}`,
        tool: tool.name,
        remediation:
          "Remove embedded code blocks, separators, or XML-like tags from tool descriptions.",
      });
    }
  }

  const zeroWidth = /[\u200b\u00ad\u200c\u200d\u2060\ufeff]/;
  if (zeroWidth.test(text)) {
    findings.push({
      id: id("MI"),
      severity: "high",
      category: "prompt-injection",
      title: "Zero-width / invisible characters in tool description",
      description: `Tool "${tool.name}" contains zero-width or invisible Unicode characters that could hide injected text.`,
      tool: tool.name,
      remediation:
        "Strip all zero-width Unicode characters from tool names and descriptions.",
    });
  }

  if ((tool.description?.length ?? 0) > 2000) {
    findings.push({
      id: id("MI"),
      severity: "medium",
      category: "prompt-injection",
      title: "Unusually long tool description",
      description: `Tool "${tool.name}" has a ${tool.description!.length}-character description. Long descriptions provide more surface area for hidden instructions.`,
      tool: tool.name,
      remediation:
        "Keep tool descriptions concise (under 500 characters). Move detail to parameter descriptions.",
    });
  }

  return findings;
}

function checkInputSchema(tool: ToolDef): Finding[] {
  const findings: Finding[] = [];
  const props = tool.inputSchema?.properties ?? {};

  if (tool.inputSchema?.type === "object" && Object.keys(props).length === 0) {
    findings.push({
      id: id("MS"),
      severity: "info",
      category: "schema",
      title: "Tool accepts no defined parameters",
      description: `Tool "${tool.name}" has an empty input schema. If it takes dynamic input via other means, this is a schema coverage gap.`,
      tool: tool.name,
      remediation:
        "Define explicit input parameters with types and descriptions.",
    });
  }

  for (const [param, schema] of Object.entries(props)) {
    if (!schema.type) {
      findings.push({
        id: id("MS"),
        severity: "low",
        category: "schema",
        title: "Untyped parameter in schema",
        description: `Tool "${tool.name}" parameter "${param}" has no type constraint, accepting any value.`,
        tool: tool.name,
        remediation: `Add a type constraint to the "${param}" parameter schema.`,
      });
    }

    if (!schema.description) {
      findings.push({
        id: id("MS"),
        severity: "info",
        category: "schema",
        title: "Undescribed parameter",
        description: `Tool "${tool.name}" parameter "${param}" has no description. LLMs may misinterpret its purpose.`,
        tool: tool.name,
        remediation: `Add a clear description to the "${param}" parameter.`,
      });
    }
  }

  return findings;
}

export const NAME_SIMILARITY_THRESHOLD = 0.82;

function checkToolConfusion(tools: ToolDef[]): Finding[] {
  const findings: Finding[] = [];

  const DESTRUCTIVE_KEYWORDS = [
    "delete",
    "remove",
    "drop",
    "destroy",
    "purge",
    "clear",
    "reset",
    "wipe",
  ];
  const READ_KEYWORDS = [
    "get",
    "read",
    "fetch",
    "list",
    "query",
    "find",
    "search",
    "show",
  ];

  for (let i = 0; i < tools.length; i++) {
    for (let j = i + 1; j < tools.length; j++) {
      const a = tools[i];
      const b = tools[j];

      // Typosquat risk lives in the NAME. Similarity used to be measured over
      // name + description concatenated, so a long description on one tool and a
      // short one on the other dragged the score down and hid the squat:
      // read_file vs read_fil scores 0.978 on names and 0.809 concatenated,
      // which sat just under this threshold and was never reported.
      const nameSim = jaroWinkler(a.name, b.name);
      const descSim = jaroWinkler(a.description ?? "", b.description ?? "");

      if (nameSim > NAME_SIMILARITY_THRESHOLD) {
        const aDestructive = DESTRUCTIVE_KEYWORDS.some((k) =>
          a.name.toLowerCase().includes(k),
        );
        const bDestructive = DESTRUCTIVE_KEYWORDS.some((k) =>
          b.name.toLowerCase().includes(k),
        );
        const aRead = READ_KEYWORDS.some((k) =>
          a.name.toLowerCase().includes(k),
        );
        const bRead = READ_KEYWORDS.some((k) =>
          b.name.toLowerCase().includes(k),
        );

        const crossIntent = (aDestructive && bRead) || (bDestructive && aRead);
        const severity = crossIntent ? "high" : "medium";

        findings.push({
          id: id("MC"),
          severity,
          category: "tool-confusion",
          title: `Confusable tool pair: "${a.name}" / "${b.name}"`,
          description: `These tools have ${Math.round(nameSim * 100)}% name similarity. An LLM may call the wrong one.${crossIntent ? " One is destructive and one is read-only — this is especially dangerous." : ""}`,
          evidence: `Jaro-Winkler on names: ${nameSim.toFixed(3)} (descriptions: ${descSim.toFixed(3)})`,
          remediation:
            "Differentiate tool names and descriptions clearly. Add explicit warnings in destructive tool descriptions.",
        });
      }
    }
  }

  return findings;
}

function checkExfiltrationChain(tools: ToolDef[]): Finding[] {
  const findings: Finding[] = [];

  const readers = tools.filter((t) =>
    /read|file|env|secret|config|credential|key|token|password/i.test(
      `${t.name} ${t.description ?? ""}`,
    ),
  );
  const senders = tools.filter((t) =>
    /send|post|http|request|webhook|email|upload|exfil|transmit|notify/i.test(
      `${t.name} ${t.description ?? ""}`,
    ),
  );

  if (readers.length > 0 && senders.length > 0) {
    findings.push({
      id: id("MC"),
      severity: "high",
      category: "tool-confusion",
      title: "Potential data exfiltration chain",
      description: `Server exposes both data-reading tools (${readers.map((t) => t.name).join(", ")}) and network-sending tools (${senders.map((t) => t.name).join(", ")}). A compromised LLM could chain these to exfiltrate data.`,
      remediation:
        "Audit whether read+send tool combinations are necessary. Add scope restrictions and logging to both.",
    });
  }

  return findings;
}

export function jaroWinkler(s1: string, s2: string): number {
  s1 = s1.toLowerCase().slice(0, 100);
  s2 = s2.toLowerCase().slice(0, 100);
  if (s1 === s2) return 1;

  const matchWindow = Math.floor(Math.max(s1.length, s2.length) / 2) - 1;
  if (matchWindow < 0) return 0;

  const s1Matches = new Array(s1.length).fill(false);
  const s2Matches = new Array(s2.length).fill(false);
  let matches = 0;
  let transpositions = 0;

  for (let i = 0; i < s1.length; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(i + matchWindow + 1, s2.length);
    for (let j = start; j < end; j++) {
      if (s2Matches[j] || s1[i] !== s2[j]) continue;
      s1Matches[i] = true;
      s2Matches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0;

  let k = 0;
  for (let i = 0; i < s1.length; i++) {
    if (!s1Matches[i]) continue;
    while (!s2Matches[k]) k++;
    if (s1[i] !== s2[k]) transpositions++;
    k++;
  }

  const jaro =
    (matches / s1.length +
      matches / s2.length +
      (matches - transpositions / 2) / matches) /
    3;
  const prefix = [...Array(Math.min(4, s1.length))].filter(
    (_, i) => s1[i] === s2[i],
  ).length;
  return jaro + prefix * 0.1 * (1 - jaro);
}
