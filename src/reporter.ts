import chalk from "chalk";
import { writeFileSync } from "fs";
import type { Finding, ScanResult, Severity } from "./types.js";

type ChalkFn = (text: string) => string;

const SEVERITY_COLOR: Record<Severity, ChalkFn> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.blue,
  info: chalk.gray,
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRIT",
  high: "HIGH",
  medium: " MED",
  low: " LOW",
  info: "INFO",
};

const SCORE_COLOR = (score: number) =>
  score >= 80
    ? chalk.green.bold
    : score >= 50
      ? chalk.yellow.bold
      : chalk.red.bold;

export function printTerminal(result: ScanResult): void {
  const { summary, findings, tools, target, durationMs } = result;

  console.log("\n" + chalk.bold("─".repeat(60)));
  console.log(
    chalk.bold("  mcp-red-team") +
      chalk.gray(" — MCP Adversarial Security Scanner"),
  );
  console.log(chalk.bold("─".repeat(60)));
  console.log(`  Target : ${chalk.cyan(target)}`);
  console.log(
    `  Tools  : ${chalk.cyan(String(tools.length))} (${tools.map((t) => t.name).join(", ")})`,
  );
  console.log(`  Time   : ${chalk.cyan(durationMs + "ms")}`);
  console.log(chalk.bold("─".repeat(60)));

  const scoreLabel = SCORE_COLOR(summary.score)(`${summary.score}/100`);
  const grade =
    summary.score >= 80
      ? chalk.green("PASS")
      : summary.score >= 50
        ? chalk.yellow("WARN")
        : chalk.red("FAIL");

  console.log(`\n  Security Score: ${scoreLabel}  ${grade}`);
  console.log(
    `  ${chalk.bgRed.white(` ${summary.critical} CRITICAL `)}  ` +
      `${chalk.red(`${summary.high} HIGH`)}  ` +
      `${chalk.yellow(`${summary.medium} MED`)}  ` +
      `${chalk.blue(`${summary.low} LOW`)}  ` +
      `${chalk.gray(`${summary.info} INFO`)}\n`,
  );

  if (findings.length === 0) {
    console.log(chalk.green("  No findings. Server passed all checks.\n"));
    return;
  }

  const bySeverity: Severity[] = ["critical", "high", "medium", "low", "info"];
  for (const sev of bySeverity) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;

    for (const f of group) {
      printFinding(f);
    }
  }

  console.log(chalk.bold("─".repeat(60)) + "\n");
}

function printFinding(f: Finding): void {
  const badge = SEVERITY_COLOR[f.severity](` ${SEVERITY_LABEL[f.severity]} `);
  const toolTag = f.tool ? chalk.gray(` [${f.tool}]`) : "";
  console.log(`  ${badge} ${chalk.bold(f.title)}${toolTag}`);
  console.log(`         ${chalk.gray(f.category)} · ${f.id}`);
  console.log(`         ${f.description}`);
  if (f.evidence) {
    console.log(
      `         ${chalk.gray("Evidence:")} ${chalk.italic(f.evidence.slice(0, 120).replace(/\n/g, "↵"))}`,
    );
  }
  console.log(`         ${chalk.cyan("Fix:")} ${f.remediation}`);
  console.log();
}

export function writeMarkdown(result: ScanResult, outputFile: string): void {
  const md = buildMarkdown(result);
  writeFileSync(outputFile, md, "utf8");
}

function buildMarkdown(result: ScanResult): string {
  const { summary, findings, tools, target, timestamp, durationMs } = result;
  const grade =
    summary.score >= 80 ? "PASS" : summary.score >= 50 ? "WARN" : "FAIL";

  const lines: string[] = [
    "# mcp-red-team Security Report",
    "",
    `| Field | Value |`,
    `|-------|-------|`,
    `| Target | \`${target}\` |`,
    `| Scan time | ${new Date(timestamp).toLocaleString()} |`,
    `| Duration | ${durationMs}ms |`,
    `| Tools found | ${tools.map((t) => `\`${t.name}\``).join(", ")} |`,
    `| Score | **${summary.score}/100** (${grade}) |`,
    "",
    "## Summary",
    "",
    `| Severity | Count |`,
    `|----------|-------|`,
    `| 🔴 Critical | ${summary.critical} |`,
    `| 🟠 High | ${summary.high} |`,
    `| 🟡 Medium | ${summary.medium} |`,
    `| 🔵 Low | ${summary.low} |`,
    `| ⚪ Info | ${summary.info} |`,
    "",
  ];

  if (findings.length === 0) {
    lines.push("## Findings", "", "_No findings. Server passed all checks._");
    return lines.join("\n");
  }

  lines.push("## Findings", "");

  const bySeverity: Severity[] = ["critical", "high", "medium", "low", "info"];
  for (const sev of bySeverity) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;

    lines.push(`### ${capitalize(sev)}`, "");
    for (const f of group) {
      lines.push(
        `#### ${f.id}: ${f.title}`,
        "",
        `- **Category:** ${f.category}`,
        f.tool ? `- **Tool:** \`${f.tool}\`` : "",
        `- **Description:** ${f.description}`,
        f.evidence
          ? `- **Evidence:** \`${f.evidence.slice(0, 300).replace(/`/g, "'")}\``
          : "",
        `- **Remediation:** ${f.remediation}`,
        "",
      );
    }
  }

  lines.push("## Remediation Checklist", "");
  const uniqueRemediations = [...new Set(findings.map((f) => f.remediation))];
  for (const r of uniqueRemediations) {
    lines.push(`- [ ] ${r}`);
  }
  lines.push(
    "",
    "_Generated by [mcp-red-team](https://github.com/paramxclaudedev/mcp-red-team)_",
  );

  return lines.filter((l) => l !== undefined).join("\n");
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

export function writeJSON(result: ScanResult, outputFile: string): void {
  writeFileSync(outputFile, JSON.stringify(result, null, 2), "utf8");
}
