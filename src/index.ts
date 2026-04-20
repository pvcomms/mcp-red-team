#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { runScan } from "./runner.js";
import { printTerminal, writeMarkdown, writeJSON } from "./reporter.js";
import type { ScanOptions, StreamMode } from "./types.js";

const program = new Command();

program
  .name("mcp-red-team")
  .description("Adversarial security testing framework for MCP servers")
  .version("0.1.0")
  .option(
    "--stdio <command>",
    'stdio transport: command string to spawn (e.g. "python server.py")',
  )
  .option("--sse <url>", "SSE transport: URL of running MCP server")
  .option(
    "--llm",
    "Enable Claude-powered adversarial manifest analysis (requires --anthropic-key or ANTHROPIC_API_KEY)",
  )
  .option(
    "--anthropic-key <key>",
    "Anthropic API key (or set ANTHROPIC_API_KEY env var)",
  )
  .option(
    "--output <file>",
    "Write markdown report to file (use .json suffix for JSON output)",
  )
  .option(
    "--skip-behavioral",
    "Skip dynamic behavioral tests (manifest analysis only)",
  )
  .option("--timeout <ms>", "Per-tool-call timeout in ms", "5000")
  .option("-v, --verbose", "Verbose output")
  .option(
    "--stream",
    "Pretty-print per-attempt progress to stdout as the scan runs",
  )
  .option(
    "--stream-json",
    "Emit NDJSON events to stdout as the scan runs (for tool consumption)",
  )
  .option(
    "--stop-on-hit",
    "Stop the scan as soon as a critical/high finding is confirmed",
  )
  .option(
    "--case <file>",
    "Write the attack-tree case file to this path (default: cases/<uuid>.json)",
  )
  .option(
    "--replay <file>",
    "Replay every attempt in the given case file against the live target",
  )
  .option(
    "--fork <nodeId>",
    "Fork a specific node from --replay with a modified payload variant",
  )
  .option(
    "--variant <mutation>",
    "Payload mutation for --fork: base64 | url-encode | double-url | reverse | raw",
    "raw",
  )
  .addHelpText(
    "after",
    `
Examples:
  mcp-red-team --stdio "python server.py"
  mcp-red-team --stdio "node build/index.js" --llm --output report.md
  mcp-red-team --stdio "node build/index.js" --stream --stop-on-hit
  mcp-red-team --stdio "node build/index.js" --stream-json | jq '.'
  mcp-red-team --stdio "node server.js" --case cases/my-scan.json
  mcp-red-team --stdio "node server.js" --replay cases/my-scan.json
  mcp-red-team --stdio "node server.js" --replay cases/my-scan.json --fork a12 --variant base64
`,
  )
  .parse();

const opts = program.opts<{
  stdio?: string;
  sse?: string;
  llm?: boolean;
  anthropicKey?: string;
  output?: string;
  skipBehavioral?: boolean;
  timeout: string;
  verbose?: boolean;
  stream?: boolean;
  streamJson?: boolean;
  stopOnHit?: boolean;
  case?: string;
  replay?: string;
  fork?: string;
  variant?: string;
}>();

if (!opts.stdio && !opts.sse) {
  console.error(chalk.red("Error: provide --stdio <command> or --sse <url>"));
  process.exit(1);
}

const anthropicKey = opts.anthropicKey ?? process.env.ANTHROPIC_API_KEY;

if (opts.llm && !anthropicKey) {
  console.error(
    chalk.red(
      "Error: --llm requires --anthropic-key or ANTHROPIC_API_KEY env var",
    ),
  );
  process.exit(1);
}

let command = "";
let args: string[] = [];

if (opts.stdio) {
  const parts = opts.stdio.trim().split(/\s+/);
  command = parts[0];
  args = parts.slice(1);
}

const streamMode: StreamMode = opts.streamJson
  ? "json"
  : opts.stream
    ? "pretty"
    : "off";

const options: ScanOptions = {
  command,
  args,
  transport: opts.sse ? "sse" : "stdio",
  sseUrl: opts.sse,
  llmAnalysis: !!opts.llm,
  anthropicKey,
  outputFile: opts.output,
  verbose: !!opts.verbose,
  timeout: parseInt(opts.timeout, 10),
  skipBehavioral: !!opts.skipBehavioral,
  stream: streamMode,
  stopOnHit: !!opts.stopOnHit,
  caseFile: opts.case,
  replayCase: opts.replay,
  forkNode: opts.fork,
  forkVariant: opts.variant,
};

if (streamMode === "off") {
  console.log(chalk.gray("\nConnecting to MCP server..."));
}

runScan(options)
  .then((result) => {
    if (streamMode !== "json") {
      printTerminal(result);
    }

    if (opts.output) {
      if (opts.output.endsWith(".json")) {
        writeJSON(result, opts.output);
      } else {
        writeMarkdown(result, opts.output);
      }
      if (streamMode !== "json") {
        console.log(chalk.green(`Report written to ${opts.output}`));
      }
    }

    const exitCode =
      result.summary.critical > 0 ? 2 : result.summary.high > 0 ? 1 : 0;
    process.exit(exitCode);
  })
  .catch((err) => {
    console.error(
      chalk.red("\nScan failed:"),
      err instanceof Error ? err.message : String(err),
    );
    process.exit(3);
  });
