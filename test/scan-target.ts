import { runScan } from "../src/runner.js";
import type { ScanResult } from "../src/types.js";

/**
 * One scan of the bundled vulnerable server, shared by every regression test in
 * this file's module graph. The server is the same target the README quotes.
 */
let cached: Promise<ScanResult> | undefined;

export function scanVulnerableServer(): Promise<ScanResult> {
  cached ??= runScan({
    command: "node",
    args: ["examples/vulnerable-server.mjs"],
    transport: "stdio",
    llmAnalysis: false,
    verbose: false,
    timeout: 5000,
    skipBehavioral: false,
  });
  return cached;
}
