import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { commandInjectionPayloads } from "../src/checks/payloads.js";
import { stripReflections } from "../src/checks/behavioral.js";
import { scanVulnerableServer } from "./scan-target.js";

const CANARY = "PWNED_RT_TESTAA";

/** Runs the payload as if it were the entire command, the execSync(input) case. */
function emitsCanary(payload: string): boolean {
  try {
    return execFileSync("sh", ["-c", payload], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 3000,
    }).includes(CANARY);
  } catch {
    return false;
  }
}

describe("command injection payloads", () => {
  it("does not rely on the leading-separator forms that sh rejects outright", () => {
    // The shipped behaviour: three leading-separator payloads with "; echo CANARY"
    // appended. sh syntax-errors on all three before anything executes, so the
    // canary never appears and a literally vulnerable server scans clean.
    const shipped = ["; id", "| id", "&& id"].map(
      (p) => `${p}; echo ${CANARY}`,
    );
    expect(shipped.filter(emitsCanary)).toHaveLength(0);

    expect(commandInjectionPayloads(CANARY).filter(emitsCanary).length).toBeGreaterThan(0);
  });

  it("keeps the canary out of a pure reflection, including its JSON-escaped form", () => {
    const newline = commandInjectionPayloads(CANARY).find((p) =>
      p.includes("\n"),
    )!;
    const reflected = JSON.stringify([{ type: "text", text: newline }]);
    expect(stripReflections(reflected, newline)).not.toContain(CANARY);
  });

  it("flags execSync(userInput) in the bundled vulnerable server", async () => {
    const result = await scanVulnerableServer();
    const injection = result.findings.filter((f) => f.id.startsWith("BC-"));

    expect(injection.length).toBeGreaterThan(0);
    expect(injection[0].severity).toBe("critical");
    expect(injection[0].tool).toBe("run_shell");
  }, 60_000);
});
