import chalk from "chalk";
import type { StreamEvent, StreamMode } from "../types.js";

const TERRACOTTA = "#C35831";

const SEVERITY_GLYPH: Record<string, string> = {
  critical: "!!",
  high: "!",
  medium: "~",
  low: ".",
  info: " ",
};

const OUTCOME_COLOR: Record<string, (s: string) => string> = {
  pass: chalk.gray,
  fail: chalk.hex(TERRACOTTA).bold,
  error: chalk.yellow,
  skip: chalk.gray.dim,
};

export class StreamEmitter {
  private seq = 0;
  private events: StreamEvent[] = [];
  private pulsedFindings = new Set<string>();

  constructor(private mode: StreamMode) {}

  emit(ev: Omit<StreamEvent, "ts" | "seq">): StreamEvent {
    const full: StreamEvent = {
      ts: new Date().toISOString(),
      seq: ++this.seq,
      ...ev,
    };
    this.events.push(full);

    if (this.mode === "json") {
      process.stdout.write(JSON.stringify(full) + "\n");
    } else if (this.mode === "pretty") {
      this.writePretty(full);
    }

    return full;
  }

  all(): StreamEvent[] {
    return this.events;
  }

  private writePretty(ev: StreamEvent): void {
    const t = ev.ts.slice(11, 23);
    const tag = chalk.gray(t);

    if (ev.kind === "scan-start") {
      process.stdout.write(
        `${tag} ${chalk.bold("scan")} ${chalk.gray("target=")}${ev.message ?? ""}\n`,
      );
      return;
    }

    if (ev.kind === "probe") {
      process.stdout.write(
        `${tag} ${chalk.bold("probe")} ${chalk.gray("tools=")}${ev.totalAttempts ?? 0}\n`,
      );
      return;
    }

    if (ev.kind === "branch-open") {
      const cat = chalk.cyan(ev.category ?? "?");
      const tool = ev.tool ? chalk.gray(` [${ev.tool}]`) : "";
      process.stdout.write(
        `${tag} ${chalk.dim("┌")} ${cat}${tool} ${chalk.gray(ev.message ?? "")}\n`,
      );
      return;
    }

    if (ev.kind === "attempt") {
      const colorFn = OUTCOME_COLOR[ev.outcome ?? "pass"] ?? chalk.white;
      const outcome = colorFn((ev.outcome ?? "").padEnd(5));
      const lat =
        ev.latencyMs !== undefined ? chalk.gray(`${ev.latencyMs}ms`) : "";
      const n =
        ev.attemptNumber && ev.totalAttempts
          ? chalk.gray(`${ev.attemptNumber}/${ev.totalAttempts}`)
          : "";
      const label = ev.payloadLabel
        ? chalk.gray(ev.payloadLabel.slice(0, 48))
        : "";
      process.stdout.write(
        `${tag} ${chalk.dim("│")} ${outcome} ${n} ${label} ${lat}\n`,
      );
      return;
    }

    if (ev.kind === "finding") {
      const sev = ev.severity ?? "info";
      const glyph = SEVERITY_GLYPH[sev] ?? " ";
      const line = `${tag} ${chalk.dim("│")} ${chalk
        .hex(TERRACOTTA)
        .bold(`${glyph} ${sev.toUpperCase()}`)} ${ev.message ?? ""}`;
      // single terracotta pulse per finding — no loop
      if (ev.findingId && !this.pulsedFindings.has(ev.findingId)) {
        this.pulsedFindings.add(ev.findingId);
        process.stdout.write(line + chalk.hex(TERRACOTTA)(" ●") + "\n");
      } else {
        process.stdout.write(line + "\n");
      }
      return;
    }

    if (ev.kind === "branch-close") {
      process.stdout.write(
        `${tag} ${chalk.dim("└")} ${chalk.gray(ev.message ?? "")}\n`,
      );
      return;
    }

    if (ev.kind === "scan-end") {
      process.stdout.write(
        `${tag} ${chalk.bold("done")} ${chalk.gray(ev.message ?? "")}\n`,
      );
    }
  }
}
