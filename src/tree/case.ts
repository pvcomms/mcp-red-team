import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { dirname } from "path";
import type { AttackTree, ScanResult, StreamEvent } from "../types.js";

export interface CaseFile {
  version: "1";
  caseId: string;
  target: string;
  createdAt: string;
  tree: AttackTree;
  events: StreamEvent[];
  findings: ScanResult["findings"];
  summary: ScanResult["summary"];
}

export function saveCase(path: string, c: CaseFile): void {
  if (!existsSync(dirname(path))) {
    mkdirSync(dirname(path), { recursive: true });
  }
  writeFileSync(path, JSON.stringify(c, null, 2), "utf8");
}

export function loadCase(path: string): CaseFile {
  return JSON.parse(readFileSync(path, "utf8")) as CaseFile;
}

export function defaultCasePath(caseId: string): string {
  return `cases/${caseId}.json`;
}
