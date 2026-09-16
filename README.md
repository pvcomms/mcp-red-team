# mcp-red-team

Against the deliberately broken server in `examples/`, this scanner returns 30 findings in 243ms and exits 2: three critical, three high, twenty medium, four informational. Before I audited the scanner itself it returned 24, and the six it was missing were its own bugs rather than the target's.

The target is a five-tool MCP server written to be indefensible. `read_file` carries a prompt injection inside its own description. `read_fil` sits one character away from it. `run_shell` hands its argument straight to `execSync`. `send_data` posts to an arbitrary URL, and `get_config` returns a fake API key alongside a Postgres URL with the password in it. What the scanner now reports against that: command injection confirmed in `run_shell`, because a canary string came back out of the shell; path traversal confirmed in `read_file`, because it read `/etc/passwd`; the `read_file` / `read_fil` pair at 0.978 name similarity; the description injection; and the read-tool-plus-send-tool exfiltration chain. Seventeen of the twenty mediums are the same stack-trace leak in `read_file`, counted once per probe. That is noise, and I have not deduplicated it.

## The ten checks

| Prefix | Attack                                 | Detection                                                                                                                                                                 |
| ------ | -------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MI-`  | Prompt injection in the manifest       | 13 instruction-override regexes, 4 hidden-instruction patterns, a zero-width character class, and a 2,000-character description ceiling, run over name plus description   |
| `MS-`  | Schema gaps                            | Walks `inputSchema` for untyped parameters, undescribed parameters, and empty property sets                                                                               |
| `MC-`  | Tool confusion and exfiltration chains | Jaro-Winkler over tool names above 0.82; separately, a keyword partition of the manifest into reader tools and sender tools                                               |
| `BC-`  | Command injection                      | 9 canary payloads per parameter, each a complete shell fragment on its own; every reflection of the payload is stripped from the response before the canary is looked for |
| `BP-`  | Path traversal                         | 8 `/etc/passwd` payloads, absolute and relative, matched against 5 passwd content signatures covering Linux and macOS                                                     |
| `BD-`  | Oversized input                        | A 500,000-character string; a timeout counts as high, silent acceptance as medium                                                                                         |
| `BO-`  | Output injection                       | 2 model-instruction payloads sent as input, flagged when they return unsanitized into what would be the model's context                                                   |
| `BE-`  | Error leakage                          | 8 credential regexes and 7 stack-trace and absolute-path patterns, run over every response from every other probe, plus 6 Unicode edge-case inputs of its own             |
| `BS-`  | SQL injection                          | 2 payloads matched against 6 raw database error signatures                                                                                                                |
| `LA-`  | Adversarial manifest reading           | Optional, behind `--llm`. Claude reads the manifest for framing, trust escalation, and social engineering that regex will not catch                                       |

The one idea in here worth keeping is inside `BC-`. A tool that echoes your input back at you looks identical to a tool that executed it, if all you do is search the response for your canary. So the check strips every reflection of the payload — including its JSON-escaped form, since responses are stringified before matching — and only then looks for what is left. `read_fil` echoes everything it is given and is correctly not reported as executing anything.

## What I got wrong

Three false negatives, all found by auditing the scanner rather than by scanning anything.

Command injection went undetected against a literal `execSync(userInput)`. The payloads led with a bare separator — `"; id"` — and the caller appended `"; echo CANARY"`. When the whole argument is the command, `sh` syntax-errors on that leading semicolon before anything runs, no canary appears, and the scanner reports clean. Payloads now embed the canary themselves and each is valid shell in context.

Path traversal went undetected for two reasons at once. The content signature was `root:x:0:0`, which is Linux; macOS writes `root:*:0:0`. And the payload list was sliced to its first three entries, which dropped the absolute `/etc/passwd` — the only one that resolves, since relative payloads resolve against the scanner's own working directory, not the target's.

The typosquat pair scored 0.809 against a 0.82 threshold because similarity was measured over name and description concatenated, and one of the two tools had a long description. Over names alone the same pair scores 0.978. Names now carry the decision, with description similarity reported alongside as context.

Each of the three has a regression test that fails against the previous behaviour and passes against this one. `pnpm test` runs 10 tests across 3 files.

## What this does not do

I have never run this against a third-party MCP server. Every number above comes from a target I wrote to fail. `cases/` is empty and gitignored; there is no corpus of real scans behind any of this.

The `BO-` and `BS-` probes still send only two of their payloads each, which is the same truncation that hid the path traversal. Neither has a demonstrated false negative yet, so I left them, but the shape of the bug is identical.

Scoring typosquats on names alone will produce more findings on servers that name things consistently. `get_issue` / `get_issues` scores 0.980, `search_docs` / `search_code` scores 0.944, `list_users` / `list_usage` scores 0.920 — all above the threshold, none of them squats. I would rather read a false positive than miss a real one, but that is a preference, not a result.

Nothing here tests transports, authentication, session handling, or rate limits. The `--llm` path has not been benchmarked at all; treat it as a second opinion, not a measurement.

## Scope

Run this against MCP servers you operate, or servers you have written permission to test. The behavioural probes execute shell payloads and read files on the target host. Pointing it at somebody else's server without their agreement is an attack, not an audit.

## Install and run

```bash
pnpm install
pnpm build

node dist/index.js --stdio "node examples/vulnerable-server.mjs"
node dist/index.js --stdio "python server.py" --output report.md
node dist/index.js --sse http://localhost:3000 --skip-behavioral
node dist/index.js --stdio "node server.js" --llm   # needs ANTHROPIC_API_KEY
```

Exit codes are `0` for clean, `1` for high findings, `2` for critical findings, `3` when the scan itself failed. The score starts at 100 and deducts 25 per critical, 10 per high, 5 per medium and 2 per low, floored at zero — which is why the example server scored 0 both before and after these fixes. The finding counts moved. The score had nowhere left to go.

A scanner that has only ever been pointed at a target its author wrote is a scanner with one confirmed data point, and the honest thing is to print that next to the score.

## License

MIT.
