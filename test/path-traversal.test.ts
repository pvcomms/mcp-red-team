import { describe, expect, it } from "vitest";
import {
  PASSWD_CONTENT_SIGNATURES,
  PATH_TRAVERSAL_PAYLOADS,
} from "../src/checks/payloads.js";
import { scanVulnerableServer } from "./scan-target.js";

const LINUX_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
const MACOS_PASSWD = "##\n# User Database\n##\nnobody:*:-2:-2:Unprivileged User:/var/empty:/usr/bin/false\nroot:*:0:0:System Administrator:/var/root:/bin/sh\n";

const matches = (passwd: string) =>
  PASSWD_CONTENT_SIGNATURES.some((sig) => sig.test(JSON.stringify(passwd)));

describe("path traversal detection", () => {
  it("recognises a macOS passwd file, not just the Linux one", () => {
    // The shipped signature was /root:x:0:0/. macOS writes root:*:0:0, so every
    // traversal on a Mac read the file successfully and still scored clean.
    expect(/root:x:0:0/.test(MACOS_PASSWD)).toBe(false);

    expect(matches(MACOS_PASSWD)).toBe(true);
    expect(matches(LINUX_PASSWD)).toBe(true);
  });

  it("does not fire on an ordinary error response", () => {
    expect(
      matches("Error: ENOENT: no such file or directory, open '/etc/passwd'"),
    ).toBe(false);
  });

  it("sends the absolute /etc/passwd payload, not only relative ones", () => {
    // The scanner used to take PATH_TRAVERSAL_PAYLOADS.slice(0, 3); "/etc/passwd"
    // sat at index 5 and was never sent. Relative payloads resolve against the
    // scanner's cwd and hit nothing, so the absolute one carries the test.
    expect(PATH_TRAVERSAL_PAYLOADS.slice(0, 3)).toContain("/etc/passwd");
  });

  it("flags the unguarded readFileSync in the bundled vulnerable server", async () => {
    const result = await scanVulnerableServer();
    const traversal = result.findings.filter((f) => f.id.startsWith("BP-"));

    expect(traversal.length).toBeGreaterThan(0);
    expect(traversal[0].severity).toBe("critical");
    expect(traversal[0].tool).toBe("read_file");
  }, 60_000);
});
