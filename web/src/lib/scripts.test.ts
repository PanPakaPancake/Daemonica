import { describe, expect, it } from "vitest";
import { interpreterFor, normalizeRepo, terminalCommand } from "./scripts";

describe("script library helpers", () => {
  it("normalizes repositories like the server", () => {
    expect(normalizeRepo("https://github.com/o/r.git")).toBe("o/r");
    expect(normalizeRepo(" github.com/o/r/ ")).toBe("o/r");
    for (const r of ["o", "o/r/x", "https://evil.example/o/r", "o/r?x"]) expect(normalizeRepo(r)).toBeUndefined();
  });

  it("picks an interpreter only for files that are not executable", () => {
    expect(interpreterFor({ exec: true, shebang: "#!/usr/bin/env python3", path: "a.py" })).toBe("");
    expect(interpreterFor({ exec: false, shebang: "#!/usr/bin/env python3", path: "a" })).toBe("/usr/bin/python3");
    expect(interpreterFor({ exec: false, shebang: "#!/bin/bash", path: "a" })).toBe("/bin/bash");
    expect(interpreterFor({ exec: false, path: "x.sh" })).toBe("/bin/sh");
    expect(interpreterFor({ exec: false, path: "README.md" })).toBe("");
    expect(terminalCommand({ exec: false, path: "x.sh", abs: "/var/lib/daemonica-scripts/local/x.sh" })).toBe("/bin/sh /var/lib/daemonica-scripts/local/x.sh ");
  });
});
