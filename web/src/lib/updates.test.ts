import { describe, expect, it } from "vitest";
import { appendLog, extraRemovals, pkgNameRE, removalNames, securityNames, statusKey, suiteOf, termRE, type Plan } from "./updates";

describe("updates helpers", () => {
  it("names and terms", () => {
    expect(pkgNameRE.test("openssh-server")).toBe(true);
    expect(pkgNameRE.test("libc6:amd64")).toBe(true);
    expect(pkgNameRE.test("-y")).toBe(false);
    expect(pkgNameRE.test("a b")).toBe(false);
    expect(termRE.test("htop")).toBe(true);
    expect(termRE.test("a*")).toBe(false);
  });

  it("suites and security", () => {
    expect(suiteOf("Ubuntu:26.04/resolute-security")).toBe("resolute-security");
    const sim = {
      install: [
        { name: "openssl", old: "1", new: "2", security: true },
        { name: "newdep", new: "1", security: true },
        { name: "tzdata", old: "1", new: "2", security: false },
      ],
      remove: [],
      kept: [],
    };
    expect(securityNames(sim)).toEqual(["openssl"]);
  });

  it("extra removals", () => {
    const plan: Plan = {
      kind: "remove",
      sim: {
        install: [],
        remove: [
          { name: "vim", security: false },
          { name: "vim-runtime", security: false },
          { name: "vim", security: false },
        ],
        kept: [],
      },
      critical: [],
      protected: false,
    };
    expect(extraRemovals(plan, ["vim"])).toEqual(["vim-runtime"]);
    expect(removalNames(plan)).toEqual(["vim", "vim-runtime"]);
  });

  it("log cap", () => {
    expect(appendLog("a\nb\n", "c\n", 4)).toBe("c\n");
    expect(appendLog("", "abc", 10)).toBe("abc");
  });

  it("status", () => {
    expect(statusKey("ii ")).toBe("installed");
    expect(statusKey("hi ")).toBe("held");
    expect(statusKey("rc ")).toBe("config");
    expect(statusKey("iF ")).toBe("other");
    expect(statusKey("iiR")).toBe("broken");
  });
});
