import { describe, expect, it } from "vitest";
import { confirmName, countdown, groupZones, hostnameProblem, inZone, nextPhase, sameZone, secondsUntil } from "./timehost";

describe("timehost", () => {
  it("checks host names like the helper", () => {
    expect(hostnameProblem("web2")).toBeUndefined();
    expect(hostnameProblem("")).toBe("empty");
    expect(hostnameProblem("Web2")).toBe("upper");
    expect(hostnameProblem("web.example.org")).toBe("dot");
    expect(hostnameProblem("-web")).toBe("invalid");
    expect(hostnameProblem("a".repeat(64))).toBe("invalid");
  });

  it("confirms with the static name", () => {
    expect(confirmName({ hostname: "k", static: "s", pretty: "" })).toBe("s");
    expect(confirmName({ hostname: "k", static: "", pretty: "" })).toBe("k");
    expect(confirmName(null)).toBe("");
  });

  it("groups and orders zones", () => {
    expect(groupZones(["UTC", "Europe/Berlin", "America/New_York", "Europe/Amsterdam"])).toEqual([
      ["America", ["America/New_York"]],
      ["Europe", ["Europe/Berlin", "Europe/Amsterdam"]],
      ["", ["UTC"]],
    ]);
  });

  it("formats in a zone and falls back to UTC", () => {
    const ms = Date.UTC(2026, 9, 26, 12, 0, 0);
    expect(inZone(ms, "Europe/Berlin", "en", false)).toContain("1:00:00");
    expect(inZone(ms, "No/Such", "en", false)).toContain("12:00:00");
    expect(inZone(ms, "Europe/Berlin", "de")).toMatch(/26\.10\.2026.*13:00:00.*(MEZ|GMT\+1)/);
  });

  it("folds the UTC aliases only", () => {
    expect(sameZone("UTC", "Etc/UTC")).toBe(true);
    expect(sameZone("Europe/Berlin", "Europe/Berlin")).toBe(true);
    expect(sameZone("Europe/Berlin", "Europe/Paris")).toBe(false);
  });

  it("counts down", () => {
    expect(secondsUntil("2026-10-26T12:00:10Z", Date.UTC(2026, 9, 26, 12, 0, 0))).toBe(10);
    expect(secondsUntil("2026-10-26T12:00:00Z", Date.UTC(2026, 9, 26, 13, 0, 0))).toBe(0);
    expect(countdown(65)).toBe("1:05");
    expect(countdown(3669)).toBe("1:01:09");
  });

  it("detects the return after a reboot by the boot id", () => {
    expect(nextPhase("waiting", "a", { ok: true, bootId: "a" }, 1000, 60000)).toBe("waiting");
    expect(nextPhase("waiting", "a", { ok: false }, 1000, 60000)).toBe("offline");
    expect(nextPhase("offline", "a", { ok: false }, 70000, 60000)).toBe("timeout");
    expect(nextPhase("timeout", "a", { ok: true, bootId: "b" }, 90000, 60000)).toBe("back");
    expect(nextPhase("offline", "a", { ok: true, bootId: "a" }, 2000, 60000)).toBe("offline");
  });
});
