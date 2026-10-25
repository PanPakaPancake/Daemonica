import { describe, expect, it } from "vitest";
import { fromCron, toCron, type CronDraft } from "./cron";

describe("cron schedule builder", () => {
  it("round-trips the builder choices", () => {
    for (const e of [
      "5 * * * *",
      "30 2 * * *",
      "0 7 * * 1,2,3,4,5",
      "15 22 * * 1,0",
      "0 4 31 * *",
      "*/15 * * * *",
      "* * * * *",
      "10 */6 * * *",
      "0 * * * *",
      "@reboot",
    ]) {
      const d = fromCron(e);
      expect(d.kind).not.toBe("custom");
      expect(toCron(d)).toBe(e);
    }
  });

  it("reads shortcuts and keeps everything else as a custom expression", () => {
    expect(fromCron("@daily")).toMatchObject({ kind: "daily", time: "00:00" });
    expect(fromCron("0 7 * * 1-5")).toMatchObject({ kind: "weekly", weekdays: ["Mon", "Tue", "Wed", "Thu", "Fri"] });
    expect(fromCron("0 7 * * 7").weekdays).toEqual(["Sun"]);
    for (const e of ["0 3 * 1 *", "*/7 * * * *", "0 0 1,15 * *", "0 0 * * mon", "@yearly", "1 2 3"]) {
      const d = fromCron(e);
      expect(d.kind).toBe("custom");
      expect(toCron(d)).toBe(e);
    }
  });

  it("builds expressions from the form", () => {
    const d: CronDraft = { kind: "weekly", minute: 0, time: "06:30", weekdays: ["Sun", "Mon"], day: 1, every: 15, unit: "min", expr: "" };
    expect(toCron(d)).toBe("30 6 * * 1,0");
    expect(toCron({ ...d, kind: "interval", unit: "h", every: 1, minute: 5 })).toBe("5 * * * *");
    expect(toCron({ ...d, kind: "monthly", day: 15 })).toBe("30 6 15 * *");
  });
});
