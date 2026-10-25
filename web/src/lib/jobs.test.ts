import { describe as suite, expect, it } from "vitest";
import { cleanPath, duplicate, joinArgs, noControl, slug, splitArgs, type Job } from "./jobs";

suite("jobs helpers", () => {
  it("splits and joins arguments without expansion", () => {
    expect(splitArgs(`-a "b c" 'd e' $HOME ; %n`)).toEqual(["-a", "b c", "d e", "$HOME", ";", "%n"]);
    expect(splitArgs(`""`)).toEqual([""]);
    expect(splitArgs(`"a \\" b"`)).toEqual([`a " b`]);
    expect(splitArgs(`"open`)).toBeUndefined();
    for (const a of [
      ["x", "y z", "", `q"t`, "back\\slash"],
      [";", "rm", "-rf"],
    ])
      expect(splitArgs(joinArgs(a))).toEqual(a);
  });

  it("checks paths and text like the server", () => {
    expect(cleanPath("/usr/local/bin/backup.sh")).toBe(true);
    for (const p of ["relative", "/a b", "/usr/../bin", "/a//b", "/a/", "/%n", "/a\nb"]) expect(cleanPath(p)).toBe(false);
    expect(noControl("a\nb")).toBe(false);
    expect(noControl("ä 100% ok")).toBe(true);
  });

  it("suggests ids and duplicates", () => {
    expect(slug("Nächtliches Backup – /var/www")).toBe("nachtliches-backup-var-www");
    expect(slug("Größe prüfen")).toBe("grosse-prufen");
    const j: Job = {
      id: "backup",
      mode: "exec",
      program: "/bin/true",
      user: "root",
      schedule: { kind: "daily", time: "02:00" },
      hardening: "safe",
      enabled: true,
      created: "x",
    };
    const d = duplicate(j, ["backup", "backup-2"]);
    expect(d.id).toBe("backup-3");
    expect(d.enabled).toBe(false);
    expect(d.created).toBeUndefined();
    expect(duplicate(d, ["backup-3"]).id).toBe("backup-2");
  });
});
