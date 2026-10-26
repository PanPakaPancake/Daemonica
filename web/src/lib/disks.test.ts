import { describe, expect, it } from "vitest";
import { addOptions, critical, entryFor, flatten, mountable, type Block } from "./disks";

const part: Block = {
  name: "sdb1",
  path: "/dev/sdb1",
  type: "part",
  size: 10,
  fstype: "ext4",
  uuid: "u-1",
  mountpoints: [],
  ro: false,
  rm: false,
  rota: false,
};

describe("disks helpers", () => {
  it("flattens the tree with depth", () => {
    const rows = flatten([{ ...part, name: "sdb", path: "/dev/sdb", type: "disk", fstype: undefined, children: [part] }]);
    expect(rows.map((r) => [r.path, r.depth])).toEqual([
      ["/dev/sdb", 0],
      ["/dev/sdb1", 1],
    ]);
  });

  it("option templates", () => {
    expect(addOptions("defaults", "nofail")).toBe("nofail");
    expect(addOptions("defaults,nofail", "noexec,nosuid,nodev")).toBe("nofail,noexec,nosuid,nodev");
    expect(addOptions("", "defaults")).toBe("defaults");
    expect(addOptions("ro", "ro")).toBe("ro");
  });

  it("entries for devices", () => {
    expect(entryFor(part, "/srv/data")).toEqual({ spec: "UUID=u-1", file: "/srv/data", type: "ext4", options: "defaults,nofail", freq: 0, pass: 2, line: 0 });
    expect(entryFor({ ...part, fstype: "swap" }, "/x").file).toBe("none");
    expect(mountable(part)).toBe(true);
    expect(mountable({ ...part, fstype: "LVM2_member" })).toBe(false);
    expect(mountable({ ...part, mountpoints: ["/srv"] })).toBe(false);
  });

  it("critical mounts", () => {
    expect(critical("/")).toBe(true);
    expect(critical("/run/user/1000")).toBe(true);
    expect(critical("/srv/data")).toBe(false);
    expect(critical("/runner")).toBe(false);
  });
});
