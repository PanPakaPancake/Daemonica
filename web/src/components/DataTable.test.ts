import { describe, expect, it } from "vitest";
import { applyTable, filterKind, parseNumFilter, type Column } from "./DataTable";

interface Row {
  name: string;
  size?: number;
  state: string;
}

const cols: Column<Row>[] = [
  { key: "name", label: "Name", cell: (r) => r.name, sortValue: (r) => r.name, filter: "text" },
  { key: "size", label: "Size", cell: (r) => r.size, sortValue: (r) => r.size },
  { key: "state", label: "State", cell: (r) => r.state, sortValue: (r) => r.state, filter: { options: [] } },
];

const rows: Row[] = [
  { name: "file10", size: 3, state: "on" },
  { name: "file2", state: "off" },
  { name: "File1", size: 1, state: "on" },
];

const names = (rs: Row[]) => rs.map((r) => r.name);

describe("applyTable", () => {
  it("sorts naturally and case-insensitively", () => {
    expect(names(applyTable(rows, cols, { key: "name", desc: false }, {}))).toEqual(["File1", "file2", "file10"]);
    expect(names(applyTable(rows, cols, { key: "name", desc: true }, {}))).toEqual(["file10", "file2", "File1"]);
  });

  it("keeps empty values last in both directions", () => {
    expect(names(applyTable(rows, cols, { key: "size", desc: false }, {}))).toEqual(["File1", "file10", "file2"]);
    expect(names(applyTable(rows, cols, { key: "size", desc: true }, {}))).toEqual(["file10", "File1", "file2"]);
  });

  it("filters by substring and exact option", () => {
    expect(names(applyTable(rows, cols, null, { name: "FILE1" }))).toEqual(["file10", "File1"]);
    expect(names(applyTable(rows, cols, null, { state: "off" }))).toEqual(["file2"]);
    expect(names(applyTable(rows, cols, null, { name: "", state: "" }))).toEqual(names(rows));
  });
});

describe("parseNumFilter", () => {
  it("parses comparisons, ranges and units", () => {
    expect(parseNumFilter("10")).toEqual({ min: 10, max: Infinity });
    expect(parseNumFilter("<= 5")).toEqual({ min: -Infinity, max: 5 });
    expect(parseNumFilter("=0")).toEqual({ min: 0, max: 0 });
    expect(parseNumFilter("1K-2MiB", true)).toEqual({ min: 1024, max: 2 * 1024 ** 2 });
    expect(parseNumFilter("1,5G", true)?.min).toBe(1.5 * 1024 ** 3);
    for (const bad of ["", "abc", "-5", "2-1", ">1K-2K", "1K"]) expect(parseNumFilter(bad)).toBeNull();
  });
});

describe("inferred filters", () => {
  const now = Date.now();
  const rs = [
    { n: "a", size: 500, at: new Date(now - 2 * 86_400_000).toISOString() },
    { n: "b", size: 4096, at: new Date(now - 60 * 86_400_000).toISOString() },
    { n: "c", size: undefined, at: "" },
  ];
  const cs: Column<(typeof rs)[number]>[] = [
    { key: "n", label: "N", cell: (r) => r.n, sortValue: (r) => r.n },
    { key: "size", label: "S", cell: (r) => r.size, sortValue: (r) => r.size, filter: "bytes" },
    { key: "at", label: "A", cell: (r) => r.at, sortValue: (r) => r.at },
    { key: "x", label: "X", cell: () => null },
  ];
  const ns = (f: Record<string, string>) => applyTable(rs, cs, null, f).map((r) => r.n);

  it("infers kinds from values", () => {
    expect(cs.map((c) => filterKind(c, rs))).toEqual(["text", "bytes", "date", null]);
  });
  it("filters numbers, dates and ignores invalid input", () => {
    expect(ns({ size: ">1K" })).toEqual(["b"]);
    expect(ns({ size: "<1K" })).toEqual(["a"]);
    expect(ns({ size: "foo" })).toEqual(["a", "b", "c"]);
    expect(ns({ at: "7d" })).toEqual(["a"]);
    expect(ns({ at: "-30d" })).toEqual(["b"]);
  });
});
