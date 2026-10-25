import { describe, expect, it } from "vitest";
import { applyTable, type Column } from "./DataTable";

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
