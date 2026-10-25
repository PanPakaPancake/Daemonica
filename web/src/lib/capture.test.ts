import { describe, expect, it } from "vitest";
import { exprAllowed, filterPreview, parsePorts, templateBuilder } from "./capture";

describe("capture filter preview", () => {
  it("mirrors the server builder", () => {
    expect(filterPreview({ builder: { proto: "tcp", host: "10.0.0.0/8", ports: [22, 443], dir: "dst" } }, 8443)).toBe(
      "tcp and dst net 10.0.0.0/8 and (dst port 22 or dst port 443) and not (tcp port 8443)",
    );
    expect(filterPreview({ builder: { proto: "icmp", host: "192.0.2.1" }, include_dashboard: true }, 8443)).toBe("(icmp or icmp6) and host 192.0.2.1");
    expect(filterPreview({ builder: templateBuilder("dns") }, 8443)).toBe("udp and (port 53) and not (tcp port 8443)");
    expect(filterPreview({ builder: {}, expr: "  udp   port 53 " }, 0)).toBe("(udp port 53)");
    expect(filterPreview({ builder: {} }, 0)).toBe("");
  });

  it("parses ports", () => {
    expect(parsePorts("53, 67 68")).toEqual([53, 67, 68]);
    expect(parsePorts("")).toEqual([]);
    expect(parsePorts("0")).toBeUndefined();
    expect(parsePorts("80;id")).toBeUndefined();
    expect(parsePorts("1 2 3 4 5 6 7 8 9 10 11")).toBeUndefined();
  });

  it("applies the expression allowlist", () => {
    expect(exprAllowed("tcp port 80 and not net 10.0.0.0/8")).toBe(true);
    expect(exprAllowed("tcp[13] & 2 != 0")).toBe(true);
    for (const bad of ["-w /etc/passwd", "; id", "$(id)", "`id`", "port 80 'x'", "a\\b"]) expect(exprAllowed(bad)).toBe(false);
  });
});
