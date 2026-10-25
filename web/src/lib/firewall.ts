import type { TFunction } from "i18next";

/** One ufw rule as returned by GET /firewall. */
export interface Rule {
  num: number;
  v6: boolean;
  action: "allow" | "deny" | "reject" | "limit";
  log?: string;
  direction: "in" | "out" | "route";
  iface?: string;
  out_iface?: string;
  proto: string;
  dport: string;
  sport: string;
  dst: string;
  src: string;
  app?: string;
  sapp?: string;
  comment?: string;
  managed: boolean;
  packets: number;
  bytes: number;
  counted: boolean;
}
/** Plain-language explanation of a rule ("Erlaubt eingehend TCP 22 von überall"). */
export function explainRule(t: TFunction, r: Rule): string {
  const what = r.app
    ? t("firewall.explain.app", { app: r.app, ports: r.dport })
    : [r.proto === "any" ? "" : r.proto.toUpperCase(), r.dport === "any" ? t("firewall.explain.allPorts") : t("firewall.explain.port", { port: r.dport })]
        .filter(Boolean)
        .join(" ");
  const parts = [
    t(`firewall.explain.action.${r.action}`),
    t(`firewall.dir.${r.direction}`),
    what,
    r.src === "any" ? t("firewall.explain.fromAny") : t("firewall.explain.from", { src: r.src }),
  ];
  if (r.sport !== "any" && r.sport) parts.push(t("firewall.explain.sport", { port: r.sport }));
  if (r.dst !== "any") parts.push(t("firewall.explain.to", { dst: r.dst }));
  if (r.iface) parts.push(t("firewall.explain.iface", { iface: r.iface }));
  if (r.out_iface) parts.push(t("firewall.explain.outIface", { iface: r.out_iface }));
  if (r.log) parts.push(t("firewall.explain.logged"));
  return parts.join(" ");
}
