import i18next from "i18next";
import { beforeAll, describe, expect, it } from "vitest";
import de from "../locales/de.json";
import en from "../locales/en.json";
import { explainRule, type Rule } from "./firewall";

const rule = (o: Partial<Rule>): Rule => ({
  num: 1,
  v6: false,
  action: "allow",
  direction: "in",
  proto: "tcp",
  dport: "22",
  sport: "any",
  dst: "any",
  src: "any",
  managed: false,
  packets: 0,
  bytes: 0,
  counted: false,
  ...o,
});

describe("explainRule", () => {
  const i = i18next.createInstance();
  beforeAll(() => i.init({ lng: "de", interpolation: { escapeValue: false }, resources: { de: { translation: de }, en: { translation: en } } }));

  it("explains rules in plain language", () => {
    const t = i.getFixedT("de");
    expect(explainRule(t, rule({}))).toBe("Erlaubt eingehend TCP 22 von überall");
    expect(explainRule(t, rule({ action: "limit", dport: "2222", iface: "eth0" }))).toBe("Erlaubt begrenzt eingehend TCP 2222 von überall über eth0");
    expect(explainRule(t, rule({ action: "reject", proto: "any", dport: "any", src: "203.0.113.66" }))).toBe("Weist ab eingehend alle Ports von 203.0.113.66");
    expect(explainRule(t, rule({ action: "deny", direction: "out", proto: "udp", dport: "53", dst: "10.0.0.1", log: "log" }))).toBe(
      "Verwirft ausgehend UDP 53 von überall an 10.0.0.1 (protokolliert)",
    );
    expect(explainRule(t, rule({ app: "OpenSSH" }))).toBe("Erlaubt eingehend Profil OpenSSH (Port 22) von überall");
    expect(explainRule(i.getFixedT("en"), rule({ dport: "80,443", src: "10.0.0.0/8" }))).toBe("Allows incoming TCP 80,443 from 10.0.0.0/8");
  });
});
