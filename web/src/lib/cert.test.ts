import { describe, expect, it } from "vitest";
import { certTone, isStaging, relativeName, running, zoneGuess, type CertInfo, type Issuance } from "./cert";

const cert = (days: number, extra: Partial<CertInfo> = {}): CertInfo => ({ domain: "d.example.org", not_after: "", days_left: days, source: "own", ...extra });

describe("cert helpers", () => {
  it("knows running states", () => {
    const i = (state: Issuance["state"]): Issuance => ({ method: "dns-01", ca: "staging", state, started: "" });
    expect(running(i("dns_wait"))).toBe(true);
    expect(running(i("dns_check"))).toBe(true);
    expect(running(i("done"))).toBe(false);
    expect(running(undefined)).toBe(false);
  });

  it("rates remaining validity", () => {
    expect(certTone(cert(60), 30)).toBe("ok");
    expect(certTone(cert(29), 30)).toBe("warn");
    expect(certTone(cert(-1), 30)).toBe("bad");
    expect(certTone(undefined, 30)).toBe("bad");
  });

  it("detects staging certificates", () => {
    expect(isStaging(cert(60, { source: "acme-staging" }))).toBe(true);
    expect(isStaging(cert(60, { issuer: "(STAGING) Ersatz Edamame E1" }))).toBe(true);
    expect(isStaging(cert(60, { issuer: "E7" }))).toBe(false);
  });

  it("shortens record names to the zone", () => {
    expect(zoneGuess("daemonica.404squad.cloud")).toBe("404squad.cloud");
    expect(relativeName("_acme-challenge.daemonica.404squad.cloud", "404squad.cloud")).toBe("_acme-challenge.daemonica");
    expect(relativeName("_acme-challenge.other.net.", "404squad.cloud")).toBe("_acme-challenge.other.net");
  });
});
