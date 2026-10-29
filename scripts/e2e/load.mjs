// Base load and idle memory (SPEC §6 "Nicht-funktional", M1.8): N parallel
// sessions poll like open dashboards, each logged in with a real passkey
// assertion (signed here with the private key exported from the virtual
// authenticator) and from its own loopback address (127.0.0.x), as the login
// rate limit is per client IP. Measures latency, failures and the resident
// memory of the web process before, during and after the load.
import { createHash, createPrivateKey, sign } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { Agent, request } from "node:https";

const b64url = (b) => Buffer.from(b).toString("base64url");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Polling profile of an open dashboard tab (intervals from the pages' refetchInterval). */
const profiles = [
  ["/system/overview", 3000],
  ["/processes", 3000],
  ["/network", 10_000],
  ["/firewall", 10_000],
  ["/jobs", 15_000],
  ["/session", 60_000],
];

/** Resident memory in MiB of the processes named comm (first match). */
export function rssMiB(comm) {
  for (const pid of readdirSync("/proc").filter((d) => /^\d+$/.test(d))) {
    try {
      if (readFileSync(`/proc/${pid}/comm`, "utf8").trim() !== comm) continue;
      const kb = Number(/VmRSS:\s+(\d+)/.exec(readFileSync(`/proc/${pid}/status`, "utf8"))?.[1] ?? 0);
      return Math.round((kb / 1024) * 10) / 10;
    } catch {
      /* process gone */
    }
  }
  return undefined;
}

class Client {
  constructor({ domain, port, ca, localAddress }) {
    this.origin = `https://${domain}:${port}`;
    this.opts = { host: "127.0.0.1", port, servername: domain, ca, agent: new Agent({ keepAlive: true, maxSockets: 2, localAddress }) };
    this.cookie = "";
  }

  call(method, path, body) {
    const data = body === undefined ? undefined : JSON.stringify(body);
    const headers = { Accept: "application/json", Host: `${this.origin.slice(8)}` };
    if (this.cookie) headers.Cookie = this.cookie;
    if (method !== "GET") Object.assign(headers, { "X-Daemonica-CSRF": "1", Origin: this.origin });
    if (data) Object.assign(headers, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) });
    const t0 = performance.now();
    return new Promise((resolve) => {
      const req = request({ ...this.opts, method, path: `/api/v1${path}`, headers, timeout: 30_000 }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const set = res.headers["set-cookie"];
          if (set) this.cookie = set.map((c) => c.split(";")[0]).join("; ");
          let json;
          try {
            json = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          } catch {
            /* not JSON */
          }
          resolve({ status: res.statusCode, json, ms: performance.now() - t0 });
        });
      });
      req.on("timeout", () => req.destroy(new Error("timeout")));
      req.on("error", (e) => resolve({ status: 0, error: e.message, ms: performance.now() - t0 }));
      req.end(data);
    });
  }

  close() {
    this.opts.agent.destroy();
  }
}

/** Passkey login with an assertion signed by the exported credential. */
async function login(client, cred, counter) {
  const begin = await client.call("POST", "/auth/login/begin", {});
  if (begin.status !== 200) throw new Error(`login/begin ${begin.status} ${begin.json?.code ?? begin.error ?? ""}`);
  const challenge = begin.json.options.publicKey.challenge;
  const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge, origin: client.origin, crossOrigin: false }));
  const flags = 0x01 | 0x04; // user present, user verified
  const authData = Buffer.alloc(37);
  createHash("sha256").update(cred.rpId).digest().copy(authData, 0);
  authData[32] = flags;
  authData.writeUInt32BE(counter, 33);
  const toSign = Buffer.concat([authData, createHash("sha256").update(clientData).digest()]);
  const signature = sign("sha256", toSign, cred.key); // DER-encoded ECDSA, as WebAuthn expects
  const id = b64url(Buffer.from(cred.credentialId, "base64"));
  const response = {
    id,
    rawId: id,
    type: "public-key",
    clientExtensionResults: {},
    response: {
      clientDataJSON: b64url(clientData),
      authenticatorData: b64url(authData),
      signature: b64url(signature),
      userHandle: b64url(Buffer.from(cred.userHandle, "base64")),
    },
  };
  const fin = await client.call("POST", "/auth/login/finish", { ceremony_id: begin.json.ceremony_id, response });
  if (fin.status !== 200 || !client.cookie) throw new Error(`login/finish ${fin.status} ${fin.json?.code ?? fin.error ?? ""}`);
}

const pct = (sorted, p) => (sorted.length ? Math.round(sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))]) : 0);

/**
 * Runs the load. credential is one entry of WebAuthn.getCredentials (CDP).
 * Returns the measurements; the caller decides about pass/fail.
 */
export async function runLoad({ domain, port, ca, credential, sessions = 50, seconds = 120, idleSeconds = 60, log = () => undefined }) {
  const cred = { ...credential, key: createPrivateKey({ key: Buffer.from(credential.privateKey, "base64"), format: "der", type: "pkcs8" }) };
  let counter = (credential.signCount ?? 0) + 1;
  const caPem = readFileSync(ca);
  const mem = { idleBefore: rssMiB("daemonica-web"), helperBefore: rssMiB("daemonica-helpe") };

  // Logins one after the other: the sign counter must rise (clone detection).
  const clients = [];
  const t0 = Date.now();
  for (let i = 0; i < sessions; i++) {
    const c = new Client({ domain, port, ca: caPem, localAddress: `127.0.0.${10 + i}` });
    await login(c, cred, counter++);
    clients.push(c);
  }
  const loginSeconds = (Date.now() - t0) / 1000;
  log(`${sessions} Sitzungen angemeldet (${loginSeconds.toFixed(1)} s)`);

  const lat = {};
  const failures = {};
  let requests = 0;
  let peak = 0;
  const end = Date.now() + seconds * 1000;
  const poll = async (c, path, every) => {
    await sleep(Math.random() * every); // spread like tabs opened at different times
    while (Date.now() < end) {
      const next = Date.now() + every;
      const r = await c.call("GET", path);
      requests++;
      (lat[path] ??= []).push(r.ms);
      if (r.status !== 200) {
        const k = `${path} → ${r.status || r.error}`;
        failures[k] = (failures[k] ?? 0) + 1;
      }
      await sleep(Math.max(0, next - Date.now()));
    }
  };
  const sampler = setInterval(() => (peak = Math.max(peak, rssMiB("daemonica-web") ?? 0)), 1000);
  // Every session shows the overview; a third of them also the process list
  // and the network/firewall/jobs pages (tabs left open on other modules).
  await Promise.all(
    clients.flatMap((c, i) => profiles.filter(([p]) => p === "/system/overview" || p === "/session" || i % 3 === 0).map(([p, every]) => poll(c, p, every))),
  );
  clearInterval(sampler);
  mem.underLoadPeak = peak;

  for (const c of clients) {
    await c.call("POST", "/auth/logout");
    c.close();
  }
  log(`Last beendet, ${idleSeconds} s Leerlauf`);
  await sleep(idleSeconds * 1000);
  mem.idleAfter = rssMiB("daemonica-web");
  mem.helperAfter = rssMiB("daemonica-helpe");

  const all = Object.values(lat)
    .flat()
    .sort((a, b) => a - b);
  const perPath = Object.fromEntries(
    Object.entries(lat).map(([p, v]) => {
      const s = [...v].sort((a, b) => a - b);
      return [p, { n: s.length, p50: pct(s, 50), p95: pct(s, 95), max: Math.round(s.at(-1) ?? 0) }];
    }),
  );
  return {
    sessions,
    seconds,
    loginSeconds: Math.round(loginSeconds * 10) / 10,
    requests,
    rps: Math.round((requests / seconds) * 10) / 10,
    failed: Object.values(failures).reduce((a, b) => a + b, 0),
    failures,
    latencyMs: { p50: pct(all, 50), p95: pct(all, 95), p99: pct(all, 99), max: Math.round(all.at(-1) ?? 0) },
    perPath,
    memoryMiB: mem,
  };
}
