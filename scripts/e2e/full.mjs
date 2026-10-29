// End-to-end test of a fresh installation (SPEC §6.4, M1.8): setup wizard with
// an own certificate, first passkey, every module page, step-up, invitations,
// role checks, logout and passkey login. Passkeys come from Chromium's virtual
// WebAuthn authenticator (CDP); the domain is mapped to 127.0.0.1, so loopback
// access is enough and nothing leaves the host.
//
// Needs a freshly installed, not yet set up Daemonica on this host, root (for
// daemonica-admin), openssl and Playwright with Chromium. Usage on the VM:
//   sudo E2E_USERS=alice,bob,carol node scripts/e2e/full.mjs /root/e2e/out
// Environment:
//   E2E_DOMAIN   dashboard domain for the test (default e2e.daemonica.test)
//   E2E_PORT     port (default 8443)
//   E2E_USERS    three normal Linux users for admin, operator, read-only
//   E2E_STRICT=1 also fail on error notices and API 5xx answers (on a real host
//                every page must load; a container without systemd cannot)
//   DAEMONICA_ADMIN_SOCKET  passed to daemonica-admin (local test stacks)
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// require() honours NODE_PATH, so a global Playwright installation works too.
const { chromium } = createRequire(import.meta.url)("playwright");

const out = process.argv[2] ?? "e2e-out";
mkdirSync(out, { recursive: true });
const DOMAIN = process.env.E2E_DOMAIN ?? "e2e.daemonica.test";
const PORT = Number(process.env.E2E_PORT ?? 8443);
const [ADMIN_USER, OP_USER, VIEW_USER] = (process.env.E2E_USERS ?? "e2eadmin,e2eop,e2eview").split(",");
const STRICT = process.env.E2E_STRICT === "1";
const SETUP = `https://127.0.0.1:${PORT}`;
const BASE = `https://${DOMAIN}:${PORT}`;
const ADMIN_BIN = process.env.DAEMONICA_ADMIN ?? "daemonica-admin";

const results = [];
const started = Date.now();
let current, currentErrors; // page of the running step, for a screenshot on failure
async function step(name, fn) {
  const t0 = Date.now();
  try {
    const detail = await fn();
    results.push({ name, ok: true, ms: Date.now() - t0, ...(detail ? { detail } : {}) });
    console.log(`✓ ${name}`);
  } catch (e) {
    results.push({ name, ok: false, ms: Date.now() - t0, error: String(e?.message ?? e).slice(0, 2000) });
    console.log(`✗ ${name}: ${e?.message ?? e}`);
    if (currentErrors?.length) console.log(currentErrors.slice(-10).join("\n"));
    await current?.screenshot({ path: join(out, `fail-${results.length}.png`), fullPage: true }).catch(() => undefined);
    throw e;
  }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- certificate: own CA + ECDSA P-256 leaf for DOMAIN (SPEC §3.6 "eigenes Zertifikat") ---
function makeCert() {
  const d = mkdtempSync(join(tmpdir(), "daemonica-e2e-"));
  const sh = (...a) => execFileSync("openssl", a, { cwd: d, stdio: ["ignore", "pipe", "pipe"] });
  sh("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key");
  sh("req", "-x509", "-new", "-key", "ca.key", "-sha256", "-days", "2", "-subj", "/CN=Daemonica E2E CA", "-out", "ca.pem");
  sh("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "leaf.key");
  sh("req", "-new", "-key", "leaf.key", "-subj", `/CN=${DOMAIN}`, "-out", "leaf.csr");
  writeFileSync(join(d, "ext.cnf"), `subjectAltName=DNS:${DOMAIN}\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n`);
  sh(
    "x509",
    "-req",
    "-in",
    "leaf.csr",
    "-CA",
    "ca.pem",
    "-CAkey",
    "ca.key",
    "-CAcreateserial",
    "-days",
    "2",
    "-sha256",
    "-extfile",
    "ext.cnf",
    "-out",
    "leaf.pem",
  );
  // SPKI hash of the leaf: Chromium then treats the certificate as valid
  // (WebAuthn refuses origins with certificate errors).
  const pub = sh("x509", "-in", "leaf.pem", "-pubkey", "-noout");
  const der = execFileSync("openssl", ["pkey", "-pubin", "-outform", "der"], { input: pub });
  const spki = execFileSync("openssl", ["dgst", "-sha256", "-binary"], { input: der }).toString("base64");
  const cert = readFileSync(join(d, "leaf.pem"), "utf8") + readFileSync(join(d, "ca.pem"), "utf8");
  // The upload expects "EC PRIVATE KEY" or PKCS#8; openssl ecparam writes SEC1.
  return { cert, key: readFileSync(join(d, "leaf.key"), "utf8"), spki, ca: join(d, "ca.pem") };
}

function bootstrapToken() {
  const txt = execFileSync(ADMIN_BIN, ["bootstrap"], { encoding: "utf8", env: process.env });
  const m = txt.match(/^\s{4}(\S{20,})$/m);
  if (!m) throw new Error("no token in daemonica-admin output");
  return m[1];
}

const certs = makeCert();
const browser = await chromium.launch({
  args: ["--no-proxy-server", `--host-resolver-rules=MAP ${DOMAIN} 127.0.0.1`, `--ignore-certificate-errors-spki-list=${certs.spki}`],
});

/** A browser context with its own virtual passkey authenticator. */
async function actor(label, { insecure = false } = {}) {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: insecure, viewport: { width: 1440, height: 900 }, locale: "de-DE" });
  const page = await ctx.newPage();
  current = page;
  // errors: script errors (always a failure); api: API answers >= 400 (kept for
  // the report; the module check fails on 5xx only with E2E_STRICT=1, since
  // a container without systemd answers several system pages with 500).
  const errors = [];
  const api = [];
  currentErrors = errors;
  page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource|status of (4|5)\d\d/.test(m.text())) errors.push(m.text());
  });
  page.on("response", async (r) => {
    if (r.status() >= 400 && r.url().includes("/api/"))
      api.push({
        status: r.status(),
        text: `${r.request().method()} ${new URL(r.url()).pathname} → ${r.status()} ${(await r.text().catch(() => "")).slice(0, 200)}`,
      });
  });
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const credentials = async () => (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials;
  return { label, ctx, page, errors, api, credentials };
}

/** API call from the page (session cookie + CSRF header like the app). */
async function call(page, method, path, body) {
  return page.evaluate(
    async ([method, path, body]) => {
      const r = await fetch(`/api/v1${path}`, {
        method,
        headers: { Accept: "application/json", ...(method !== "GET" && { "X-Daemonica-CSRF": "1" }), ...(body && { "Content-Type": "application/json" }) },
        body: body ? JSON.stringify(body) : undefined,
      });
      let code = "";
      try {
        code = (await r.clone().json()).code ?? "";
      } catch {
        /* not JSON */
      }
      return { status: r.status, code };
    },
    [method, path, body],
  );
}

async function waitFor(url, ms = 60_000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    try {
      // Verified against the test CA: the setup-mode listener (self-signed) does not count.
      execFileSync("curl", [
        "-s",
        "--cacert",
        certs.ca,
        "--noproxy",
        "*",
        "--max-time",
        "3",
        "--resolve",
        `${DOMAIN}:${PORT}:127.0.0.1`,
        "-o",
        "/dev/null",
        url,
      ]);
      return;
    } catch {
      await sleep(1000);
    }
  }
  throw new Error(`${url} not reachable`);
}

const shot = (page, name) => page.screenshot({ path: join(out, `${name}.png`), fullPage: true });
const btn = (page, name) => page.getByRole("button", { name, exact: false });

let admin,
  invites = {};
try {
  const token = bootstrapToken();

  await step("Setup: Token, Domain, Allowlist, eigenes Zertifikat (Loopback)", async () => {
    const a = await actor("setup", { insecure: true });
    const p = a.page;
    await p.goto(`${SETUP}/setup`);
    await p.getByLabel("Einrichtungs-Token").fill(token);
    await btn(p, "Weiter").click();
    await p.getByLabel("Domain des Dashboards").fill(DOMAIN);
    await p.getByLabel("Port").fill(String(PORT));
    await btn(p, "Weiter").click();
    await p.getByLabel(/Erlaubte Netze/).fill("192.0.2.0/24");
    await btn(p, "Weiter").click();
    await p.getByText("Eigenes Zertifikat hochladen").click();
    await p.getByLabel("Zertifikatskette (PEM)").fill(certs.cert);
    await p.getByLabel(/Privater Schlüssel/).fill(certs.key);
    await btn(p, "Zertifikat übernehmen").click();
    await p.getByText("Wechsel auf die endgültige Adresse").waitFor({ timeout: 30_000 });
    await shot(p, "01-setup-switch");
    await a.ctx.close();
  });

  await step("Dienst wechselt auf die Domain", async () => {
    await waitFor(`${BASE}/api/v1/setup/state`);
  });

  admin = await actor("admin", { insecure: true });
  await step("Erster Passkey auf der Domain (virtueller Authenticator)", async () => {
    const p = admin.page;
    await p.goto(`${BASE}/setup`);
    await p.getByLabel("Einrichtungs-Token").fill(token);
    await btn(p, "Weiter").click();
    await p.getByLabel("Kontoname").fill("e2e-admin");
    await p.getByLabel("Zugeordneter Linux-Benutzer").selectOption(ADMIN_USER);
    await p.getByLabel(/Name des Passkeys/).fill("virtuell");
    await btn(p, "Passkey registrieren").click();
    await p.getByText("Geschafft!").waitFor({ timeout: 30_000 });
    if ((await admin.credentials()).length !== 1) throw new Error("no resident credential");
    await shot(p, "02-setup-done");
  });

  await step("Bootstrap-Token ist verbraucht", async () => {
    const r = await call(admin.page, "POST", "/setup/token", { token });
    if (r.status < 400) throw new Error(`token accepted again: ${r.status}`);
  });

  const pages = [
    "/",
    "/services",
    "/jobs",
    "/users",
    "/ssh-keys",
    "/network",
    "/firewall",
    "/updates",
    "/disks",
    "/timehost",
    "/terminal",
    "/files",
    "/logs",
    "/processes",
    "/capture",
    "/security/passkeys",
    "/security/sessions",
    "/security/accounts",
    "/security/audit",
    "/security/settings",
  ];
  await step("Alle Module als Admin laden", async () => {
    const p = admin.page;
    const problems = [];
    const notes = [];
    for (const path of pages) {
      const before = admin.errors.length;
      const apiBefore = admin.api.length;
      await p.goto(`${BASE}${path}`);
      await p.waitForLoadState("networkidle", { timeout: 15_000 }).catch(() => undefined);
      await sleep(400);
      const name = path === "/" ? "overview" : path.slice(1).replaceAll("/", "-");
      await shot(p, `10-${name}`);
      if (await p.getByText("Seite nicht gefunden").count()) problems.push(`${path}: not found`);
      const alerts = await p.getByRole("alert").allInnerTexts();
      if (STRICT && alerts.length) problems.push(`${path}: ${alerts.join(" | ").slice(0, 300)}`);
      if (admin.errors.length > before) problems.push(`${path}: ${admin.errors.slice(before).join(" | ").slice(0, 300)}`);
      const failedApi = admin.api.slice(apiBefore).filter((x) => x.status >= 500);
      if (failedApi.length)
        (STRICT ? problems : notes).push(
          `${path}: ${failedApi
            .map((x) => x.text)
            .join(" | ")
            .slice(0, 300)}`,
        );
    }
    if (problems.length) throw new Error(problems.join("\n"));
    return { pages: pages.length, notes };
  });

  await step("Step-up mit Passkey (Einladung Operator)", async () => {
    const p = admin.page;
    await p.goto(`${BASE}/security/accounts`);
    for (const [role, user, label] of [
      ["operator", OP_USER, "Operator"],
      ["readonly", VIEW_USER, "Nur-Lesen"],
    ]) {
      await p.getByLabel("Name", { exact: true }).fill(`e2e-${role}`);
      await p.getByLabel("Rolle", { exact: true }).selectOption({ label });
      await p.getByLabel("Linux-Benutzer", { exact: true }).selectOption({ value: user });
      await btn(p, "Einladen").click();
      // The first changing call asks for step-up; later ones within 5 minutes do not.
      const code = p.locator("code", { hasText: "/invite#token=" }).first();
      const stepUp = p.getByRole("dialog").filter({ hasText: "Mit Passkey bestätigen" });
      await code.or(stepUp).first().waitFor({ timeout: 20_000 });
      if (await stepUp.count()) await stepUp.getByRole("button", { name: "Bestätigen" }).click();
      const link = await code.innerText({ timeout: 20_000 });
      invites[role] = link.trim();
      await btn(p, "Schließen")
        .click()
        .catch(() => undefined);
    }
    await shot(p, "20-accounts-invited");
  });

  const roleChecks = {
    // [method, path, body, allowed]
    operator: [
      ["GET", "/system/overview", undefined, true],
      ["POST", "/journal/query", { lines: 5 }, true],
      ["GET", "/accounts", undefined, false],
      ["GET", "/settings", undefined, false],
      ["POST", "/audit/query", {}, false],
    ],
    readonly: [
      ["GET", "/system/overview", undefined, true],
      ["POST", "/journal/query", { lines: 5 }, false],
      ["GET", "/accounts", undefined, false],
      ["POST", "/processes/signal", { pid: 1, signal: "TERM" }, false],
      ["GET", "/settings", undefined, false],
    ],
  };

  for (const role of ["operator", "readonly"]) {
    await step(`Einladung annehmen und Rollen prüfen: ${role}`, async () => {
      const a = await actor(role);
      const p = a.page;
      await p.goto(invites[role].replace(/^https:\/\/[^/]+/, BASE));
      await p.getByLabel(/Name des Passkeys/).fill("virtuell");
      await btn(p, "Passkey registrieren und anmelden").click();
      await p.waitForURL((u) => !u.pathname.startsWith("/invite"), { timeout: 30_000 });
      await sleep(800);
      await shot(p, `30-${role}-home`);
      const wrong = [];
      for (const [m, path, body, allowed] of roleChecks[role]) {
        const r = await call(p, m, path, body);
        const denied = r.status === 403 && r.code !== "step_up_required";
        if (allowed === denied) wrong.push(`${m} ${path}: ${r.status} ${r.code}`);
      }
      const nav = await p.getByRole("navigation").innerText();
      if (role === "readonly" && /Terminal|Dateien|Logs/.test(nav)) wrong.push("read-only sees terminal/files/logs in the navigation");
      if (/Konten|Audit-Log|Einstellungen/.test(nav)) wrong.push(`${role} sees admin navigation`);
      await a.ctx.close();
      if (wrong.length) throw new Error(wrong.join("\n"));
    });
  }

  await step("Abmelden und mit Passkey wieder anmelden", async () => {
    const p = admin.page;
    await p.goto(`${BASE}/`);
    await btn(p, "Abmelden")
      .first()
      .click()
      .catch(async () => call(p, "POST", "/auth/logout"));
    await p.goto(`${BASE}/login`);
    await btn(p, "Mit Passkey anmelden").click();
    await p.waitForURL((u) => u.pathname === "/", { timeout: 30_000 });
    const r = await call(p, "GET", "/session");
    if (r.status !== 200) throw new Error(`session ${r.status}`);
  });

  await step("Ohne Sitzung ist keine API erreichbar", async () => {
    const a = await actor("anon");
    await a.page.goto(`${BASE}/login`);
    const bad = [];
    for (const path of ["/system/overview", "/services", "/accounts", "/settings", "/files/info"]) {
      const r = await call(a.page, "GET", path);
      if (r.status !== 401) bad.push(`${path}: ${r.status}`);
    }
    await a.ctx.close();
    if (bad.length) throw new Error(bad.join(", "));
  });
} catch {
  // reported below
} finally {
  await browser.close();
  const failed = results.filter((r) => !r.ok).length;
  const report = {
    started: new Date(started).toISOString(),
    seconds: Math.round((Date.now() - started) / 1000),
    domain: DOMAIN,
    strict: STRICT,
    passed: results.length - failed,
    failed,
    results,
  };
  writeFileSync(join(out, "report.json"), JSON.stringify(report, null, 2));
  console.log(`\n${report.passed} passed, ${failed} failed → ${join(out, "report.json")}`);
  process.exit(failed ? 1 : 0);
}
