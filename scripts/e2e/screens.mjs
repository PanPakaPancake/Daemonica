// Screenshot smoke test with fixture data (real host data dumped by the
// integration test, served through Playwright route mocks). Detects CSP and
// runtime errors on every page. Usage on the test VM:
//   DUMP_DIR=/root/e2e/fx go test -tags integration -run TestDumpFixtures ./test/integration/
//   node scripts/e2e/screens.mjs /root/e2e/fx /root/e2e/out
import { chromium } from "playwright";
import { mkdirSync, readFileSync } from "node:fs";

const [fxDir, outDir] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const fx = (n) => readFileSync(`${fxDir}/${n}.json`, "utf8");
const base = process.env.BASE ?? "https://127.0.0.1:8443";
const b = await chromium.launch();
const results = [];

async function shot(name, path, { width = 1440, height = 900, after, theme = "dark", rootMode = false } = {}) {
  const ctx = await b.newContext({ ignoreHTTPSErrors: true, viewport: { width, height }, colorScheme: theme });
  const p = await ctx.newPage();
  if (theme === "light") await p.addInitScript(() => localStorage.setItem("daemonica.theme", "light"));
  const errs = [];
  p.on("console", (m) => m.type() === "error" && errs.push(m.text()));
  p.on("pageerror", (e) => errs.push(e.message));
  const json = (body) => (r) => r.fulfill({ contentType: "application/json", body });
  const routes = {
    "**/api/v1/session": JSON.stringify({ account_id: "x", role: "admin", linux_user: "pancake", step_up: false }),
    "**/api/v1/setup/state": JSON.stringify({ setup_done: true, language: "de" }),
    "**/api/v1/passkeys": "[{},{}]",
    "**/api/v1/system/overview": fx("overview"),
    "**/api/v1/services": fx("services"),
    "**/api/v1/journal/query": fx("journal"),
    "**/api/v1/processes": fx("processes"),
    "**/api/v1/users/list": fx("users"),
    "**/api/v1/ssh-keys/list": fx("sshkeys"),
    "**/api/v1/ssh-keys/server": fx("sshserver"),
    "**/api/v1/services/get": JSON.stringify({ name: "ssh.service", type: "service", description: "OpenBSD Secure Shell server", load: "loaded", active: "active", sub: "running", file_state: "enabled", protected: true, fragment_path: "/usr/lib/systemd/system/ssh.service", unit_file: "[Unit]\nDescription=OpenBSD Secure Shell server\nAfter=network.target\n\n[Service]\nExecStart=/usr/sbin/sshd -D\n", main_pid: 1043, after: ["network.target"] }),
  };
  for (const [pat, body] of Object.entries(routes)) await p.route(pat, json(body));
  // File manager: info, listings (tree requests ask for dirs_only), editor content.
  await p.route("**/api/v1/files/info", json(JSON.stringify({ home: "/etc", root: rootMode ? { active: true, until: new Date(Date.now() + 8 * 60000).toISOString() } : { active: false }, upload_limit_mib: 1024, edit_limit: 5242880 })));
  await p.route("**/api/v1/files/list", (r) => {
    const req = r.request().postDataJSON() ?? {};
    if (req.dirs_only) return r.fulfill({ contentType: "application/json", body: req.path === "/" ? fx("fstree") : JSON.stringify({ path: req.path, entries: [], total: 0, writable: false }) });
    return r.fulfill({ contentType: "application/json", body: fx("fslist") });
  });
  await p.route("**/api/v1/files/content/read", json(fx("fscontent")));
  if (rootMode) await p.route("**/api/v1/files/root/**", json("{}"));
  await p.goto(base + path, { waitUntil: "networkidle" });
  await p.waitForTimeout(600);
  if (after) {
    await after(p);
    await p.waitForTimeout(500);
  }
  await p.screenshot({ path: `${outDir}/${name}.png` });
  results.push({ name, errors: errs });
  await ctx.close();
}

await shot("overview", "/", { height: 1300 });
await shot("services", "/services");
await shot("services-detail", "/services", { after: (p) => p.click("text=ssh.service") });
await shot("logs", "/logs");
await shot("processes", "/processes");
await shot("users", "/users");
await shot("users-create", "/users", { after: (p) => p.click("text=Benutzer anlegen") });
await shot("sshkeys", "/ssh-keys?user=pancake", { height: 1100 });
await shot("files", "/files?path=/etc", { height: 1000 });
await shot("files-root", "/files?path=/etc", { rootMode: true });
await shot("files-chmod", "/files?path=/etc", {
  after: async (p) => {
    await p.click('button[aria-label^="Aktionen für hosts"]');
    await p.click("text=Rechte ändern");
  },
});
await shot("files-editor", "/files/edit?dir=/etc/ssh&name=sshd_config", { height: 1000 });
await shot("files-mobile", "/files?path=/etc", { width: 390, height: 1200 });
await shot("overview-mobile", "/", { width: 390, height: 1500 });
await shot("overview-light", "/", { theme: "light", height: 1300 });
await b.close();
console.log(JSON.stringify(results));
if (results.some((r) => r.errors.length)) process.exit(1);
