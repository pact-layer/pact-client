import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const BIN = new URL("../bin/pact.js", import.meta.url).pathname;

function run(args, env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function mockServer() {
  const requests = [];
  const server = createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    requests.push({ method: req.method, url: req.url, body: raw ? JSON.parse(raw) : null });
    res.setHeader("content-type", "application/json");
    if (req.url === "/access/request") {
      const email = JSON.parse(raw).call.email;
      res.statusCode = email === "fail@example.com" ? 503 : 200;
      res.end(JSON.stringify(email === "fail@example.com" ? { error: "mail unavailable" } : { ok: true }));
      return;
    }
    if (req.url === "/access/verify") {
      const otp = JSON.parse(raw).call.otp;
      if (otp === "000000") {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: "wrong code" }));
        return;
      }
      res.end(JSON.stringify({ status: otp === "111111" ? "allowed" : "pending" }));
      return;
    }
    if (req.url?.startsWith("/access/")) {
      res.end(JSON.stringify({ mode: "invite", status: "allowed" }));
      return;
    }
    res.statusCode = 404;
    res.end(JSON.stringify({ error: "not found" }));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return {
    url: `http://127.0.0.1:${address.port}`,
    requests,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
  };
}

test("version and init use 0.2.1 and the documented default server", async () => {
  const home = mkdtempSync(join(tmpdir(), "pact-cli-test-"));
  const version = await run(["--version"], { PACT_HOME: home });
  assert.equal(version.status, 0);
  assert.deepEqual(JSON.parse(version.stdout), { pact: "0.2.1" });

  const init = await run(["init"], { PACT_HOME: home });
  assert.equal(init.status, 0);
  assert.equal(JSON.parse(init.stdout).server, "https://api.pact.sh");
  assert.equal(JSON.parse(readFileSync(join(home, "agent.json"), "utf8")).server, "https://api.pact.sh");
});

test("init --server persists the selected server and PACT_SERVER overrides it", async (t) => {
  const configured = await mockServer();
  const overridden = await mockServer();
  t.after(async () => {
    await configured.close();
    await overridden.close();
  });
  const home = mkdtempSync(join(tmpdir(), "pact-cli-test-"));
  assert.equal((await run(["init", "--server", configured.url], { PACT_HOME: home })).status, 0);

  const access = await run(["access"], { PACT_HOME: home, PACT_SERVER: overridden.url });
  assert.equal(access.status, 0);
  assert.deepEqual(JSON.parse(access.stdout), { mode: "invite", status: "allowed" });
  assert.equal(configured.requests.length, 0);
  assert.match(overridden.requests[0].url, /^\/access\/ed25519:/);
});

test("request-access and verify print English guidance matching allowed, pending, and failure states", async (t) => {
  const api = await mockServer();
  t.after(() => api.close());
  const home = mkdtempSync(join(tmpdir(), "pact-cli-test-"));
  await run(["init", "--server", api.url], { PACT_HOME: home });

  const requested = await run(["request-access", "--email", "user@example.com", "--use-case", "agent trading"], { PACT_HOME: home });
  assert.equal(requested.status, 0);
  assert.match(requested.stderr, /Check your inbox, then run: pact verify/);
  assert.doesNotMatch(requested.stdout + requested.stderr, /[가-힣]/);

  const failed = await run(["request-access", "--email", "fail@example.com"], { PACT_HOME: home });
  assert.equal(failed.status, 1);
  assert.deepEqual(JSON.parse(failed.stdout), { error: "mail unavailable" });

  const allowed = await run(["verify", "111111"], { PACT_HOME: home });
  assert.equal(allowed.status, 0);
  assert.match(allowed.stderr, /Access granted/);

  const pending = await run(["verify", "222222"], { PACT_HOME: home });
  assert.equal(pending.status, 0);
  assert.match(pending.stderr, /pending operator approval/);
  assert.match(pending.stderr, /Wait for the approval email/);
  assert.doesNotMatch(pending.stdout + pending.stderr, /[가-힣]/);

  const rejected = await run(["verify", "000000"], { PACT_HOME: home });
  assert.equal(rejected.status, 1);
  assert.deepEqual(JSON.parse(rejected.stdout), { error: "wrong code" });
});
