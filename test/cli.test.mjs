import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { readSecretInput } from "../lib/secure-input.js";

const BIN = new URL("../bin/pact.js", import.meta.url).pathname;

function run(args, env = {}, input = "") {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], {
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
    child.stdin.end(input);
  });
}

async function mockServer({ denyWrites = false } = {}) {
  const requests = [];
  const server = createServer(async (req, res) => {
    let raw = "";
    for await (const chunk of req) raw += chunk;
    const isJson = req.headers["content-type"]?.startsWith("application/json");
    requests.push({
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: raw ? (isJson ? JSON.parse(raw) : raw) : null
    });
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
    if (req.method === "GET" && req.url === "/pacts/p_test") {
      res.end(JSON.stringify({ pact: { id: "p_test", stateNonce: 7 } }));
      return;
    }
    if (denyWrites && req.method === "POST") {
      res.statusCode = 403;
      res.end(JSON.stringify({ error: "access_required" }));
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

test("version and init use 0.2.2 and the documented default server", async () => {
  const home = mkdtempSync(join(tmpdir(), "pact-cli-test-"));
  const version = await run(["--version"], { PACT_HOME: home });
  assert.equal(version.status, 0);
  assert.deepEqual(JSON.parse(version.stdout), { pact: "0.2.2" });

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

  const allowed = await run(["verify"], { PACT_HOME: home }, "111111\n");
  assert.equal(allowed.status, 0);
  assert.match(allowed.stderr, /Access granted/);

  const pending = await run(["verify"], { PACT_HOME: home }, "222222\n");
  assert.equal(pending.status, 0);
  assert.match(pending.stderr, /pending operator approval/);
  assert.match(pending.stderr, /Wait for the approval email/);
  assert.doesNotMatch(pending.stdout + pending.stderr, /[가-힣]/);

  const rejected = await run(["verify", "000000"], { PACT_HOME: home });
  assert.equal(rejected.status, 1);
  assert.deepEqual(JSON.parse(rejected.stdout), { error: "wrong code" });
  assert.match(rejected.stderr, /argv is legacy behavior/);

  const empty = await run(["verify"], { PACT_HOME: home });
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /OTP is required on stdin/);
});

test("secure TTY input never echoes the secret", async () => {
  const input = new PassThrough();
  input.isTTY = true;
  input.setRawMode = () => input;
  const output = new PassThrough();
  let rendered = "";
  output.setEncoding("utf8");
  output.on("data", (chunk) => (rendered += chunk));

  const reading = readSecretInput({ input, output, prompt: "OTP: " });
  input.end("123456\n");

  assert.equal(await reading, "123456");
  assert.equal(rendered.replace(/\u001b\[[0-9;]*[A-Za-z]/g, ""), "OTP: \n");
  assert.doesNotMatch(rendered, /123456/);
});

test("fund prefers proof JSON on stdin and rejects ambiguous proof sources", async (t) => {
  const api = await mockServer({ denyWrites: true });
  t.after(() => api.close());
  const home = mkdtempSync(join(tmpdir(), "pact-cli-test-"));
  await run(["init", "--server", api.url], { PACT_HOME: home });

  const fromStdin = await run(
    ["fund", "p_test", "--proof-stdin"],
    { PACT_HOME: home },
    '{"txHash":"0xstdin"}\n'
  );
  assert.equal(fromStdin.status, 1);
  const funded = api.requests.find((request) => request.method === "POST" && request.url === "/pacts/p_test/fund");
  assert.ok(funded);
  assert.deepEqual(JSON.parse(Buffer.from(funded.headers["x-payment"], "base64").toString("utf8")), {
    txHash: "0xstdin"
  });
  assert.doesNotMatch(fromStdin.stdout + fromStdin.stderr, /0xstdin/);

  const ambiguous = await run(
    ["fund", "p_test", "--proof-stdin", "--proof", '{"txHash":"0xargv"}'],
    { PACT_HOME: home },
    '{"txHash":"0xstdin"}\n'
  );
  assert.equal(ambiguous.status, 1);
  assert.match(ambiguous.stderr, /cannot be used together/);

  const empty = await run(["fund", "p_test", "--proof-stdin"], { PACT_HOME: home });
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /payment proof JSON is required on stdin/);

  const invalid = await run(["fund", "p_test", "--proof-stdin"], { PACT_HOME: home }, "secret-not-json\n");
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /invalid payment proof JSON on stdin/);
  assert.doesNotMatch(invalid.stdout + invalid.stderr, /secret-not-json/);

  const legacy = await run(
    ["fund", "p_test", "--proof", '{"txHash":"0xlegacy"}'],
    { PACT_HOME: home }
  );
  assert.equal(legacy.status, 1);
  assert.match(legacy.stderr, /retained for compatibility/);
});

test("every raw non-success write response exits non-zero", async (t) => {
  const api = await mockServer({ denyWrites: true });
  t.after(() => api.close());
  const home = mkdtempSync(join(tmpdir(), "pact-cli-test-"));
  const deliverable = join(home, "deliverable.txt");
  writeFileSync(deliverable, "test deliverable");
  await run(["init", "--server", api.url], { PACT_HOME: home });

  const commands = [
    ["fund", "p_test"],
    ["withdraw", "p_test"],
    ["put", "p_test", deliverable],
    ["link", "p_test", "a".repeat(64)],
    ["propose", "p_test", "--dist", "ed25519:test:10000"],
    ["cosign", "p_test"],
    ["object", "p_test", "--reason", "missing deliverable"],
    ["poke", "p_test"],
    ["bind-address", "--rail", "x402", "--address", "0x1234"],
    ["offers", "publish", "--pact", "p_test", "--text", "test offer"]
  ];

  for (const args of commands) {
    const result = await run(args, { PACT_HOME: home });
    assert.equal(result.status, 1, `${args.join(" ")} must exit 1: ${result.stderr}`);
    assert.deepEqual(JSON.parse(result.stdout), { error: "access_required" });
  }
});

test("help and representative success and failure output are English-only", async () => {
  const home = mkdtempSync(join(tmpdir(), "pact-cli-test-"));
  const outputs = [];
  outputs.push(await run(["--help"], { PACT_HOME: home }));
  outputs.push(await run(["whoami"], { PACT_HOME: home }));
  outputs.push(await run(["init"], { PACT_HOME: home }));
  outputs.push(await run(["init"], { PACT_HOME: home }));
  outputs.push(await run(["offers", "invalid"], { PACT_HOME: home }));
  outputs.push(await run(["admin", "invalid"], { PACT_HOME: home }));

  for (const result of outputs) {
    assert.doesNotMatch(result.stdout + result.stderr, /[가-힣]/);
  }
  assert.match(outputs[0].stderr, /--proof-stdin/);
  assert.match(outputs[0].stderr, /TTY input is hidden/);
});
