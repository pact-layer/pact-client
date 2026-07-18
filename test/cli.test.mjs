import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  statSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import test from "node:test";
import { readSecretInput } from "../lib/secure-input.js";
import { signCanonical } from "../lib/sdk.js";

const BIN = new URL("../bin/pact.js", import.meta.url).pathname;
const README = readFileSync(new URL("../README.md", import.meta.url), "utf8");

function secureTempHome(prefix = "pact-cli-test-") {
  return realpathSync(mkdtempSync(join(realpathSync(tmpdir()), prefix)));
}

test("cancellation docs create a private file included by the submit glob", () => {
  assert.match(README, /umask 077/);
  assert.match(README, /party-cancel-me\.json/);
  assert.match(README, /party-cancel-\*\.json/);
  assert.doesNotMatch(README, /my-cancel\.json/);
});

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
    if (req.method === "POST" && /^\/rails\/[^/]+\/address$/.test(req.url ?? "")) {
      const call = JSON.parse(raw).call;
      res.end(JSON.stringify({ rail: call.rail, address: call.address }));
      return;
    }
    if (req.method === "POST" && /^\/offers\/[^/]+\/accept$/.test(req.url ?? "")) {
      const body = JSON.parse(raw);
      res.end(JSON.stringify({ pact: { id: "p_offer", sourceOffer: { id: body.pactId } } }));
      return;
    }
    if (req.method === "POST" && req.url === "/pacts/p_test/cancel") {
      res.end(JSON.stringify({ pact: { id: "p_test", state: "CANCELLED", stateNonce: 8 } }));
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

test("version and init use 0.4.0 and the documented default server", async () => {
  const home = secureTempHome();
  const version = await run(["--version"], { PACT_HOME: home });
  assert.equal(version.status, 0);
  assert.deepEqual(JSON.parse(version.stdout), { pact: "0.4.0" });

  const init = await run(["init"], { PACT_HOME: home });
  assert.equal(init.status, 0);
  const initialized = JSON.parse(init.stdout);
  const configPath = join(home, "agent.json");
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  assert.equal(initialized.server, "https://api.pact.sh");
  assert.equal(config.server, "https://api.pact.sh");
  assert.equal(statSync(home).mode & 0o777, 0o700);
  assert.equal(statSync(configPath).mode & 0o777, 0o600);
  assert.doesNotMatch(init.stdout + init.stderr, new RegExp(config.privkey));
});

test("identity reads reject insecure files, directories, strict-schema violations, and invalid servers", async () => {
  const modeHome = secureTempHome();
  assert.equal((await run(["init"], { PACT_HOME: modeHome })).status, 0);
  const modePath = join(modeHome, "agent.json");
  const modeConfig = JSON.parse(readFileSync(modePath, "utf8"));
  chmodSync(modePath, 0o644);
  const publicFile = await run(["whoami"], { PACT_HOME: modeHome });
  assert.equal(publicFile.status, 1);
  assert.match(publicFile.stderr, /mode 0600/);
  assert.doesNotMatch(publicFile.stdout + publicFile.stderr, new RegExp(modeConfig.privkey));

  const directoryHome = secureTempHome();
  chmodSync(directoryHome, 0o755);
  const publicDirectory = await run(["init"], { PACT_HOME: directoryHome });
  assert.equal(publicDirectory.status, 1);
  assert.match(publicDirectory.stderr, /mode 0700/);
  assert.equal(existsSync(join(directoryHome, "agent.json")), false);

  const mismatchHome = secureTempHome();
  assert.equal((await run(["init"], { PACT_HOME: mismatchHome })).status, 0);
  const mismatchPath = join(mismatchHome, "agent.json");
  const mismatch = JSON.parse(readFileSync(mismatchPath, "utf8"));
  mismatch.partyId = "ed25519:not-the-derived-party";
  writeFileSync(mismatchPath, `${JSON.stringify(mismatch)}\n`);
  const mismatchedParty = await run(["whoami"], { PACT_HOME: mismatchHome });
  assert.equal(mismatchedParty.status, 1);
  assert.match(mismatchedParty.stderr, /partyId does not match/);
  assert.doesNotMatch(mismatchedParty.stdout + mismatchedParty.stderr, new RegExp(mismatch.privkey));

  const strictHome = secureTempHome();
  assert.equal((await run(["init"], { PACT_HOME: strictHome })).status, 0);
  const strictPath = join(strictHome, "agent.json");
  const strict = JSON.parse(readFileSync(strictPath, "utf8"));
  writeFileSync(strictPath, `${JSON.stringify({ ...strict, unexpected: true })}\n`);
  const extraField = await run(["whoami"], { PACT_HOME: strictHome });
  assert.equal(extraField.status, 1);
  assert.match(extraField.stderr, /must contain only/);
  assert.doesNotMatch(extraField.stdout + extraField.stderr, new RegExp(strict.privkey));

  const invalidServerHome = secureTempHome();
  const invalidServer = await run(["init", "--server", "file:///tmp/pact.sock"], {
    PACT_HOME: invalidServerHome
  });
  assert.equal(invalidServer.status, 1);
  assert.match(invalidServer.stderr, /http\(s\) origin URL/);
  assert.equal(existsSync(join(invalidServerHome, "agent.json")), false);
});

test("identity reads reject oversized configs and a config changed during the open read", async () => {
  const oversizedHome = secureTempHome();
  assert.equal((await run(["init"], { PACT_HOME: oversizedHome })).status, 0);
  const oversizedPath = join(oversizedHome, "agent.json");
  writeFileSync(oversizedPath, Buffer.alloc(16_385, 0x20));
  const oversized = await run(["whoami"], { PACT_HOME: oversizedHome });
  assert.equal(oversized.status, 1);
  assert.match(oversized.stderr, /exceeds 16384 bytes/);

  const racedHome = secureTempHome();
  assert.equal((await run(["init"], { PACT_HOME: racedHome })).status, 0);
  const racedPath = join(racedHome, "agent.json");
  const original = readFileSync(racedPath);
  const { loadIdentityConfig } = await import("../bin/pact.js");
  assert.throws(
    () =>
      loadIdentityConfig(racedPath, {
        afterOpen() {
          writeFileSync(racedPath, Buffer.concat([original, Buffer.from(" ")]));
        }
      }),
    /changed during secure read/
  );
});

test("identity paths reject final and ancestor symlinks, including init --force", async () => {
  const finalHome = secureTempHome();
  const targetHome = secureTempHome("pact-cli-target-");
  assert.equal((await run(["init"], { PACT_HOME: targetHome })).status, 0);
  const targetPath = join(targetHome, "agent.json");
  const targetBefore = readFileSync(targetPath);
  const finalPath = join(finalHome, "agent.json");
  symlinkSync(targetPath, finalPath);

  const finalRead = await run(["whoami"], { PACT_HOME: finalHome });
  assert.equal(finalRead.status, 1);
  assert.match(finalRead.stderr, /regular non-symlink file/);
  const forced = await run(["init", "--force"], { PACT_HOME: finalHome });
  assert.equal(forced.status, 1);
  assert.match(forced.stderr, /refusing to replace.*symlink/);
  assert.equal(lstatSync(finalPath).isSymbolicLink(), true);
  assert.deepEqual(readFileSync(targetPath), targetBefore);

  const ancestorBase = secureTempHome("pact-cli-ancestor-");
  const realParent = join(ancestorBase, "real-parent");
  const linkedParent = join(ancestorBase, "linked-parent");
  const realHome = join(realParent, "identity-home");
  const linkedHome = join(linkedParent, "identity-home");
  mkdirSync(realParent, { mode: 0o700 });
  mkdirSync(realHome, { mode: 0o700 });
  assert.equal((await run(["init"], { PACT_HOME: realHome })).status, 0);
  symlinkSync(realParent, linkedParent, "dir");
  const ancestorRead = await run(["whoami"], { PACT_HOME: linkedHome });
  assert.equal(ancestorRead.status, 1);
  assert.match(ancestorRead.stderr, /ancestor must not be a symlink/);
});

test("wallet-capable dependencies are exact and integrity-locked for the published package", () => {
  const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const lock = JSON.parse(readFileSync(new URL("../npm-shrinkwrap.json", import.meta.url), "utf8"));
  const cliSource = readFileSync(new URL("../bin/pact.js", import.meta.url), "utf8");
  const payerSource = readFileSync(new URL("../lib/mppx-payer.js", import.meta.url), "utf8");

  assert.ok(manifest.files.includes("npm-shrinkwrap.json"));
  for (const [name, version] of Object.entries({
    "@paysponge/sdk": "0.1.147",
    agentcash: "0.17.0",
    mppx: "0.8.6",
    spongewallet: "0.1.127",
    viem: "2.55.1"
  })) {
    assert.equal(manifest.dependencies[name], version);
    const installed = lock.packages[`node_modules/${name}`];
    assert.equal(installed.version, version);
    assert.match(installed.integrity, /^sha512-/);
  }
  assert.doesNotMatch(cliSource, /spawn\(["']npx["']/);
  assert.doesNotMatch(cliSource, /agentcash@\$\{|spongewallet@\$\{/);
  assert.doesNotMatch(cliSource, /--signatures [<'"]/);
  assert.match(cliSource, /join\(homedir\(\), "\.agentcash", "wallet\.json"\)/);
  assert.doesNotMatch(cliSource, /console\.(?:log|error)\([^\n]*privateKey/);
  // Raw key material may be touched in exactly one place: the container-operator
  // file keystore, and only behind its explicit ack gate. Everything else in the
  // payer keeps the original no-key-file invariant.
  assert.doesNotMatch(payerSource, /wallet\.json|AGENTCASH_HOME/);
  const keystoreFn = payerSource.slice(
    payerSource.indexOf("export async function resolveFileKeystoreAccount"),
    payerSource.indexOf("export async function resolveMppxKeychainAccount")
  );
  const outsideKeystore = payerSource.replace(keystoreFn, "").replace(/^import [^\n]*\n/gm, "");
  assert.doesNotMatch(outsideKeystore, /readFileSync|privateKeyToAccount/,
    "key material access must stay confined to resolveFileKeystoreAccount");
  assert.match(keystoreFn, /readFileSync/);
  assert.match(keystoreFn, /privateKeyToAccount/);
  assert.match(keystoreFn, /PACT_MPPX_ALLOW_FILE_KEYSTORE/);
  assert.match(payerSource, /FILE_KEYSTORE_ACK = "container-operator"/);
});

test("AgentCash and PaySponge onboarding use only pinned local executables", async () => {
  const { resolveWalletExecutable, runExternalWalletTool, verifyWalletManifest } =
    await import("../bin/pact.js");
  assert.throws(
    () =>
      verifyWalletManifest("agentcash", {
        name: "agentcash",
        version: "0.18.0",
        bin: { agentcash: "dist/esm/index.js" }
      }),
    /dependency mismatch/
  );
  assert.match(resolveWalletExecutable("agentcash"), /agentcash\/dist\/esm\/index\.js$/);
  assert.match(resolveWalletExecutable("paysponge"), /spongewallet\/bin\/spongewallet\.js$/);

  const calls = [];
  const fakeSpawn = (executable, args, options) => {
    calls.push({ executable, args, options });
    return { status: 0 };
  };
  assert.equal(runExternalWalletTool("agentcash", "balance", ["--format", "json"], fakeSpawn), 0);
  assert.equal(runExternalWalletTool("paysponge", "init", [], fakeSpawn), 0);
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(call.executable, process.execPath);
    assert.equal(call.options.shell, false);
    assert.equal(call.options.stdio, "inherit");
    assert.doesNotMatch(call.args[0], /node_modules\/.bin/);
  }
  assert.throws(() => runExternalWalletTool("agentcash", "pay", [], fakeSpawn), /usage: pact wallet/);
  assert.throws(() => runExternalWalletTool("paysponge", "export", [], fakeSpawn), /usage: pact wallet/);
});

test("wallet commands use only a named OS keychain and never start a faucet or network request", async () => {
  const { loadMppxKeychainRuntime, readPrivateAgentCashWallet, runWalletTool, verifyWalletManifest } =
    await import("../bin/pact.js");
  assert.throws(
    () => verifyWalletManifest("mppx", { name: "mppx", version: "0.8.7", bin: { mppx: "./dist/bin.js" } }),
    /dependency mismatch/
  );
  const installedRuntime = await loadMppxKeychainRuntime();
  assert.equal(typeof installedRuntime.createKeychain, "function");
  assert.equal(typeof installedRuntime.generatePrivateKey, "function");
  assert.equal(typeof installedRuntime.privateKeyToAccount, "function");

  const stored = new Map();
  let generated = 0;
  let keyReads = 0;
  let networkCalls = 0;
  const runtime = {
    createKeychain(name = "main") {
      return {
        async get() {
          keyReads += 1;
          return stored.get(name);
        },
        async list() { return [...stored.keys()]; },
        async set(value) { stored.set(name, value); }
      };
    },
    generatePrivateKey() {
      generated += 1;
      return `key-${generated}`;
    },
    privateKeyToAccount(key) {
      const suffix = key === "key-1" ? "1" : key === `0x${"33".repeat(32)}` ? "3" : "2";
      return { address: `0x${suffix.repeat(40)}` };
    },
    async storePrivateKey(name, value) {
      stored.set(name, value);
    },
    async fetch() {
      networkCalls += 1;
      throw new Error("wallet creation must not use the network");
    }
  };

  const created = await runWalletTool("mppx", "create", ["--account", "buyer"], runtime);
  assert.deepEqual(created, {
    name: "buyer",
    address: `0x${"1".repeat(40)}`,
    keyStorage: "os-keychain",
    rails: {
      x402: {
        network: "eip155:8453",
        networkName: "Base mainnet",
        asset: "USDC",
        assetAddress: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        minimumFundingAmount: "10000",
        collectionGas: "facilitator-sponsored"
      },
      mpp: {
        network: "eip155:4217",
        networkName: "Tempo mainnet",
        asset: "USDC.e",
        assetAddress: "0x20C000000000000000000000b9537d11c60E8b50",
        minimumFundingAmount: "10000",
        maximumNetworkFee: {
          amount: "10000",
          asset: "USDC.e",
          display: "0.01 USDC.e",
          separateFromMaxAmount: true
        }
      }
    },
    nextStep:
      "Before funding, run pact get <pactId>, derive the exact deposit-plus-bond principal, and " +
      "obtain approval for that cap. For x402, fund this address with USDC on Base mainnet; " +
      "collection gas is facilitator-sponsored. For MPP, fund it with USDC.e on Tempo mainnet plus a " +
      "transaction-fee reserve. --max-amount caps principal; MPP separately enforces a " +
      "0.01 USDC.e network-fee ceiling. Then run: " +
      "pact fund <pactId> --payer mppx --account buyer --max-amount <approved-principal-cap-USD>"
  });
  assert.equal(generated, 1);
  assert.equal(networkCalls, 0);
  assert.doesNotMatch(JSON.stringify(created), /testnet|faucet/i);

  const viewed = await runWalletTool("mppx", "view", ["--account", "buyer"], runtime);
  assert.equal(viewed.address, created.address);
  const keyReadsBeforeList = keyReads;
  assert.deepEqual(await runWalletTool("mppx", "list", [], runtime), {
    accounts: ["buyer"],
    keyStorage: "os-keychain"
  });
  assert.equal(keyReads, keyReadsBeforeList);

  const agentCashKey = `0x${"33".repeat(32)}`;
  const imported = await runWalletTool("mppx", "import-agentcash", ["--account", "agentcash"], {
    ...runtime,
    readAgentCashWallet: () => ({ privateKey: agentCashKey, address: `0x${"3".repeat(40)}` })
  });
  assert.equal(imported.address, `0x${"3".repeat(40)}`);
  assert.equal(imported.importedFrom, "agentcash");
  assert.equal(imported.sourceAddressVerified, true);
  assert.doesNotMatch(JSON.stringify(imported), /3333333333333333333333333333333333333333333333333333333333333333/);
  assert.equal(stored.get("agentcash"), agentCashKey);
  await assert.rejects(
    runWalletTool("mppx", "import-agentcash", ["--account", "mismatch"], {
      ...runtime,
      readAgentCashWallet: () => ({ privateKey: agentCashKey, address: `0x${"4".repeat(40)}` })
    }),
    /public address does not match/
  );

  const walletDir = mkdtempSync(join(tmpdir(), "agentcash-wallet-test-"));
  const walletPath = join(walletDir, "wallet.json");
  writeFileSync(
    walletPath,
    JSON.stringify({ privateKey: agentCashKey, address: `0x${"3".repeat(40)}` }),
    { mode: 0o600 }
  );
  assert.equal(readPrivateAgentCashWallet(walletPath).address, `0x${"3".repeat(40)}`);
  chmodSync(walletPath, 0o644);
  assert.throws(() => readPrivateAgentCashWallet(walletPath), /mode 0600/);

  await assert.rejects(runWalletTool("mppx", "create", ["--account", "buyer"], runtime), /already exists/);
  await assert.rejects(runWalletTool("mppx", "export", ["--account", "buyer"], runtime), /usage: pact wallet/);
  await assert.rejects(runWalletTool("mppx", "create", ["--network", "testnet"], runtime), /usage: pact wallet/);
});

test("macOS mppx key import is add-only over security stdin and preserves a raced existing key", async () => {
  const { addMacOsMppxPrivateKey, runWalletTool } = await import("../bin/pact.js");
  const importedKey = `0x${"33".repeat(32)}`;
  let invocation;
  addMacOsMppxPrivateKey("agentcash", importedKey, (executable, args, options) => {
    invocation = { executable, args, options };
    return { status: 0 };
  });
  assert.equal(invocation.executable, "/usr/bin/security");
  assert.deepEqual(invocation.args, ["-i"]);
  assert.equal(invocation.options.shell, false);
  assert.deepEqual(invocation.options.stdio, ["pipe", "ignore", "ignore"]);
  assert.equal(invocation.options.env, undefined);
  assert.match(invocation.options.input, /^add-generic-password -s mppx -a agentcash -w 0x[0-9a-f]{64}\n$/);
  assert.doesNotMatch(invocation.options.input, /delete-generic-password|-U/);
  assert.doesNotMatch(JSON.stringify({
    args: invocation.args,
    env: invocation.options.env,
    executable: invocation.executable,
    shell: invocation.options.shell,
    stderr: "",
    stdout: ""
  }), new RegExp(importedKey.slice(2)));
  assert.throws(
    () => addMacOsMppxPrivateKey("agentcash", importedKey, () => ({ status: 1 })),
    (error) => !error.message.includes(importedKey) && /keychain rejected/.test(error.message)
  );

  const otherKey = `0x${"44".repeat(32)}`;
  let stored;
  const runtime = {
    createKeychain() {
      return {
        async get() { return stored; },
        async list() { return []; },
        async set() { throw new Error("unsafe overwrite path must not run"); }
      };
    },
    generatePrivateKey() { return importedKey; },
    privateKeyToAccount(key) {
      return { address: key === importedKey ? `0x${"3".repeat(40)}` : `0x${"4".repeat(40)}` };
    },
    async readAgentCashWallet() {
      return { address: `0x${"3".repeat(40)}`, privateKey: importedKey };
    },
    async storePrivateKey() {
      // Simulate another process winning the add-only race with a different key.
      stored = otherKey;
    }
  };
  await assert.rejects(
    runWalletTool("mppx", "import-agentcash", ["--account", "agentcash"], runtime),
    /could not be verified/
  );
  assert.equal(stored, otherKey);

  stored = undefined;
  runtime.storePrivateKey = async (_name, privateKey) => { stored = privateKey; };
  const imported = await runWalletTool(
    "mppx",
    "import-agentcash",
    ["--account", "agentcash"],
    runtime
  );
  assert.equal(imported.address, `0x${"3".repeat(40)}`);
  assert.equal(stored, importedKey);
});

test("mppx funding selects x402 or MPP from the Pact and rejects raw environment keys early", async () => {
  const { paymentProtocol } = await import("../bin/pact.js");
  assert.equal(paymentProtocol("mpp"), "mpp");
  assert.equal(paymentProtocol("x402"), "x402");
  assert.equal(paymentProtocol("x402", "x402"), "x402");
  assert.throws(() => paymentProtocol("mpp", "x402"), /does not match Pact rail/);
  assert.throws(() => paymentProtocol("mock"), /not payable by mppx/);
  assert.throws(() => paymentProtocol("mpp", "other"), /must be mpp or x402/);

  const home = secureTempHome();
  const common = ["fund", "p_1", "--payer", "mppx", "--max-amount", "0.01"];
  const mppxKey = await run(common, {
    PACT_HOME: home,
    MPPX_PRIVATE_KEY: `0x${"11".repeat(32)}`,
    X402_PRIVATE_KEY: ""
  });
  assert.equal(mppxKey.status, 1);
  assert.match(mppxKey.stderr, /MPPX_PRIVATE_KEY is disabled/);
  assert.doesNotMatch(mppxKey.stderr, /no agent config/);

  const x402Key = await run(common, {
    PACT_HOME: home,
    MPPX_PRIVATE_KEY: "",
    X402_PRIVATE_KEY: `0x${"22".repeat(32)}`
  });
  assert.equal(x402Key.status, 1);
  assert.match(x402Key.stderr, /X402_PRIVATE_KEY is disabled/);
  assert.doesNotMatch(x402Key.stderr, /no agent config/);

  const missingAccount = await run(common, {
    PACT_HOME: home,
    MPPX_PRIVATE_KEY: "",
    X402_PRIVATE_KEY: ""
  });
  assert.equal(missingAccount.status, 1);
  assert.match(missingAccount.stderr, /--account is required with --payer mppx/);
  assert.doesNotMatch(missingAccount.stderr, /no agent config/);
});

test("init --server persists the selected server and PACT_SERVER overrides it", async (t) => {
  const configured = await mockServer();
  const overridden = await mockServer();
  t.after(async () => {
    await configured.close();
    await overridden.close();
  });
  const home = secureTempHome();
  assert.equal((await run(["init", "--server", configured.url], { PACT_HOME: home })).status, 0);

  const access = await run(["access"], { PACT_HOME: home, PACT_SERVER: overridden.url });
  assert.equal(access.status, 0);
  assert.deepEqual(JSON.parse(access.stdout), { mode: "invite", status: "allowed" });
  assert.equal(configured.requests.length, 0);
  assert.match(overridden.requests[0].url, /^\/access\/ed25519:/);
});

test("quickstart defaults to production x402 and requires an explicit mock simulation", async () => {
  const home = secureTempHome();
  assert.equal((await run(["init"], { PACT_HOME: home })).status, 0);

  const defaultTemplate = await run(["quickstart"], { PACT_HOME: home });
  assert.equal(defaultTemplate.status, 0, defaultTemplate.stderr);
  assert.equal(JSON.parse(defaultTemplate.stdout).rail, "x402");

  const mppTemplate = await run(["quickstart", "--rail", "mpp"], { PACT_HOME: home });
  assert.equal(mppTemplate.status, 0, mppTemplate.stderr);
  assert.equal(JSON.parse(mppTemplate.stdout).rail, "mpp");

  const mockTemplate = await run(["quickstart", "--rail", "mock"], { PACT_HOME: home });
  assert.equal(mockTemplate.status, 0, mockTemplate.stderr);
  assert.equal(JSON.parse(mockTemplate.stdout).rail, "mock");

  const invalid = await run(["quickstart", "--rail", "solana"], { PACT_HOME: home });
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /--rail must be x402, mpp, or mock/);
});

test("request-access and verify print English guidance matching allowed, pending, and failure states", async (t) => {
  const api = await mockServer();
  t.after(() => api.close());
  const home = secureTempHome();
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

  const rejected = await run(["verify"], { PACT_HOME: home }, "000000\n");
  assert.equal(rejected.status, 1);
  assert.deepEqual(JSON.parse(rejected.stdout), { error: "wrong code" });

  const positional = await run(["verify", "654321"], { PACT_HOME: home });
  assert.equal(positional.status, 1);
  assert.match(positional.stderr, /usage: pact verify/);
  assert.doesNotMatch(positional.stdout + positional.stderr, /654321/);

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

test("fund accepts proof JSON only on stdin and never reflects rejected argv secrets", async (t) => {
  const api = await mockServer({ denyWrites: true });
  t.after(() => api.close());
  const home = secureTempHome();
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

  const argvProof = await run(
    ["fund", "p_test", "--proof", '{"txHash":"0xargv"}'],
    { PACT_HOME: home }
  );
  assert.equal(argvProof.status, 1);
  assert.match(argvProof.stderr, /usage: pact fund/);
  assert.doesNotMatch(argvProof.stdout + argvProof.stderr, /0xargv/);

  const inlineArgvProof = await run(
    ["fund", "p_test", '--proof={"txHash":"0xinline"}'],
    { PACT_HOME: home }
  );
  assert.equal(inlineArgvProof.status, 1);
  assert.match(inlineArgvProof.stderr, /usage: pact fund/);
  assert.doesNotMatch(inlineArgvProof.stdout + inlineArgvProof.stderr, /0xinline/);

  const empty = await run(["fund", "p_test", "--proof-stdin"], { PACT_HOME: home });
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /payment proof JSON is required on stdin/);

  const invalid = await run(["fund", "p_test", "--proof-stdin"], { PACT_HOME: home }, "secret-not-json\n");
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /invalid payment proof JSON on stdin/);
  assert.doesNotMatch(invalid.stdout + invalid.stderr, /secret-not-json/);

});

test("cancel prepares an action-bound signature and submits all signatures from stdin", async (t) => {
  const api = await mockServer();
  t.after(() => api.close());
  const home = secureTempHome();
  await run(["init", "--server", api.url], { PACT_HOME: home });
  const conf = JSON.parse(readFileSync(join(home, "agent.json"), "utf8"));
  const expiresAt = 2_000_000_000_000;

  const prepared = await run(
    ["cancel", "p_test", "--expires-at", String(expiresAt)],
    { PACT_HOME: home }
  );
  assert.equal(prepared.status, 0);
  const preparation = JSON.parse(prepared.stdout);
  assert.equal(preparation.pactId, "p_test");
  assert.equal(preparation.stateNonce, 7);
  assert.equal(preparation.expiresAt, expiresAt);
  assert.deepEqual(preparation.signature, {
    signer: conf.partyId,
    sig: signCanonical(
      { action: "cancel", pactId: "p_test", stateNonce: 7, expiresAt },
      conf.privkey
    )
  });
  assert.match(preparation.nextStep, /same stateNonce and expiresAt/);
  assert.equal(api.requests.filter((request) => request.url === "/pacts/p_test/cancel").length, 0);

  const other = { signer: "ed25519:counterparty", sig: "ab", ignored: "not forwarded" };
  const submitted = await run(
    ["cancel", "p_test", "--expires-at", String(expiresAt), "--signatures-stdin"],
    { PACT_HOME: home },
    JSON.stringify([other])
  );
  assert.equal(submitted.status, 0);
  assert.deepEqual(JSON.parse(submitted.stdout), {
    pact: { id: "p_test", state: "CANCELLED", stateNonce: 8 }
  });
  const request = api.requests.find(
    (entry) => entry.method === "POST" && entry.url === "/pacts/p_test/cancel"
  );
  assert.ok(request);
  assert.equal(request.body.action, "pacts.cancel");
  assert.equal(request.body.pactId, "p_test");
  assert.equal(request.body.stateNonce, 7);
  assert.equal(request.body.call.expiresAt, expiresAt);
  assert.deepEqual(request.body.call.sigs, [
    { signer: other.signer, sig: other.sig },
    preparation.signature
  ]);
});

test("cancel rejects argv signatures and invalid stdin without reflecting input", async (t) => {
  const api = await mockServer();
  t.after(() => api.close());
  const home = secureTempHome();
  await run(["init", "--server", api.url], { PACT_HOME: home });

  for (const argv of [
    ["cancel", "p_test", "--expires-at", "2000000000000", "--signatures", "argv-sensitive"],
    ["cancel", "p_test", "--expires-at", "2000000000000", "--signatures=inline-sensitive"]
  ]) {
    const rejected = await run(argv, { PACT_HOME: home });
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /usage: pact cancel/);
    assert.doesNotMatch(rejected.stdout + rejected.stderr, /argv-sensitive|inline-sensitive/);
  }

  const empty = await run(
    ["cancel", "p_test", "--expires-at", "2000000000000", "--signatures-stdin"],
    { PACT_HOME: home }
  );
  assert.equal(empty.status, 1);
  assert.match(empty.stderr, /cancellation signatures JSON is required on stdin/);

  const invalid = await run(
    ["cancel", "p_test", "--expires-at", "2000000000000", "--signatures-stdin"],
    { PACT_HOME: home },
    "stdin-sensitive-not-json\n"
  );
  assert.equal(invalid.status, 1);
  assert.match(invalid.stderr, /invalid cancellation signatures JSON on stdin/);
  assert.doesNotMatch(invalid.stdout + invalid.stderr, /stdin-sensitive-not-json/);

  const badExpiry = await run(
    ["cancel", "p_test", "--expires-at", "not-a-time"],
    { PACT_HOME: home }
  );
  assert.equal(badExpiry.status, 1);
  assert.match(badExpiry.stderr, /usage: pact cancel/);
});

test("bind-address signs the rail as well as the address", async (t) => {
  const api = await mockServer();
  t.after(() => api.close());
  const home = secureTempHome();
  await run(["init", "--server", api.url], { PACT_HOME: home });

  const bound = await run(
    ["bind-address", "--rail", "x402", "--address", "0x1234"],
    { PACT_HOME: home }
  );
  assert.equal(bound.status, 0, bound.stderr);
  const request = api.requests.find(
    (entry) => entry.method === "POST" && entry.url === "/rails/x402/address"
  );
  assert.ok(request);
  assert.equal(request.body.action, "rails.bindAddress");
  assert.deepEqual(request.body.call, { rail: "x402", address: "0x1234" });
  const { sig, ...unsigned } = request.body;
  const identity = JSON.parse(readFileSync(join(home, "agent.json"), "utf8"));
  assert.equal(sig, signCanonical(unsigned, identity.privkey));
});

test("offers accept sends only the idempotency key in an action-bound signature", async (t) => {
  const api = await mockServer();
  t.after(() => api.close());
  const home = secureTempHome();
  await run(["init", "--server", api.url], { PACT_HOME: home });

  const accepted = await run(
    ["offers", "accept", "o_test", "--acceptance-id", "cli-test"],
    { PACT_HOME: home }
  );
  assert.equal(accepted.status, 0, accepted.stderr);
  const request = api.requests.find(
    (entry) => entry.method === "POST" && entry.url === "/offers/o_test/accept"
  );
  assert.ok(request);
  assert.equal(request.body.action, "offers.accept");
  assert.equal(request.body.pactId, "o_test");
  assert.equal(request.body.stateNonce, 0);
  assert.deepEqual(request.body.call, { acceptanceId: "cli-test" });
  const { sig, ...unsigned } = request.body;
  const identity = JSON.parse(readFileSync(join(home, "agent.json"), "utf8"));
  assert.equal(sig, signCanonical(unsigned, identity.privkey));
});

test("every raw non-success write response exits non-zero", async (t) => {
  const api = await mockServer({ denyWrites: true });
  t.after(() => api.close());
  const home = secureTempHome();
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
    ["offers", "publish", "--pact", "p_test", "--text", "test offer"],
    ["offers", "accept", "o_test", "--acceptance-id", "deny-test"]
  ];

  for (const args of commands) {
    const result = await run(args, { PACT_HOME: home });
    assert.equal(result.status, 1, `${args.join(" ")} must exit 1: ${result.stderr}`);
    assert.deepEqual(JSON.parse(result.stdout), { error: "access_required" });
  }

  const cancel = await run(
    ["cancel", "p_test", "--expires-at", "2000000000000", "--signatures-stdin"],
    { PACT_HOME: home },
    "[]\n"
  );
  assert.equal(cancel.status, 1);
  assert.deepEqual(JSON.parse(cancel.stdout), { error: "access_required" });
});

test("help and representative success and failure output are English-only", async () => {
  const home = secureTempHome();
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
  assert.match(outputs[0].stderr, /--payer mppx/);
  assert.match(outputs[0].stderr, /--max-amount/);
  assert.match(outputs[0].stderr, /pact cancel/);
  assert.match(outputs[0].stderr, /--signatures-stdin/);
  assert.match(outputs[0].stderr, /TTY input is hidden/);
  assert.doesNotMatch(outputs[0].stderr, /legacy|pact verify <otp>|--proof '<j>'/);
});
