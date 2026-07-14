#!/usr/bin/env node
// Pact agent escrow CLI. Config: ~/.pact/agent.json {privkey, partyId, server}
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fchmodSync,
  fstatSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, parse, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { PactClient, generateKeypair, usdc } from "../lib/sdk.js";
import {
  BASE_CHAIN_ID,
  BASE_USDC,
  MPPX_VERSION,
  MPP_MAX_TOTAL_FEE_ATOMIC_USDCE,
  MPP_MAX_TOTAL_FEE_USDCE,
  MPP_MIN_FUNDING_AMOUNT,
  TEMPO_CHAIN_ID,
  TEMPO_USDCE,
  X402_MIN_FUNDING_AMOUNT,
  assertMppxKeychainOnly,
  resolveMppxKeychainAccount,
  runMppxPayment,
  usdMinorUnits
} from "../lib/mppx-payer.js";
import { readSecretInput } from "../lib/secure-input.js";
import { hex } from "@scure/base";

const CONF_DIR = resolve(process.env.PACT_HOME ?? join(homedir(), ".pact"));
const CONF = join(CONF_DIR, "agent.json");
const MAX_IDENTITY_CONFIG_BYTES = 16_384;
const IDENTITY_CONFIG_KEYS = Object.freeze(["partyId", "privkey", "server"]);

function currentUid() {
  const uid = typeof process.geteuid === "function" ? process.geteuid() : process.getuid?.();
  if (!Number.isSafeInteger(uid) || uid < 0) throw new Error("cannot determine the current user for identity security checks");
  return BigInt(uid);
}

function permissions(stat) {
  return Number(stat.mode & 0o777n);
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function stableFileIdentity(before, after) {
  return (
    sameInode(before, after) &&
    before.size === after.size &&
    before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs
  );
}

function lstatBigInt(path) {
  return lstatSync(path, { bigint: true });
}

function fstatBigInt(fd) {
  return fstatSync(fd, { bigint: true });
}

function assertRealDirectoryChain(path) {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  const parts = relative(root, absolute).split(/[\\/]+/).filter(Boolean);
  let cursor = root;
  for (const part of parts) {
    cursor = join(cursor, part);
    let stat;
    try {
      stat = lstatBigInt(cursor);
    } catch (error) {
      if (error?.code === "ENOENT") throw new Error(`identity path ancestor does not exist: ${cursor}`);
      throw error;
    }
    if (stat.isSymbolicLink()) throw new Error(`identity path ancestor must not be a symlink: ${cursor}`);
    if (!stat.isDirectory()) throw new Error(`identity path ancestor must be a directory: ${cursor}`);
  }
}

function assertSecureDirectoryStat(stat, path) {
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`PACT_HOME must be a real directory: ${path}`);
  }
  if (stat.uid !== currentUid()) throw new Error(`PACT_HOME must be owned by the current user: ${path}`);
  if (permissions(stat) !== 0o700) throw new Error(`PACT_HOME must have mode 0700: ${path}`);
}

function openSecureConfigDirectory(path, { create = false } = {}) {
  const absolute = resolve(path);
  assertRealDirectoryChain(dirname(absolute));
  let created = false;
  let pathStat;
  try {
    pathStat = lstatBigInt(absolute);
  } catch (error) {
    if (error?.code !== "ENOENT" || !create) throw error;
    try {
      mkdirSync(absolute, { mode: 0o700 });
      created = true;
    } catch (mkdirError) {
      if (mkdirError?.code !== "EEXIST") throw mkdirError;
    }
    pathStat = lstatBigInt(absolute);
  }
  if (pathStat.isSymbolicLink() || !pathStat.isDirectory()) {
    throw new Error(`PACT_HOME must be a real directory: ${absolute}`);
  }
  if (pathStat.uid !== currentUid()) {
    throw new Error(`PACT_HOME must be owned by the current user: ${absolute}`);
  }

  const flags = fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0) | (fsConstants.O_NOFOLLOW ?? 0);
  const fd = openSync(absolute, flags);
  try {
    let opened = fstatBigInt(fd);
    if (!sameInode(pathStat, opened) || !opened.isDirectory()) {
      throw new Error("PACT_HOME changed during secure open");
    }
    if (created) {
      fchmodSync(fd, 0o700);
      opened = fstatBigInt(fd);
      pathStat = lstatBigInt(absolute);
      if (!sameInode(pathStat, opened)) throw new Error("PACT_HOME changed while securing permissions");
    }
    assertSecureDirectoryStat(opened, absolute);
    return { fd, path: absolute, stat: opened };
  } catch (error) {
    closeSync(fd);
    throw error;
  }
}

function assertSecureIdentityFileStat(stat, path) {
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`agent config must be a regular non-symlink file: ${path}`);
  }
  if (stat.uid !== currentUid()) throw new Error(`agent config must be owned by the current user: ${path}`);
  if (permissions(stat) !== 0o600) throw new Error(`agent config must have mode 0600: ${path}`);
  if (stat.size > BigInt(MAX_IDENTITY_CONFIG_BYTES)) {
    throw new Error(`agent config exceeds ${MAX_IDENTITY_CONFIG_BYTES} bytes`);
  }
}

export function validatePactServerUrl(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 2_048) {
    throw new Error("Pact server must be an http(s) origin URL");
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Pact server must be an http(s) origin URL");
  }
  if (
    (parsed.protocol !== "https:" && parsed.protocol !== "http:") ||
    parsed.username ||
    parsed.password ||
    parsed.pathname !== "/" ||
    parsed.search ||
    parsed.hash ||
    parsed.origin === "null"
  ) {
    throw new Error("Pact server must be an http(s) origin URL without credentials, path, query, or fragment");
  }
  return parsed.origin;
}

function parseIdentityConfig(source) {
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error("agent config is not valid JSON");
  }
  if (
    parsed === null ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.getPrototypeOf(parsed) !== Object.prototype ||
    JSON.stringify(Object.keys(parsed).sort()) !== JSON.stringify(IDENTITY_CONFIG_KEYS)
  ) {
    throw new Error("agent config must contain only privkey, partyId, and server");
  }
  if (typeof parsed.privkey !== "string" || !/^[0-9a-f]{64}$/.test(parsed.privkey)) {
    throw new Error("agent config contains an invalid private key");
  }
  let derived;
  try {
    derived = generateKeypair(hex.decode(parsed.privkey));
  } catch {
    throw new Error("agent config contains an invalid private key");
  }
  if (typeof parsed.partyId !== "string" || parsed.partyId !== derived.partyId) {
    throw new Error("agent config partyId does not match its private key");
  }
  return { privkey: parsed.privkey, partyId: parsed.partyId, server: validatePactServerUrl(parsed.server) };
}

export function loadIdentityConfig(path = CONF, runtime = {}) {
  const absolute = resolve(path);
  const directory = openSecureConfigDirectory(dirname(absolute));
  let fd;
  try {
    let pathStat;
    try {
      pathStat = lstatBigInt(absolute);
    } catch (error) {
      if (error?.code === "ENOENT") {
        throw new Error(`no agent config at ${absolute} — run: pact init --server <URL>`);
      }
      throw error;
    }
    assertSecureIdentityFileStat(pathStat, absolute);
    fd = openSync(absolute, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = fstatBigInt(fd);
    assertSecureIdentityFileStat(opened, absolute);
    if (!sameInode(pathStat, opened)) throw new Error("agent config changed during secure open");
    runtime.afterOpen?.({ fd, path: absolute });
    const bytes = readFileSync(fd);
    const afterRead = fstatBigInt(fd);
    assertRealDirectoryChain(dirname(absolute));
    let finalPath;
    try {
      finalPath = lstatBigInt(absolute);
    } catch {
      throw new Error("agent config changed during secure read");
    }
    if (
      !stableFileIdentity(opened, afterRead) ||
      !stableFileIdentity(afterRead, finalPath) ||
      bytes.length !== Number(afterRead.size)
    ) {
      throw new Error("agent config changed during secure read");
    }
    assertSecureIdentityFileStat(afterRead, absolute);
    const source = bytes.toString("utf8");
    if (!Buffer.from(source, "utf8").equals(bytes)) throw new Error("agent config must be valid UTF-8");
    return parseIdentityConfig(source);
  } finally {
    if (fd !== undefined) closeSync(fd);
    closeSync(directory.fd);
  }
}

function inspectInitTarget(path) {
  let stat;
  try {
    stat = lstatBigInt(path);
  } catch (error) {
    if (error?.code === "ENOENT") return undefined;
    throw error;
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`refusing to replace a non-regular or symlink agent config: ${path}`);
  }
  if (stat.uid !== currentUid()) throw new Error(`refusing to replace an agent config owned by another user: ${path}`);
  return stat;
}

function targetUnchanged(before, after) {
  if (before === undefined || after === undefined) return before === after;
  return sameInode(before, after);
}

export function writeIdentityConfig(path, config, { force = false } = {}) {
  const absolute = resolve(path);
  const directory = openSecureConfigDirectory(dirname(absolute), { create: true });
  let tempFd;
  let tempPath;
  let writtenTempStat;
  let renamed = false;
  try {
    const initialTarget = inspectInitTarget(absolute);
    if (initialTarget && !force) {
      throw new Error(
        `agent already exists at ${absolute} (use --force to overwrite — replacing the key loses your identity and reputation)`
      );
    }
    const validated = parseIdentityConfig(JSON.stringify(config));
    const payload = Buffer.from(`${JSON.stringify(validated, null, 2)}\n`, "utf8");
    if (payload.length > MAX_IDENTITY_CONFIG_BYTES) throw new Error("generated agent config is unexpectedly oversized");

    tempPath = join(directory.path, `.agent.json.tmp-${process.pid}-${randomBytes(12).toString("hex")}`);
    tempFd = openSync(
      tempPath,
      fsConstants.O_WRONLY |
        fsConstants.O_CREAT |
        fsConstants.O_EXCL |
        (fsConstants.O_NOFOLLOW ?? 0),
      0o600
    );
    fchmodSync(tempFd, 0o600);
    let tempStat = fstatBigInt(tempFd);
    assertSecureIdentityFileStat(tempStat, tempPath);
    writeFileSync(tempFd, payload);
    fsyncSync(tempFd);
    tempStat = fstatBigInt(tempFd);
    if (tempStat.size !== BigInt(payload.length) || permissions(tempStat) !== 0o600) {
      throw new Error("agent config temporary file was not durably written with mode 0600");
    }
    writtenTempStat = tempStat;
    closeSync(tempFd);
    tempFd = undefined;

    assertRealDirectoryChain(directory.path);
    const directoryPath = lstatBigInt(directory.path);
    const directoryFd = fstatBigInt(directory.fd);
    if (!sameInode(directory.stat, directoryPath) || !sameInode(directory.stat, directoryFd)) {
      throw new Error("PACT_HOME changed before atomic identity replacement");
    }
    assertSecureDirectoryStat(directoryPath, directory.path);
    const finalTarget = inspectInitTarget(absolute);
    if (!targetUnchanged(initialTarget, finalTarget)) {
      throw new Error("agent config target changed before atomic replacement");
    }
    renameSync(tempPath, absolute);
    renamed = true;
    const installed = lstatBigInt(absolute);
    if (!writtenTempStat || !sameInode(writtenTempStat, installed)) {
      throw new Error("agent config target changed during atomic replacement");
    }
    assertSecureIdentityFileStat(installed, absolute);
    fsyncSync(directory.fd);
    const loaded = loadIdentityConfig(absolute);
    if (
      loaded.partyId !== validated.partyId ||
      loaded.privkey !== validated.privkey ||
      loaded.server !== validated.server
    ) {
      throw new Error("agent config changed after atomic replacement");
    }
    return loaded;
  } finally {
    if (tempFd !== undefined) closeSync(tempFd);
    if (!renamed && tempPath) {
      try {
        unlinkSync(tempPath);
      } catch (error) {
        if (error?.code !== "ENOENT") throw error;
      }
    }
    closeSync(directory.fd);
  }
}

function loadConf() {
  return loadIdentityConfig(CONF);
}

function client() {
  const c = loadConf();
  return new PactClient({
    server: validatePactServerUrl(process.env.PACT_SERVER ?? c.server),
    privkey: c.privkey
  });
}

function out(v) {
  console.log(JSON.stringify(v, null, 2));
}

function outResponse(response, body = response.body) {
  out(body);
  if (response.status !== 200) process.exitCode = 1;
  return response.status === 200;
}

function parsePaymentProof(raw) {
  if (!raw) throw new Error("payment proof JSON is required on stdin");
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error("invalid payment proof JSON on stdin");
  }
}

function cancelUsage() {
  return "usage: pact cancel <pactId> --expires-at <unix-ms> [--signatures-stdin]";
}

function parseCancelSignatures(raw) {
  if (!raw) throw new Error("cancellation signatures JSON is required on stdin");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("invalid cancellation signatures JSON on stdin");
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length > 300 ||
    parsed.some(
      (entry) =>
        entry === null ||
        typeof entry !== "object" ||
        Array.isArray(entry) ||
        typeof entry.signer !== "string" ||
        entry.signer.length === 0 ||
        typeof entry.sig !== "string" ||
        entry.sig.length === 0
    )
  ) {
    throw new Error("invalid cancellation signatures JSON on stdin");
  }
  return parsed.map(({ signer, sig }) => ({ signer, sig }));
}

function parseDist(s) {
  // "party:bp,party:bp"; basis points must total 10,000.
  return s.split(",").map((pair) => {
    const i = pair.lastIndexOf(":");
    return { party: pair.slice(0, i), bp: Number(pair.slice(i + 1)) };
  });
}

const EXTERNAL_WALLET_TOOL_ACTIONS = Object.freeze({
  agentcash: Object.freeze(["onboard", "accounts", "balance", "fund"]),
  paysponge: Object.freeze(["init", "balance", "onramp"])
});
const WALLET_TOOL_ACTIONS = Object.freeze({
  mppx: Object.freeze(["create", "import-agentcash", "list", "view"])
});
const CLI_REQUIRE = createRequire(import.meta.url);
const WALLET_COMMANDS = Object.freeze({
  agentcash: Object.freeze({
    label: "AgentCash",
    packageName: "agentcash",
    version: "0.17.0",
    binName: "agentcash",
    binPath: "dist/esm/index.js"
  }),
  paysponge: Object.freeze({
    label: "PaySponge",
    packageName: "spongewallet",
    version: "0.1.127",
    binName: "spongewallet",
    binPath: "bin/spongewallet.js",
    runtimePackages: Object.freeze([
      Object.freeze({
        label: "PaySponge SDK",
        packageName: "@paysponge/sdk",
        version: "0.1.147"
      })
    ])
  }),
  mppx: Object.freeze({
    label: "mppx",
    packageName: "mppx",
    version: MPPX_VERSION,
    binName: "mppx",
    binPath: "./dist/bin.js",
    accountModulePath: "./dist/cli/account.js"
  })
});

function resolveInstalledManifest(fromDirectory, packageName) {
  const packageParts = packageName.split("/");
  let directory = realpathSync(fromDirectory);
  while (true) {
    const candidate = join(directory, "node_modules", ...packageParts, "package.json");
    if (existsSync(candidate)) return realpathSync(candidate);
    const parent = dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  throw new Error(`${packageName} package manifest was not found in the wallet CLI dependency tree`);
}

export function verifyWalletManifest(wallet, manifest) {
  const expected = WALLET_COMMANDS[wallet];
  if (!expected) throw new Error(`unsupported payment wallet: ${wallet}`);
  if (manifest?.name !== expected.packageName || manifest?.version !== expected.version) {
    throw new Error(`${expected.label} dependency mismatch: expected ${expected.packageName}@${expected.version}`);
  }
  const declaredBin = typeof manifest.bin === "string" ? manifest.bin : manifest.bin?.[expected.binName];
  if (declaredBin !== expected.binPath) {
    throw new Error(`${expected.label} dependency has an unexpected CLI entry point`);
  }
  return expected;
}

function resolveWalletPackageRoot(wallet) {
  const expected = WALLET_COMMANDS[wallet];
  if (!expected) throw new Error(`unsupported payment wallet: ${wallet}`);
  let manifestPath;
  try {
    manifestPath = CLI_REQUIRE.resolve(`${expected.packageName}/package.json`);
  } catch (resolutionError) {
    try {
      // ESM packages such as mppx intentionally do not export package.json.
      manifestPath = resolveInstalledManifest(dirname(fileURLToPath(import.meta.url)), expected.packageName);
    } catch (manifestError) {
      throw new Error(
        `${expected.label} ${expected.version} is not installed with Pact CLI: ${
          manifestError instanceof Error ? manifestError.message : resolutionError
        }`
      );
    }
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  verifyWalletManifest(wallet, manifest);
  return realpathSync(dirname(manifestPath));
}

export function resolveWalletExecutable(wallet) {
  const expected = WALLET_COMMANDS[wallet];
  if (!expected || wallet === "mppx") throw new Error(`unsupported external payment wallet: ${wallet}`);
  const packageRoot = resolveWalletPackageRoot(wallet);
  const executable = realpathSync(resolve(packageRoot, expected.binPath));
  const packageRelative = relative(packageRoot, executable);
  if (packageRelative.startsWith("..") || isAbsolute(packageRelative)) {
    throw new Error(`${expected.label} CLI entry point escapes its installed package`);
  }
  for (const runtimePackage of expected.runtimePackages ?? []) {
    const runtimeManifestPath = resolveInstalledManifest(dirname(executable), runtimePackage.packageName);
    const runtimeManifest = JSON.parse(readFileSync(runtimeManifestPath, "utf8"));
    if (
      runtimeManifest.name !== runtimePackage.packageName ||
      runtimeManifest.version !== runtimePackage.version
    ) {
      throw new Error(
        `${runtimePackage.label} dependency mismatch: expected ${runtimePackage.packageName}@${runtimePackage.version}`
      );
    }
  }
  return executable;
}

/**
 * Forward onboarding and top-up commands only. Pact never reads, exports, or
 * re-owns either provider's key material and never downloads wallet code with
 * npx at runtime.
 */
export function runExternalWalletTool(wallet, action, actionArgs = [], spawn = spawnSync) {
  const allowed = EXTERNAL_WALLET_TOOL_ACTIONS[wallet];
  if (!allowed || !allowed.includes(action)) {
    throw new Error(
      "usage: pact wallet agentcash onboard|accounts|balance|fund | pact wallet paysponge init|balance|onramp"
    );
  }
  const executable = resolveWalletExecutable(wallet);
  const result = spawn(process.execPath, [executable, action, ...actionArgs], {
    shell: false,
    stdio: "inherit"
  });
  if (result.error) throw new Error(`could not start ${WALLET_COMMANDS[wallet].label}: ${result.error.message}`);
  return Number.isInteger(result.status) ? result.status : 1;
}

function resolvePinnedMppxAccountModule() {
  const expected = WALLET_COMMANDS.mppx;
  const packageRoot = resolveWalletPackageRoot("mppx");
  const modulePath = realpathSync(resolve(packageRoot, expected.accountModulePath));
  const packageRelative = relative(packageRoot, modulePath);
  if (packageRelative.startsWith("..") || isAbsolute(packageRelative)) {
    throw new Error("mppx keychain API escapes its installed package");
  }
  return modulePath;
}

export async function loadMppxKeychainRuntime(runtime = {}) {
  if (runtime.createKeychain && runtime.generatePrivateKey && runtime.privateKeyToAccount) {
    return runtime;
  }
  const [keychain, accounts] = await Promise.all([
    import(pathToFileURL(resolvePinnedMppxAccountModule()).href),
    import("viem/accounts")
  ]);
  if (
    typeof keychain.createKeychain !== "function" ||
    typeof accounts.generatePrivateKey !== "function" ||
    typeof accounts.privateKeyToAccount !== "function"
  ) {
    throw new Error("pinned mppx keychain API is unavailable");
  }
  return {
    createKeychain: keychain.createKeychain,
    generatePrivateKey: accounts.generatePrivateKey,
    privateKeyToAccount: accounts.privateKeyToAccount,
    ...(process.platform === "darwin"
      ? { storePrivateKey: (name, privateKey) => addMacOsMppxPrivateKey(name, privateKey) }
      : {})
  };
}

/**
 * Add one mppx keychain item without putting the private key in argv, the
 * environment, a temporary file, stdout, or stderr. `security -i` parses the
 * add-only command from its private stdin pipe. It can report command errors
 * with a zero process status, so runWalletTool always performs a readback and
 * address comparison before reporting success.
 */
export function addMacOsMppxPrivateKey(account, privateKey, spawn = spawnSync) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(account ?? "")) {
    throw new Error("invalid mppx keychain account name");
  }
  if (!/^0x[0-9a-f]{64}$/i.test(privateKey ?? "")) {
    throw new Error("mppx private key must be a canonical 32-byte hex value");
  }
  const command = `add-generic-password -s mppx -a ${account} -w ${privateKey}\n`;
  const result = spawn("/usr/bin/security", ["-i"], {
    input: command,
    shell: false,
    stdio: ["pipe", "ignore", "ignore"],
    timeout: 10_000
  });
  if (result?.error || result?.signal || result?.status !== 0) {
    throw new Error("macOS keychain rejected the mppx private-key add request");
  }
}

function walletUsage() {
  return "usage: pact wallet mppx create --account <name> | import-agentcash --account <name> | view --account <name> | list";
}

function accountNameFor(action, actionArgs) {
  if (action === "list") {
    if (actionArgs.length !== 0) throw new Error(walletUsage());
    return undefined;
  }
  let values;
  try {
    ({ values } = parseArgs({
      args: actionArgs,
      options: { account: { type: "string", short: "a" } }
    }));
  } catch {
    throw new Error(walletUsage());
  }
  const name = values.account;
  if (!name || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(name)) {
    throw new Error("mppx account name must use 1-64 letters, numbers, dots, underscores, or hyphens");
  }
  return name;
}

function mppxAccountOutput(name, address, includeNextStep = false) {
  const output = {
    name,
    address: validatedWalletAddress(address, "mppx"),
    keyStorage: "os-keychain",
    rails: {
      x402: {
        network: `eip155:${BASE_CHAIN_ID}`,
        networkName: "Base mainnet",
        asset: "USDC",
        assetAddress: BASE_USDC,
        minimumFundingAmount: X402_MIN_FUNDING_AMOUNT,
        collectionGas: "facilitator-sponsored"
      },
      mpp: {
        network: `eip155:${TEMPO_CHAIN_ID}`,
        networkName: "Tempo mainnet",
        asset: "USDC.e",
        assetAddress: TEMPO_USDCE,
        minimumFundingAmount: MPP_MIN_FUNDING_AMOUNT,
        maximumNetworkFee: {
          amount: MPP_MAX_TOTAL_FEE_ATOMIC_USDCE,
          asset: "USDC.e",
          display: `${MPP_MAX_TOTAL_FEE_USDCE} USDC.e`,
          separateFromMaxAmount: true
        }
      }
    }
  };
  return includeNextStep
    ? {
        ...output,
        nextStep:
          `Before funding, run pact get <pactId>, derive the exact deposit-plus-bond principal, and ` +
          `obtain approval for that cap. For x402, fund this address with USDC on Base mainnet; ` +
          `collection gas is facilitator-sponsored. For MPP, fund it with USDC.e on Tempo mainnet plus a ` +
          `transaction-fee reserve. --max-amount caps principal; MPP separately enforces a ` +
          `${MPP_MAX_TOTAL_FEE_USDCE} USDC.e network-fee ceiling. Then run: ` +
          `pact fund <pactId> --payer mppx --account ${name} --max-amount <approved-principal-cap-USD>`
      }
    : output;
}

function defaultAgentCashWalletPath() {
  return join(homedir(), ".agentcash", "wallet.json");
}

export function readPrivateAgentCashWallet(path = defaultAgentCashWalletPath()) {
  const pathStat = lstatSync(path);
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (
    pathStat.isSymbolicLink() ||
    !pathStat.isFile() ||
    (uid !== undefined && pathStat.uid !== uid) ||
    (pathStat.mode & 0o777) !== 0o600
  ) {
    throw new Error("AgentCash wallet must be an owned regular file with mode 0600");
  }
  let fd;
  try {
    fd = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
    const opened = fstatSync(fd);
    if (opened.dev !== pathStat.dev || opened.ino !== pathStat.ino || opened.size > 16_384) {
      throw new Error("AgentCash wallet changed during secure open");
    }
    const wallet = JSON.parse(readFileSync(fd, "utf8"));
    if (!/^0x[0-9a-f]{64}$/i.test(wallet?.privateKey ?? "")) {
      throw new Error("AgentCash wallet contains an invalid private key");
    }
    if (!/^0x[0-9a-f]{40}$/i.test(wallet?.address ?? "")) {
      throw new Error("AgentCash wallet contains an invalid public address");
    }
    return { privateKey: wallet.privateKey, address: wallet.address };
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * Manage only named mppx OS-keychain entries. This deliberately avoids the
 * upstream account CLI because its create command starts an unrelated funding
 * request. Pact account creation performs no network request or payment.
 */
export async function runWalletTool(wallet, action, actionArgs = [], runtime = {}) {
  const allowed = WALLET_TOOL_ACTIONS[wallet];
  if (!allowed || !allowed.includes(action)) {
    throw new Error(walletUsage());
  }
  assertMppxKeychainOnly();
  const name = accountNameFor(action, actionArgs);
  const { createKeychain, generatePrivateKey, privateKeyToAccount, storePrivateKey } =
    await loadMppxKeychainRuntime(runtime);

  if (action === "list") {
    const names = (await createKeychain().list()).sort();
    return { accounts: names, keyStorage: "os-keychain" };
  }

  const keychain = createKeychain(name);
  const existing = await keychain.get();
  if (action === "view") {
    if (!existing) throw new Error(`mppx account "${name}" was not found in the OS keychain`);
    return mppxAccountOutput(name, privateKeyToAccount(existing).address);
  }
  if (existing) throw new Error(`mppx account "${name}" already exists in the OS keychain`);

  const imported = action === "import-agentcash";
  const sourceWallet = imported
    ? await (runtime.readAgentCashWallet ?? readPrivateAgentCashWallet)()
    : undefined;
  const privateKey = sourceWallet?.privateKey ?? generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  if (
    imported &&
    validatedWalletAddress(sourceWallet.address, "AgentCash").toLowerCase() !==
      account.address.toLowerCase()
  ) {
    throw new Error("AgentCash wallet public address does not match its private key");
  }
  if (storePrivateKey) await storePrivateKey(name, privateKey);
  else if (process.platform === "darwin") {
    addMacOsMppxPrivateKey(name, privateKey, runtime.spawnSecurity ?? spawnSync);
  } else {
    await keychain.set(privateKey);
  }
  const stored = await keychain.get();
  if (!stored || privateKeyToAccount(stored).address.toLowerCase() !== account.address.toLowerCase()) {
    throw new Error(`mppx account "${name}" could not be verified in the OS keychain`);
  }
  const output = mppxAccountOutput(name, account.address, true);
  return imported
    ? { ...output, importedFrom: "agentcash", sourceAddressVerified: true }
    : output;
}

export function paymentProtocol(rail, requested) {
  if (requested !== undefined && requested !== "mpp" && requested !== "x402") {
    throw new Error("--protocol must be mpp or x402");
  }
  if (rail !== "mpp" && rail !== "x402") {
    throw new Error(`Pact rail '${rail}' is not payable by mppx (expected mpp or x402)`);
  }
  if (requested !== undefined && requested !== rail) {
    throw new Error(`--protocol ${requested} does not match Pact rail ${rail}`);
  }
  return requested ?? rail;
}

function validatedWalletAddress(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{40}$/i.test(value)) {
    throw new Error(`${label} did not return a valid EVM payment address`);
  }
  return value;
}

export function payerAddress(suppliedAddress, mppxAccount) {
  const derived = validatedWalletAddress(mppxAccount?.address, "mppx");
  if (suppliedAddress && suppliedAddress.toLowerCase() !== derived.toLowerCase()) {
    throw new Error(`--rail-address does not match the active mppx wallet (${derived})`);
  }
  return derived;
}

export function assertFundingWithinLimit(pact, partyId, maxAmount) {
  const party = pact.parties?.find((candidate) => candidate.party === partyId);
  let requirement;
  if (party) {
    if (party.confirmed || party.reserved || BigInt(party.paidPot ?? "0") + BigInt(party.paidBond ?? "0") > 0n) {
      throw new Error("this Pact party is already funded or has a payment in progress");
    }
    requirement = BigInt(party.deposit.amount) + BigInt(party.bond.amount);
  } else {
    const slots = pact.openSlots;
    if (!slots || slots.taken >= slots.count) throw new Error("this identity has no available Pact funding slot");
    requirement = BigInt(slots.deposit.amount) + BigInt(slots.bond.amount);
  }
  if (requirement <= 0n) throw new Error("this Pact party has no funding requirement");
  if (requirement > usdMinorUnits(maxAmount)) {
    throw new Error(`Pact requires ${requirement} USDC minor units, above --max-amount ${maxAmount}`);
  }
  return requirement;
}

const [cmd, ...rest] = process.argv.slice(2);

async function main() {
  switch (cmd) {
    case "init": {
      const { values } = parseArgs({ args: rest, options: { server: { type: "string" }, force: { type: "boolean" } } });
      const server = validatePactServerUrl(values.server ?? "https://api.pact.sh");
      const k = generateKeypair();
      const saved = writeIdentityConfig(
        CONF,
        { privkey: hex.encode(k.privkey), partyId: k.partyId, server },
        { force: values.force === true }
      );
      out({ partyId: saved.partyId, server: saved.server, config: CONF });
      break;
    }
    case "whoami": {
      const c = loadConf();
      out({ partyId: c.partyId, server: c.server });
      break;
    }
    case "wallet": {
      const [wallet, action, ...actionArgs] = rest;
      if (wallet !== "mppx") {
        process.exitCode = runExternalWalletTool(wallet, action, actionArgs);
        return;
      }
      out(await runWalletTool(wallet, action, actionArgs));
      break;
    }
    case "create": {
      // pact create --file spec.json | echo '{...}' | pact create
      const { values } = parseArgs({ args: rest, options: { file: { type: "string" } } });
      const raw = values.file ? readFileSync(values.file, "utf8") : readFileSync(0, "utf8");
      out(await client().createPact(JSON.parse(raw)));
      break;
    }
    case "fund": {
      if (rest.some((arg) => /^--proof(?:=|$)/.test(arg))) {
        throw new Error(
          "usage: pact fund <pactId> [--rail-address <address>] [--proof-stdin] | --payer mppx --account <name> --max-amount <USD>"
        );
      }
      const { positionals, values } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: {
          "rail-address": { type: "string" },
          "proof-stdin": { type: "boolean" },
          payer: { type: "string" },
          protocol: { type: "string" },
          account: { type: "string" },
          "max-amount": { type: "string" }
        }
      });
      if (positionals.length !== 1) {
        throw new Error(
          "usage: pact fund <pactId> [--rail-address <address>] [--proof-stdin] | --payer mppx --account <name> --max-amount <USD>"
        );
      }
      if (values.payer && values.payer !== "mppx") throw new Error("--payer must be mppx");
      if (!values.payer && (values.protocol || values.account || values["max-amount"])) {
        throw new Error("--protocol, --account, and --max-amount require --payer mppx");
      }
      if (values.payer === "mppx") {
        if (values["proof-stdin"]) throw new Error("--proof-stdin cannot be combined with --payer mppx");
        // Fail before contacting Pact or resolving a wallet. mppx otherwise
        // gives a raw environment key precedence over its OS keychain.
        assertMppxKeychainOnly();
        if (!values["max-amount"]) throw new Error("--max-amount is required with --payer mppx");
        if (!values.account) throw new Error("--account is required with --payer mppx");
        const c = client();
        const pactId = positionals[0];
        const pact = (await c.getPact(pactId)).pact;
        const protocol = paymentProtocol(pact.rail, values.protocol);
        const maxAmount = values["max-amount"];
        const fundingAmount = assertFundingWithinLimit(pact, c.partyId, maxAmount);
        const mppxAccount = await resolveMppxKeychainAccount(values.account);
        const railAddress = payerAddress(values["rail-address"], mppxAccount);
        const request = await c.prepareFund(pactId, { railAddress, stateNonce: pact.stateNonce });
        const result = await runMppxPayment(
          request,
          {
            account: values.account,
            expectedAmount: fundingAmount.toString(),
            expectedPayer: railAddress,
            expectedRecipient: pact.escrowAccount,
            maxAmount,
            pactHome: CONF_DIR,
            protocol
          },
          { account: mppxAccount }
        );
        if (result.stdout) process.stdout.write(result.stdout);
        if (result.stderr) process.stderr.write(result.stderr);
        process.exitCode = result.status;
        return;
      }
      const proof = values["proof-stdin"]
        ? parsePaymentProof(await readSecretInput({ prompt: "Payment proof JSON: " }))
        : undefined;
      const r = await client().fund(positionals[0], {
        railAddress: values["rail-address"],
        proof
      });
      outResponse(r);
      break;
    }
    case "withdraw": {
      outResponse(await client().withdraw(rest[0]));
      break;
    }
    case "get": {
      out(await client().getPact(rest[0]));
      break;
    }
    case "list": {
      const { values } = parseArgs({
        args: rest,
        options: { party: { type: "string" }, state: { type: "string" }, group: { type: "string" }, mine: { type: "boolean" } }
      });
      const c = client();
      out(await c.listPacts({ party: values.mine ? c.partyId : values.party, state: values.state, groupId: values.group }));
      break;
    }
    case "put": {
      const [pactId, file] = rest;
      outResponse(await client().putBlob(pactId, readFileSync(file)));
      break;
    }
    case "link": {
      const [pactId, hash] = rest;
      const c = client();
      const response = await c.link(pactId, hash);
      const body = response.body;
      // Return an absolute URL so the recipient can open it directly.
      if (typeof body.url === "string" && body.url.startsWith("/")) body.url = c.server + body.url;
      outResponse(response, body);
      break;
    }
    case "propose": {
      const { positionals, values } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: {
          dist: { type: "string" },
          blob: { type: "string", multiple: true },
          url: { type: "string", multiple: true },
          note: { type: "string" }
        }
      });
      const evidence = [
        ...(values.blob ?? []).map((b) => ({ blob: b })),
        ...(values.url ?? []).map((u) => ({ url: u })),
        ...(values.note ? [{ note: values.note }] : [])
      ];
      const r = await client().propose(positionals[0], evidence, parseDist(values.dist));
      outResponse(r);
      break;
    }
    case "cosign": {
      outResponse(await client().cosign(rest[0]));
      break;
    }
    case "object": {
      const { positionals, values } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: { reason: { type: "string" } }
      });
      outResponse(await client().object(positionals[0], values.reason ?? "objection"));
      break;
    }
    case "cancel": {
      if (rest.some((arg) => /^--signatures(?:=|$)/.test(arg))) {
        throw new Error(cancelUsage());
      }
      const { positionals, values } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: {
          "expires-at": { type: "string" },
          "signatures-stdin": { type: "boolean" }
        }
      });
      const expiresAt = Number(values["expires-at"]);
      if (positionals.length !== 1 || !Number.isSafeInteger(expiresAt) || expiresAt <= 0) {
        throw new Error(cancelUsage());
      }
      const pactId = positionals[0];
      const c = client();
      const stateNonce = await c.nonce(pactId);
      const own = { signer: c.partyId, sig: c.cancelSig(pactId, stateNonce, expiresAt) };
      if (!values["signatures-stdin"]) {
        out({
          pactId,
          stateNonce,
          expiresAt,
          signature: own,
          nextStep:
            "Collect a signature with the same stateNonce and expiresAt from every pact party, then submit their JSON array with --signatures-stdin."
        });
        break;
      }
      const signatures = parseCancelSignatures(readFileSync(0, "utf8"));
      const sigs = signatures.some(({ signer }) => signer === c.partyId) ? signatures : [...signatures, own];
      outResponse(await c.cancel(pactId, expiresAt, sigs));
      break;
    }
    case "poke": {
      outResponse(await client().poke(rest[0]));
      break;
    }
    case "bind-address": {
      const { values } = parseArgs({
        args: rest,
        options: { rail: { type: "string" }, address: { type: "string" } }
      });
      outResponse(await client().bindRailAddress(values.rail ?? "x402", values.address));
      break;
    }
    case "offers": {
      const [sub, ...oRest] = rest;
      const c = client();
      if (sub === "search" || sub === "watch") {
        const { values } = parseArgs({
          args: oRest,
          options: { tags: { type: "string" }, q: { type: "string" }, by: { type: "string" } }
        });
        const q = { tags: values.tags?.split(","), q: values.q, by: values.by };
        out(sub === "search" ? await c.searchOffers(q) : await c.watchOffers(q));
      } else if (sub === "accept") {
        const { positionals, values } = parseArgs({
          args: oRest,
          allowPositionals: true,
          options: { "acceptance-id": { type: "string" } }
        });
        if (positionals.length !== 1) {
          throw new Error("usage: pact offers accept <offerId> [--acceptance-id <id>]");
        }
        outResponse(
          await c.acceptOffer(positionals[0], {
            acceptanceId: values["acceptance-id"]
          })
        );
      } else if (sub === "publish") {
        const { values } = parseArgs({
          args: oRest,
          options: {
            pact: { type: "string" },
            template: { type: "string" },
            inventory: { type: "string" },
            tags: { type: "string" },
            text: { type: "string" },
            "expires-in": { type: "string" }
          }
        });
        const inventory = values.inventory === undefined ? undefined : Number(values.inventory);
        if (inventory !== undefined && (!Number.isInteger(inventory) || inventory < 1 || inventory > 10_000)) {
          throw new Error("--inventory must be an integer from 1 to 10000");
        }
        outResponse(
          await c.publishOffer({
            pactId: values.pact,
            template: values.template ? JSON.parse(values.template) : undefined,
            inventory,
            tags: (values.tags ?? "").split(",").filter(Boolean),
            text: values.text ?? "",
            expiresAt: Date.now() + Number(values["expires-in"] ?? 86_400_000)
          })
        );
      } else {
        console.error("usage: pact offers search|watch|publish|accept ...");
        process.exit(1);
      }
      break;
    }
    case "quickstart": {
      // Print a one-to-one file trade template for editing before `pact create`.
      // Production onboarding is real-money first; mock must be chosen explicitly.
      const { values } = parseArgs({
        args: rest,
        options: { rail: { type: "string" } }
      });
      const rail = values.rail ?? "x402";
      if (!new Set(["x402", "mpp", "mock"]).has(rail)) {
        throw new Error("--rail must be x402, mpp, or mock");
      }
      const c = loadConf();
      out({
        rail,
        parties: [
          { party: "<PROVIDER_PARTY_ID>", deposit: usdc(0), bond: usdc(5000), required: true },
          { party: c.partyId, deposit: usdc(100000), bond: usdc(5000), required: true }
        ],
        proposer: "<PROVIDER_PARTY_ID>",
        terms: { spec: "Describe what must be delivered, including how it will be judged" },
        minParties: 2,
        windows: { fund: 3600000, perform: 86400000, object: 3600000 }
      });
      break;
    }
    case "request-access": {
      // invite-mode servers: writes return 403 "access_required" until this loop is done
      const { values } = parseArgs({
        args: rest,
        options: { email: { type: "string" }, "use-case": { type: "string" } }
      });
      if (!values.email) {
        console.error('usage: pact request-access --email you@example.com [--use-case "..."]');
        process.exit(1);
      }
      const r = await client().requestAccess(values.email, values["use-case"]);
      outResponse(r);
      if (r.status === 200) console.error("Check your inbox, then run: pact verify (TTY input is hidden)");
      break;
    }
    case "verify": {
      if (rest.length !== 0) throw new Error("usage: pact verify (reads the OTP from stdin)");
      const otp = await readSecretInput({ prompt: "OTP: " });
      if (!otp) throw new Error("OTP is required on stdin");
      const r = await client().verifyAccess(otp);
      outResponse(r);
      if (r.status === 200 && r.body.status === "allowed") {
        console.error("Access granted. You can now use Pact write commands.");
      } else if (r.status === 200 && r.body.status === "pending") {
        console.error("Email verified. Access is pending operator approval. Wait for the approval email, then run: pact access");
      }
      break;
    }
    case "access": {
      out(await client().accessStatus());
      break;
    }
    case "admin": {
      // operator only — local identity must be the server's PACT_ADMIN_PARTY
      const [action, target] = rest;
      const ok = ["allow", "revoke", "allow-email", "deny-email", "pending"].includes(action);
      if (!ok) {
        console.error("usage: pact admin allow|revoke <partyId> | allow-email|deny-email <email|@domain> | pending");
        process.exit(1);
      }
      const r = await client().accessAdmin(action, target);
      outResponse(r);
      break;
    }
    case "version":
    case "--version": {
      out({ pact: "0.3.3" });
      break;
    }
    default:
      console.error(`pact — agent escrow CLI
usage:
  pact init --server <URL>          create identity (~/.pact/agent.json)
  pact whoami
  pact wallet agentcash onboard|accounts|balance|fund   run pinned local AgentCash CLI
  pact wallet paysponge init|balance|onramp             run pinned local PaySponge CLI
  pact wallet mppx create --account <name>    create a Base/Tempo payment key (no network request)
  pact wallet mppx import-agentcash --account <name>    copy the verified 0600 AgentCash key into OS keychain
  pact wallet mppx view --account <name> | list   view one account or list account names
  pact access                       access status on this server (invite mode)
  pact request-access --email <e>   get an OTP by email  [--use-case "..."]
  pact verify                       read OTP from stdin; TTY input is hidden (recommended)
  pact quickstart [--rail x402|mpp|mock]
                                      1:1 trade spec; default x402, mock is local simulation only
  pact create --file spec.json      (or stdin)
  pact fund <pactId>                mock rail (payment proof is automatic)
  pact fund <pactId> --rail-address <addr> --proof-stdin   operator recovery proof from stdin
  pact fund <pactId> --payer mppx --account <name> [--protocol x402|mpp]
    --max-amount <USD>              required; caps principal; MPP has a separate hard 0.01 USDC.e fee ceiling
  pact withdraw <pactId>
  pact get <pactId> | pact list --mine|--party|--state|--group
  pact put <pactId> <file>          upload deliverable → hash
  pact link <pactId> <hash>         short-lived download link (absolute URL)
  pact propose <pactId> --dist "party:bp,..." [--blob h] [--url u] [--note n]
  pact cosign|object|poke <pactId>  (object: --reason "...")
  pact cancel <pactId> --expires-at <unix-ms> [--signatures-stdin]
                                      prepare or submit unanimous cancellation
  pact bind-address --rail <rail> --address <addr>   bind payout address
  pact offers publish --pact <id>|--template '<json>' [--inventory N] --tags a,b --text "..."
  pact offers accept <offerId> [--acceptance-id <id>]
  pact offers search|watch --tags a,b [--q text] [--by party]
  pact admin allow|revoke|allow-email|deny-email|pending   (operator)`);
      process.exit(cmd && cmd !== "--help" && cmd !== "help" ? 1 : 0);
  }
}

function isMain() {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === fileURLToPath(import.meta.url);
  } catch {
    return false;
  }
}

if (isMain()) {
  main().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
}
