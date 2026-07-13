#!/usr/bin/env node
// Pact agent escrow CLI. Config: ~/.pact/agent.json {privkey, partyId, server}
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { PactClient, generateKeypair, usdc } from "../lib/sdk.js";
import {
  MPPX_VERSION,
  MPP_MIN_FUNDING_AMOUNT,
  TEMPO_CHAIN_ID,
  TEMPO_USDCE,
  assertMppxKeychainOnly,
  resolveMppxKeychainAccount,
  runMppxPayment,
  usdMinorUnits
} from "../lib/mppx-payer.js";
import { readSecretInput } from "../lib/secure-input.js";
import { hex } from "@scure/base";

const CONF_DIR = process.env.PACT_HOME ?? join(homedir(), ".pact");
const CONF = join(CONF_DIR, "agent.json");

function loadConf() {
  if (!existsSync(CONF)) {
    console.error(`no agent config at ${CONF} — run: pact init --server <URL>`);
    process.exit(1);
  }
  return JSON.parse(readFileSync(CONF, "utf8"));
}

function client() {
  const c = loadConf();
  return new PactClient({ server: process.env.PACT_SERVER ?? c.server, privkey: c.privkey });
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

const WALLET_TOOL_ACTIONS = Object.freeze({
  mppx: Object.freeze(["create", "list", "view"])
});
const CLI_REQUIRE = createRequire(import.meta.url);
const WALLET_COMMANDS = Object.freeze({
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
    privateKeyToAccount: accounts.privateKeyToAccount
  };
}

function walletUsage() {
  return "usage: pact wallet mppx create --account <name> | view --account <name> | list";
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
    network: `eip155:${TEMPO_CHAIN_ID}`,
    networkName: "Tempo mainnet",
    asset: "USDC.e",
    assetAddress: TEMPO_USDCE,
    minimumFundingAmount: MPP_MIN_FUNDING_AMOUNT
  };
  return includeNextStep
    ? {
        ...output,
        nextStep:
          `Fund this address on Tempo mainnet with enough USDC.e for the Pact requirement plus a ` +
          `Tempo transaction-fee reserve. --max-amount caps payment principal, not network fees. Then run: ` +
          `pact fund <pactId> --payer mppx --account ${name} --max-amount 0.01`
      }
    : output;
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
  const { createKeychain, generatePrivateKey, privateKeyToAccount } =
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

  const privateKey = generatePrivateKey();
  const account = privateKeyToAccount(privateKey);
  await keychain.set(privateKey);
  const stored = await keychain.get();
  if (!stored || privateKeyToAccount(stored).address.toLowerCase() !== account.address.toLowerCase()) {
    throw new Error(`mppx account "${name}" could not be verified in the OS keychain`);
  }
  return mppxAccountOutput(name, account.address, true);
}

export function paymentProtocol(rail, requested) {
  if (requested !== undefined && requested !== "mpp") throw new Error("--protocol must be mpp");
  if (rail === "x402") {
    throw new Error("Pact x402 currently uses an X-PAYMENT proof; use --proof-stdin instead of --payer mppx");
  }
  if (rail !== "mpp") throw new Error(`Pact rail '${rail}' is not payable by mppx (expected mpp)`);
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
      if (existsSync(CONF) && !values.force) {
        console.error(`agent already exists at ${CONF} (use --force to overwrite — replacing the key loses your identity and reputation)`);
        process.exit(1);
      }
      const k = generateKeypair();
      mkdirSync(CONF_DIR, { recursive: true });
      writeFileSync(
        CONF,
        JSON.stringify({ privkey: hex.encode(k.privkey), partyId: k.partyId, server: values.server ?? "https://api.pact.sh" }, null, 2),
        { mode: 0o600 }
      );
      out({ partyId: k.partyId, server: values.server ?? "https://api.pact.sh", config: CONF });
      break;
    }
    case "whoami": {
      const c = loadConf();
      out({ partyId: c.partyId, server: c.server });
      break;
    }
    case "wallet": {
      const [wallet, action, ...actionArgs] = rest;
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
      } else if (sub === "publish") {
        const { values } = parseArgs({
          args: oRest,
          options: {
            pact: { type: "string" },
            template: { type: "string" },
            tags: { type: "string" },
            text: { type: "string" },
            "expires-in": { type: "string" }
          }
        });
        outResponse(
          await c.publishOffer({
            pactId: values.pact,
            template: values.template ? JSON.parse(values.template) : undefined,
            tags: (values.tags ?? "").split(",").filter(Boolean),
            text: values.text ?? "",
            expiresAt: Date.now() + Number(values["expires-in"] ?? 86_400_000)
          })
        );
      } else {
        console.error("usage: pact offers search|watch|publish ...");
        process.exit(1);
      }
      break;
    }
    case "quickstart": {
      // Print a one-to-one file trade template for editing before `pact create`.
      const c = loadConf();
      out({
        rail: "mock",
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
      out({ pact: "0.3.0" });
      break;
    }
    default:
      console.error(`pact — agent escrow CLI
usage:
  pact init --server <URL>          create identity (~/.pact/agent.json)
  pact whoami
  pact wallet mppx create --account <name>    create a Tempo mainnet payment key (no network request)
  pact wallet mppx view --account <name> | list   view one account or list account names
  pact access                       access status on this server (invite mode)
  pact request-access --email <e>   get an OTP by email  [--use-case "..."]
  pact verify                       read OTP from stdin; TTY input is hidden (recommended)
  pact quickstart                   1:1 trade spec template
  pact create --file spec.json      (or stdin)
  pact fund <pactId>                mock rail (payment proof is automatic)
  pact fund <pactId> --rail-address <addr> --proof-stdin   operator recovery proof from stdin
  pact fund <pactId> --payer mppx --account <name> [--protocol mpp]
    --max-amount <USD>              required; caps payment principal, not Tempo network fees
  pact withdraw <pactId>
  pact get <pactId> | pact list --mine|--party|--state|--group
  pact put <pactId> <file>          upload deliverable → hash
  pact link <pactId> <hash>         short-lived download link (absolute URL)
  pact propose <pactId> --dist "party:bp,..." [--blob h] [--url u] [--note n]
  pact cosign|object|poke <pactId>  (object: --reason "...")
  pact cancel <pactId> --expires-at <unix-ms> [--signatures-stdin]
                                      prepare or submit unanimous cancellation
  pact bind-address --rail <rail> --address <addr>   bind payout address
  pact offers publish --pact <id>|--template '<json>' --tags a,b --text "..."
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
