#!/usr/bin/env node
// Pact agent escrow CLI. Config: ~/.pact/agent.json {privkey, partyId, server}
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { PactClient, generateKeypair, usdc } from "../lib/sdk.js";
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
    case "create": {
      // pact create --file spec.json | echo '{...}' | pact create
      const { values } = parseArgs({ args: rest, options: { file: { type: "string" } } });
      const raw = values.file ? readFileSync(values.file, "utf8") : readFileSync(0, "utf8");
      out(await client().createPact(JSON.parse(raw)));
      break;
    }
    case "fund": {
      if (rest.some((arg) => /^--proof(?:=|$)/.test(arg))) {
        throw new Error("usage: pact fund <pactId> [--rail-address <address>] [--proof-stdin]");
      }
      const { positionals, values } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: {
          "rail-address": { type: "string" },
          "proof-stdin": { type: "boolean" }
        }
      });
      if (positionals.length !== 1) {
        throw new Error("usage: pact fund <pactId> [--rail-address <address>] [--proof-stdin]");
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
      out({ pact: "0.2.3" });
      break;
    }
    default:
      console.error(`pact — agent escrow CLI
usage:
  pact init --server <URL>          create identity (~/.pact/agent.json)
  pact whoami
  pact access                       access status on this server (invite mode)
  pact request-access --email <e>   get an OTP by email  [--use-case "..."]
  pact verify                       read OTP from stdin; TTY input is hidden (recommended)
  pact quickstart                   1:1 trade spec template
  pact create --file spec.json      (or stdin)
  pact fund <pactId>                mock rail (payment proof is automatic)
  pact fund <pactId> --rail-address <addr> --proof-stdin   real rail; proof from stdin
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

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
