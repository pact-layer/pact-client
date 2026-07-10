#!/usr/bin/env node
// pact — 에이전트 escrow CLI. 설정: ~/.pact/agent.json {privkey, partyId, server}
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { PactClient, generateKeypair, usdc } from "../lib/sdk.js";
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

function parseDist(s) {
  // "party:bp,party:bp" — bp 합 10000
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
        JSON.stringify({ privkey: hex.encode(k.privkey), partyId: k.partyId, server: values.server ?? "http://localhost:8402" }, null, 2),
        { mode: 0o600 }
      );
      out({ partyId: k.partyId, server: values.server ?? "http://localhost:8402", config: CONF });
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
      const { positionals, values } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: { "rail-address": { type: "string" }, proof: { type: "string" } }
      });
      const r = await client().fund(positionals[0], {
        railAddress: values["rail-address"],
        proof: values.proof ? JSON.parse(values.proof) : undefined
      });
      out(r.body);
      process.exit(r.status === 200 ? 0 : 1);
      break;
    }
    case "withdraw": {
      out((await client().withdraw(rest[0])).body);
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
      out((await client().putBlob(pactId, readFileSync(file))).body);
      break;
    }
    case "link": {
      const [pactId, hash] = rest;
      const c = client();
      const body = (await c.link(pactId, hash)).body;
      // 상대 url을 절대 URL로 — 상대방이 그대로 열 수 있게
      if (typeof body.url === "string" && body.url.startsWith("/")) body.url = c.server + body.url;
      out(body);
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
      out(r.body);
      process.exit(r.status === 200 ? 0 : 1);
      break;
    }
    case "cosign": {
      out((await client().cosign(rest[0])).body);
      break;
    }
    case "object": {
      const { positionals, values } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: { reason: { type: "string" } }
      });
      out((await client().object(positionals[0], values.reason ?? "objection")).body);
      break;
    }
    case "poke": {
      out((await client().poke(rest[0])).body);
      break;
    }
    case "bind-address": {
      const { values } = parseArgs({
        args: rest,
        options: { rail: { type: "string" }, address: { type: "string" } }
      });
      out((await client().bindRailAddress(values.rail ?? "x402", values.address)).body);
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
        out(
          (
            await c.publishOffer({
              pactId: values.pact,
              template: values.template ? JSON.parse(values.template) : undefined,
              tags: (values.tags ?? "").split(",").filter(Boolean),
              text: values.text ?? "",
              expiresAt: Date.now() + Number(values["expires-in"] ?? 86_400_000)
            })
          ).body
        );
      } else {
        console.error("usage: pact offers search|watch|publish ...");
        process.exit(1);
      }
      break;
    }
    case "quickstart": {
      // 1:1 파일 거래 스펙 템플릿 출력 — 편집해서 pact create로
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
    case "version":
    case "--version": {
      out({ pact: "0.1.1" });
      break;
    }
    default:
      console.error(`pact — agent escrow CLI
usage:
  pact init --server <URL>          create identity (~/.pact/agent.json)
  pact whoami
  pact quickstart                   1:1 trade spec template
  pact create --file spec.json      (or stdin)
  pact fund <pactId>                deposit via 402 flow (funding = acceptance)
  pact withdraw <pactId>
  pact get <pactId> | pact list --mine|--party|--state|--group
  pact put <pactId> <file>          upload deliverable → hash
  pact link <pactId> <hash>         short-lived download link (absolute URL)
  pact propose <pactId> --dist "party:bp,..." [--blob h] [--url u] [--note n]
  pact cosign|object|poke <pactId>  (object: --reason "...")
  pact bind-address --rail <rail> --address <addr>   bind payout address
  pact offers publish --pact <id>|--template '<json>' --tags a,b --text "..."
  pact offers search|watch --tags a,b [--q text] [--by party]`);
      process.exit(cmd && cmd !== "--help" && cmd !== "help" ? 1 : 0);
  }
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
