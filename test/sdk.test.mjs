import assert from "node:assert/strict";
import test from "node:test";
import { PactClient, signCanonical } from "../lib/sdk.js";

test("download preserves absolute URLs and resolves relative URLs against the Pact server", async (t) => {
  const originalFetch = globalThis.fetch;
  const targets = [];
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  globalThis.fetch = async (target) => {
    targets.push(String(target));
    return new Response("PACT");
  };

  const client = new PactClient({ server: "https://api.pact.sh", privkey: "01".repeat(32) });
  await client.download("https://api.runaic.com/v1/storage/blob/example?signature=redacted");
  await client.download("/dl/local-token");

  assert.deepEqual(targets, [
    "https://api.runaic.com/v1/storage/blob/example?signature=redacted",
    "https://api.pact.sh/dl/local-token"
  ]);
});

test("download surfaces a non-success response", async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  globalThis.fetch = async () => new Response("forbidden", { status: 403 });

  const client = new PactClient({ server: "https://api.pact.sh", privkey: "01".repeat(32) });
  await assert.rejects(() => client.download("/dl/expired"), /download 403/);
});

test("every SignedCall uses the canonical route action and signs it", async (t) => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  t.after(() => {
    globalThis.fetch = originalFetch;
  });

  globalThis.fetch = async (target, options = {}) => {
    const url = new URL(String(target));
    const body = options.body ? JSON.parse(String(options.body)) : undefined;
    requests.push({ method: options.method ?? "GET", path: url.pathname, body });
    const response =
      (options.method ?? "GET") === "GET" && url.pathname === "/pacts/p_test"
        ? { pact: { id: "p_test", stateNonce: 7 } }
        : url.pathname === "/pacts"
          ? { pact: { id: "p_test" } }
          : { ok: true };
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  const privkey = "01".repeat(32);
  const client = new PactClient({ server: "https://api.pact.sh", privkey });
  await client.createPact({ rail: "mock" });
  await client.fund("p_test");
  await client.withdraw("p_test");
  await client.propose("p_test", [{ note: "done" }], [{ party: client.partyId, bp: 10000 }]);
  await client.cosign("p_test");
  await client.object("p_test", "missing requirement");
  await client.cancel("p_test", 2_000_000_000_000, [{ signer: client.partyId, sig: "00" }]);
  await client.requestAccess("user@example.com", "agent trade");
  await client.verifyAccess("123456");
  await client.accessAdmin("pending");
  await client.bindRailAddress("x402", "0x1234");

  const expected = new Map([
    ["/pacts", "pacts.create"],
    ["/pacts/p_test/fund", "pacts.fund"],
    ["/pacts/p_test/withdraw", "pacts.withdraw"],
    ["/pacts/p_test/propose", "pacts.propose"],
    ["/pacts/p_test/cosign", "pacts.cosign"],
    ["/pacts/p_test/object", "pacts.object"],
    ["/pacts/p_test/cancel", "pacts.cancel"],
    ["/access/request", "access.request"],
    ["/access/verify", "access.verify"],
    ["/access/admin", "access.admin"],
    ["/rails/x402/address", "rails.bindAddress"]
  ]);

  for (const [path, action] of expected) {
    const request = requests.find((item) => item.method === "POST" && item.path === path);
    assert.ok(request, `missing request for ${path}`);
    assert.equal(request.body.action, action);
    const { sig, ...unsigned } = request.body;
    assert.equal(sig, signCanonical(unsigned, privkey), `${action} signature must cover action`);
    assert.notEqual(sig, signCanonical({ ...unsigned, action: `${action}.replay` }, privkey));
  }
});
