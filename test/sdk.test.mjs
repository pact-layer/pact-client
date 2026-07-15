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

test("prepareFund creates one action-bound request with an encoded Pact ID", async () => {
  const client = new PactClient({ server: "https://api.pact.sh/", privkey: "01".repeat(32) });
  client.getPact = async () => ({ pact: { id: "p/a", stateNonce: 13 } });

  const request = await client.prepareFund("p/a", {
    railAddress: "0x1111111111111111111111111111111111111111"
  });

  assert.equal(request.url, "https://api.pact.sh/pacts/p%2Fa/fund");
  assert.equal(request.method, "POST");
  assert.deepEqual(request.headers, { "content-type": "application/json" });
  assert.equal(request.body.action, "pacts.fund");
  assert.equal(request.body.pactId, "p/a");
  assert.equal(request.body.stateNonce, 13);
  assert.deepEqual(request.body.call, { railAddress: "0x1111111111111111111111111111111111111111" });
  const { sig, ...unsigned } = request.body;
  assert.equal(sig, signCanonical(unsigned, "01".repeat(32)));
});

test("Wallet methods sign query, deposit, paid retry, and withdrawal calls", async (t) => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  globalThis.fetch = async (target, options = {}) => {
    const request = {
      url: String(target),
      body: JSON.parse(String(options.body)),
      headers: new Headers(options.headers)
    };
    requests.push(request);
    if (request.url.endsWith("/deposit") && requests.filter((item) => item.url.endsWith("/deposit")).length === 1) {
      return new Response(JSON.stringify({ requirement: { rail: "mpp" } }), {
        status: 402,
        headers: { "content-type": "application/json", "www-authenticate": "Payment wallet" }
      });
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  };

  const client = new PactClient({ server: "https://api.pact.sh", privkey: "01".repeat(32) });
  await client.wallet({ limit: 10 });
  await client.depositWallet("mpp", "USDC.e", 10_000, {
    pay: async (_requirement, request) => {
      assert.equal(request.url, `https://api.pact.sh/wallets/${encodeURIComponent(client.partyId)}/deposit`);
      return { headers: { authorization: "Payment wallet-proof" } };
    }
  });
  await client.withdrawWallet("withdrawal-1", "mpp", "USDC.e", 5_000);

  assert.deepEqual(requests.map((request) => request.body.action), [
    "wallets.read",
    "wallets.deposit",
    "wallets.deposit",
    "wallets.withdraw"
  ]);
  assert.equal(requests[2].headers.get("authorization"), "Payment wallet-proof");
  assert.deepEqual(requests[3].body.call, {
    withdrawalId: "withdrawal-1",
    rail: "mpp",
    asset: "USDC.e",
    amount: "5000"
  });
});

test("fund reuses the exact SignedCall for a standard paid retry and never auto-pays again", async (t) => {
  const originalFetch = globalThis.fetch;
  const posts = [];
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  globalThis.fetch = async (target, options = {}) => {
    const url = new URL(String(target));
    if ((options.method ?? "GET") === "GET") {
      return new Response(JSON.stringify({ pact: { id: "p_paid", stateNonce: 7 } }), {
        headers: { "content-type": "application/json" }
      });
    }
    posts.push({
      url: url.href,
      body: String(options.body),
      headers: new Headers(options.headers)
    });
    if (posts.length === 1) {
      return new Response(JSON.stringify({ requirement: { rail: "mpp", railData: { protocol: "mpp" } } }), {
        status: 402,
        headers: {
          "content-type": "application/json",
          "www-authenticate": "Payment challenge"
        }
      });
    }
    return new Response(JSON.stringify({ error: "concurrent transition (CAS)" }), {
      status: 409,
      headers: { "content-type": "application/json" }
    });
  };

  const client = new PactClient({ server: "https://api.pact.sh", privkey: "01".repeat(32) });
  let callbackRequest;
  const result = await client.fund("p_paid", {
    railAddress: "0x1111111111111111111111111111111111111111",
    pay: async (requirement, request) => {
      assert.equal(requirement.rail, "mpp");
      callbackRequest = request;
      return { headers: { authorization: "Payment signed-credential" } };
    }
  });

  assert.equal(result.status, 409);
  assert.equal(posts.length, 2);
  assert.equal(posts[0].body, posts[1].body);
  assert.equal(posts[1].headers.get("authorization"), "Payment signed-credential");
  assert.equal(callbackRequest.url, "https://api.pact.sh/pacts/p_paid/fund");
  assert.equal(callbackRequest.method, "POST");
  assert.equal(callbackRequest.challengeHeaders["www-authenticate"], "Payment challenge");
  assert.deepEqual(callbackRequest.body, JSON.parse(posts[0].body));
});

test("fund returns a real-rail 402 without fabricating a legacy proof", async (t) => {
  const originalFetch = globalThis.fetch;
  let postCount = 0;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  globalThis.fetch = async (_target, options = {}) => {
    if ((options.method ?? "GET") === "GET") {
      return new Response(JSON.stringify({ pact: { id: "p_mpp", stateNonce: 2 } }));
    }
    postCount += 1;
    return new Response(JSON.stringify({ requirement: { rail: "mpp" } }), {
      status: 402,
      headers: { "content-type": "application/json" }
    });
  };

  const client = new PactClient({ server: "https://api.pact.sh", privkey: "01".repeat(32) });
  const result = await client.fund("p_mpp", {
    railAddress: "0x1111111111111111111111111111111111111111"
  });
  assert.equal(result.status, 402);
  assert.equal(postCount, 1);
});

test("fund replays a supplied crash-recovery proof directly and byte-identically across CAS retry", async (t) => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  let nonce = 7;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  globalThis.fetch = async (target, options = {}) => {
    const url = new URL(String(target));
    if ((options.method ?? "GET") === "GET") {
      return new Response(JSON.stringify({ pact: { id: "p_resume", stateNonce: nonce++ } }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    requests.push({ body: JSON.parse(String(options.body)), payment: options.headers["x-payment"] });
    return new Response(JSON.stringify(requests.length === 1 ? { error: "concurrent transition (CAS)" } : { ok: true }), {
      status: requests.length === 1 ? 409 : 200,
      headers: { "content-type": "application/json" }
    });
  };

  const client = new PactClient({ server: "https://api.pact.sh", privkey: "01".repeat(32) });
  const result = await client.fund("p_resume", { proof: { txHash: "0xabc" } });
  assert.equal(result.status, 200);
  assert.equal(requests.length, 2);
  assert.equal(requests[0].payment, requests[1].payment);
  assert.deepEqual(requests.map((request) => request.body.stateNonce), [7, 8]);
  assert.ok(requests.every((request) => request.payment));
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
  await client.acceptOffer("o_test", { acceptanceId: "sdk-test" });

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
    ["/rails/x402/address", "rails.bindAddress"],
    ["/offers/o_test/accept", "offers.accept"]
  ]);

  for (const [path, action] of expected) {
    const request = requests.find((item) => item.method === "POST" && item.path === path);
    assert.ok(request, `missing request for ${path}`);
    assert.equal(request.body.action, action);
    const { sig, ...unsigned } = request.body;
    assert.equal(sig, signCanonical(unsigned, privkey), `${action} signature must cover action`);
    assert.notEqual(sig, signCanonical({ ...unsigned, action: `${action}.replay` }, privkey));
  }

  const binding = requests.find(
    (item) => item.method === "POST" && item.path === "/rails/x402/address"
  );
  assert.deepEqual(binding.body.call, { rail: "x402", address: "0x1234" });
  const acceptance = requests.find(
    (item) => item.method === "POST" && item.path === "/offers/o_test/accept"
  );
  assert.deepEqual(acceptance.body.call, { acceptanceId: "sdk-test" });
  assert.equal(acceptance.body.pactId, "o_test");
  assert.equal(acceptance.body.stateNonce, 0);
});

test("offer acceptance exposes the stable idempotency key after an uncertain network response", async (t) => {
  const originalFetch = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  globalThis.fetch = async () => {
    throw new Error("connection reset");
  };

  const client = new PactClient({ server: "https://api.pact.sh", privkey: "01".repeat(32) });
  await assert.rejects(
    () => client.acceptOffer("o_test", { acceptanceId: "stable-purchase-7" }),
    /Offer acceptance stable-purchase-7 has an uncertain response.*Retry with the same acceptanceId.*connection reset/
  );
});
