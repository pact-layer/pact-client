import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { Challenge, PaymentRequest, Receipt } from "mppx";
import { createClient, custom } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Chain } from "viem/tempo";
import {
  MPP_MIN_FUNDING_AMOUNT,
  TEMPO_CHAIN_ID,
  TEMPO_USDCE,
  assertMppxChallenge,
  assertMppxKeychainOnly,
  assertMppxRequirement,
  assertMppxSettlementReceipt,
  resolveMppxKeychainAccount,
  runMppxPayment
} from "../lib/mppx-payer.js";

const PAYER_KEY = `0x${"41".repeat(32)}`;
const PAYER = privateKeyToAccount(PAYER_KEY);
const RECIPIENT = "0x1111111111111111111111111111111111111111";

function withCleanKeyEnvironment(t) {
  const mppx = process.env.MPPX_PRIVATE_KEY;
  const x402 = process.env.X402_PRIVATE_KEY;
  delete process.env.MPPX_PRIVATE_KEY;
  delete process.env.X402_PRIVATE_KEY;
  t.after(() => {
    if (mppx === undefined) delete process.env.MPPX_PRIVATE_KEY;
    else process.env.MPPX_PRIVATE_KEY = mppx;
    if (x402 === undefined) delete process.env.X402_PRIVATE_KEY;
    else process.env.X402_PRIVATE_KEY = x402;
  });
}

function requirement(overrides = {}) {
  const railData = {
    protocol: "mpp",
    method: "tempo",
    intent: "charge",
    live: true,
    network: `eip155:${TEMPO_CHAIN_ID}`,
    asset: TEMPO_USDCE,
    assetSymbol: "USDC.e",
    payTo: RECIPIENT,
    amount: "10000",
    minFundingAmount: MPP_MIN_FUNDING_AMOUNT,
    facilitator: null,
    realm: "Pact MPP test",
    feeMode: "payer",
    nativeGasTokenRequired: false,
    ...(overrides.railData ?? {})
  };
  return {
    amount: { amount: "10000", asset: "USDC" },
    asset: "USDC",
    payTo: RECIPIENT,
    rail: "mpp",
    railData,
    ...overrides,
    railData
  };
}

test("validates Pact's nested MPP requirement wrapper and every native rail field", () => {
  const expected = { amount: 10000n, recipient: RECIPIENT };
  assert.deepEqual(assertMppxRequirement(requirement(), expected), requirement().railData);

  for (const mutated of [
    requirement({ amount: { amount: "10001", asset: "USDC" } }),
    requirement({ asset: "USDC.e" }),
    requirement({ payTo: "0x2222222222222222222222222222222222222222" }),
    requirement({ rail: "x402" }),
    requirement({ railData: { network: "eip155:1" } }),
    requirement({ railData: { asset: "0x2222222222222222222222222222222222222222" } }),
    requirement({ railData: { assetSymbol: "USDC" } }),
    requirement({ railData: { amount: "10001" } }),
    requirement({ railData: { minFundingAmount: "1" } }),
    requirement({ railData: { facilitator: "https://gateway.example" } }),
    requirement({ railData: { feeMode: "relay" } }),
    requirement({ railData: { nativeGasTokenRequired: true } })
  ]) {
    assert.throws(() => assertMppxRequirement(mutated, expected));
  }
});

test("pins the Tempo charge challenge to the exact recipient, amount, scope, and pull mode", () => {
  const now = Date.parse("2026-07-13T00:00:00.000Z");
  const bodyText = JSON.stringify({ action: "pacts.fund", sig: "immutable" });
  const scope = `pact-signed-call-sha256:${createHash("sha256").update(bodyText).digest("hex")}`;
  const expected = {
    amount: 10000n,
    bodyText,
    description: "Pact p_1 funding",
    externalId: "p_1:ed25519:payer",
    recipient: RECIPIENT,
    scope
  };
  const railData = requirement().railData;
  const challenge = {
    id: "A".repeat(43),
    method: "tempo",
    intent: "charge",
    realm: railData.realm,
    description: expected.description,
    expires: "2026-07-13T00:05:00.000Z",
    opaque: PaymentRequest.serialize({ _mppx_scope: scope }),
    request: {
      amount: "10000",
      currency: TEMPO_USDCE,
      externalId: expected.externalId,
      methodDetails: { chainId: TEMPO_CHAIN_ID, supportedModes: ["pull"] },
      recipient: RECIPIENT
    }
  };
  assert.doesNotThrow(() => assertMppxChallenge(challenge, expected, railData, now));

  for (const request of [
    { ...challenge.request, amount: "10001" },
    { ...challenge.request, currency: "0x2222222222222222222222222222222222222222" },
    { ...challenge.request, recipient: "0x2222222222222222222222222222222222222222" },
    { ...challenge.request, methodDetails: { chainId: 1, supportedModes: ["pull"] } },
    { ...challenge.request, methodDetails: { chainId: TEMPO_CHAIN_ID, supportedModes: ["push"] } },
    { ...challenge.request, extra: "not-issued" }
  ]) {
    assert.throws(() => assertMppxChallenge({ ...challenge, request }, expected, railData, now));
  }
  assert.throws(() => assertMppxChallenge({ ...challenge, realm: "Attacker" }, expected, railData, now));
  assert.throws(() => assertMppxChallenge({ ...challenge, description: "Other pact" }, expected, railData, now));
  assert.throws(() =>
    assertMppxChallenge({ ...challenge, expires: "2026-07-13T00:00:00.000Z" }, expected, railData, now)
  );
  assert.throws(() =>
    assertMppxChallenge({ ...challenge, expires: "2026-07-13T00:05:30.001Z" }, expected, railData, now)
  );
});

test("resolves only an OS-keychain signer and refuses environment private keys", async (t) => {
  withCleanKeyEnvironment(t);
  const resolver = async (name) => {
    assert.equal(name, "buyer");
    return PAYER;
  };
  assert.equal(await resolveMppxKeychainAccount("buyer", resolver), PAYER);

  process.env.MPPX_PRIVATE_KEY = PAYER_KEY;
  await assert.rejects(resolveMppxKeychainAccount("buyer", resolver), /MPPX_PRIVATE_KEY is disabled/);
  delete process.env.MPPX_PRIVATE_KEY;
  process.env.X402_PRIVATE_KEY = PAYER_KEY;
  assert.throws(() => assertMppxKeychainOnly(), /X402_PRIVATE_KEY is disabled/);
});

test("requires a Pact-bound Tempo Payment-Receipt before reporting success", () => {
  const expected = {
    externalId: "p_1:ed25519:payer",
    url: "https://api.pact.sh/pacts/p_1/fund"
  };
  assert.throws(
    () => assertMppxSettlementReceipt(new Response('{"ok":true}', { status: 200 }), expected),
    /outcome uncertain.*Payment-Receipt/
  );
  const receipt = Receipt.serialize({
    externalId: expected.externalId,
    method: "tempo",
    reference: `0x${"97".repeat(32)}`,
    status: "success",
    timestamp: "2026-07-13T00:00:00.000Z"
  });
  assert.doesNotThrow(() =>
    assertMppxSettlementReceipt(
      new Response('{"ok":true}', { status: 200, headers: { "payment-receipt": receipt } }),
      expected
    )
  );
  const wrong = Receipt.serialize({
    method: "stripe",
    reference: "not-a-tempo-hash",
    status: "success",
    timestamp: "2026-07-13T00:00:00.000Z"
  });
  assert.throws(
    () =>
      assertMppxSettlementReceipt(
        new Response('{"ok":true}', { status: 200, headers: { "payment-receipt": wrong } }),
        expected
      ),
    /does not match Tempo/
  );

  for (const externalId of [undefined, "p_other:ed25519:payer", "p_1:ed25519:other"]) {
    const unbound = Receipt.serialize({
      ...(externalId === undefined ? {} : { externalId }),
      method: "tempo",
      reference: `0x${"95".repeat(32)}`,
      status: "success",
      timestamp: "2026-07-13T00:00:00.000Z"
    });
    assert.throws(
      () =>
        assertMppxSettlementReceipt(
          new Response('{"ok":true}', { status: 200, headers: { "payment-receipt": unbound } }),
          expected
        ),
      /outcome uncertain.*not bound to this Pact/
    );
  }
});

test("completes one standard MPP 402 challenge and paid retry with the exact SignedCall", async (t) => {
  withCleanKeyEnvironment(t);
  let signatures = 0;
  const account = {
    ...PAYER,
    async signTransaction(...args) {
      signatures += 1;
      return PAYER.signTransaction(...args);
    }
  };
  const tempoClient = createClient({
    account,
    chain: Chain.mainnet,
    transport: custom({
      async request({ method, params }) {
        if (method === "eth_fillTransaction") return params?.[0];
        if (method === "eth_getBlockByNumber") {
          return {
            baseFeePerGas: "0x1",
            gasLimit: "0x1c9c380",
            gasUsed: "0x0",
            hash: `0x${"01".repeat(32)}`,
            number: "0x1",
            timestamp: "0x1",
            transactions: []
          };
        }
        if (method === "eth_maxPriorityFeePerGas") return "0x1";
        if (method === "eth_estimateGas") return "0x186a0";
        if (method === "eth_chainId") return "0x1079";
        throw new Error(`unexpected Tempo RPC method: ${method}`);
      }
    })
  });
  const body = {
    action: "pacts.fund",
    call: { railAddress: account.address },
    issuedAt: 1,
    pactId: "p_1",
    signer: "ed25519:payer",
    stateNonce: 1,
    sig: "ab".repeat(64)
  };
  const bodyText = JSON.stringify(body);
  const scope = `pact-signed-call-sha256:${createHash("sha256").update(bodyText).digest("hex")}`;
  const railData = requirement().railData;
  const challenge = {
    id: "A".repeat(43),
    method: "tempo",
    intent: "charge",
    realm: railData.realm,
    description: "Pact p_1 funding",
    expires: new Date(Date.now() + 300_000).toISOString(),
    opaque: PaymentRequest.serialize({ _mppx_scope: scope }),
    request: {
      amount: "10000",
      currency: TEMPO_USDCE,
      externalId: "p_1:ed25519:payer",
      methodDetails: { chainId: TEMPO_CHAIN_ID, supportedModes: ["pull"] },
      recipient: RECIPIENT
    }
  };
  let calls = 0;
  const fetch = async (input, init) => {
    calls += 1;
    const request = new Request(input, init);
    assert.equal(request.redirect, "error");
    assert.equal(await request.clone().text(), bodyText);
    if (!request.headers.get("authorization")) {
      return new Response(JSON.stringify({ requirement: requirement() }), {
        status: 402,
        headers: {
          "content-type": "application/json",
          "www-authenticate": Challenge.serialize(challenge)
        }
      });
    }
    const receipt = Receipt.serialize({
      externalId: "p_1:ed25519:payer",
      method: "tempo",
      reference: `0x${"96".repeat(32)}`,
      status: "success",
      timestamp: "2026-07-13T00:00:00.000Z"
    });
    return new Response('{"pact":{"id":"p_1"}}', {
      status: 200,
      headers: { "content-type": "application/json", "payment-receipt": receipt }
    });
  };

  const result = await runMppxPayment(
    {
      url: "https://api.pact.sh/pacts/p_1/fund",
      method: "POST",
      body,
      headers: { "content-type": "application/json" }
    },
    {
      protocol: "mpp",
      maxAmount: "0.01",
      expectedAmount: "10000",
      expectedRecipient: RECIPIENT,
      expectedPayer: account.address
    },
    { account, fetch, getTempoClient: () => tempoClient }
  );

  assert.deepEqual(result, { status: 0, stdout: '{"pact":{"id":"p_1"}}\n', stderr: "" });
  assert.equal(calls, 2);
  assert.equal(signatures, 1);
});

test("fails caps, non-HTTPS routes, x402, and malformed SignedCalls before network or signing", async (t) => {
  withCleanKeyEnvironment(t);
  let signatures = 0;
  const account = {
    ...PAYER,
    async signTransaction(...args) {
      signatures += 1;
      return PAYER.signTransaction(...args);
    }
  };
  let fetches = 0;
  const fetch = async () => {
    fetches += 1;
    throw new Error("must not fetch");
  };
  const body = {
    action: "pacts.fund",
    call: { railAddress: account.address },
    issuedAt: 1,
    pactId: "p_1",
    signer: "ed25519:payer",
    stateNonce: 1,
    sig: "ab".repeat(64)
  };
  const request = {
    url: "https://api.pact.sh/pacts/p_1/fund",
    method: "POST",
    body,
    headers: { "content-type": "application/json" }
  };
  const options = {
    protocol: "mpp",
    maxAmount: "0.01",
    expectedAmount: "10000",
    expectedRecipient: RECIPIENT,
    expectedPayer: account.address
  };

  await assert.rejects(
    runMppxPayment(request, { ...options, expectedAmount: "10001" }, { account, fetch }),
    /exceeds --max-amount/
  );
  await assert.rejects(
    runMppxPayment({ ...request, url: "http://api.pact.sh/pacts/p_1/fund" }, options, { account, fetch }),
    /exact HTTPS URL/
  );
  await assert.rejects(
    runMppxPayment(request, { ...options, protocol: "x402" }, { account, fetch }),
    /supports only the MPP rail/
  );
  await assert.rejects(
    runMppxPayment({ ...request, body: { ...body, action: "pacts.withdraw" } }, options, { account, fetch }),
    /action-bound Pact fund SignedCall/
  );
  assert.equal(fetches, 0);
  assert.equal(signatures, 0);
});
