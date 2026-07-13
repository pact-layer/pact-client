import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { Challenge, PaymentRequest, Receipt } from "mppx";
import { createClient, custom, encodeFunctionData } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { Chain } from "viem/tempo";
import {
  MPP_MAX_FEE_PER_GAS,
  MPP_MAX_GAS,
  MPP_MAX_PRIORITY_FEE_PER_GAS,
  MPP_MAX_TOTAL_FEE,
  MPP_CLIENT_ID,
  MPP_MIN_FUNDING_AMOUNT,
  TEMPO_CHAIN_ID,
  TEMPO_USDCE,
  assertMppxChallenge,
  assertMppxKeychainOnly,
  assertMppxRequirement,
  assertMppxSettlementReceipt,
  assertMppxTransactionFeeCaps,
  mppAttributionMemo,
  pinnedTempoClientResolver,
  resolveMppxKeychainAccount,
  runMppxPayment,
  withMppxTransactionFeeCaps
} from "../lib/mppx-payer.js";

const PAYER_KEY = `0x${"41".repeat(32)}`;
const PAYER = privateKeyToAccount(PAYER_KEY);
const RECIPIENT = "0x1111111111111111111111111111111111111111";
const TEST_CHALLENGE_ID = "A".repeat(43);
const TEST_REALM = "Pact MPP test";
const TEST_MEMO = mppAttributionMemo({
  challengeId: TEST_CHALLENGE_ID,
  clientId: MPP_CLIENT_ID,
  serverId: TEST_REALM
});
const MAX_UINT256 = (1n << 256n) - 1n;
const EXPECTED_TRANSFER = Object.freeze({
  amount: 10000n,
  expiresAt: Date.now() + 300_000,
  memo: TEST_MEMO,
  payer: PAYER.address,
  recipient: RECIPIENT
});
const TRANSFER_WITH_MEMO_ABI = [{
  type: "function",
  name: "transferWithMemo",
  stateMutability: "nonpayable",
  inputs: [
    { name: "to", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "memo", type: "bytes32" }
  ],
  outputs: []
}];

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
    requirement({ railData: { realm: "가".repeat(43) } }),
    requirement({ railData: { realm: "bad\ud800realm" } }),
    requirement({ railData: { feeMode: "relay" } }),
    requirement({ railData: { nativeGasTokenRequired: true } })
  ]) {
    assert.throws(() => assertMppxRequirement(mutated, expected));
  }
});

test("matches mppx 0.8.6 attribution encoding and binds challenge, realm, and client", () => {
  assert.equal(MPP_CLIENT_ID, "pact-agent");
  assert.equal(
    TEST_MEMO,
    "0xef1ed712010e80be6540a7ab14a5cbd5b377fbf4afb04ccaf08373f214d72734"
  );
  assert.notEqual(
    mppAttributionMemo({
      challengeId: "B".repeat(43),
      clientId: MPP_CLIENT_ID,
      serverId: TEST_REALM
    }),
    TEST_MEMO
  );
  assert.notEqual(
    mppAttributionMemo({
      challengeId: TEST_CHALLENGE_ID,
      clientId: MPP_CLIENT_ID,
      serverId: "Other Pact realm"
    }),
    TEST_MEMO
  );
  assert.notEqual(
    mppAttributionMemo({
      challengeId: TEST_CHALLENGE_ID,
      clientId: "other-client",
      serverId: TEST_REALM
    }),
    TEST_MEMO
  );
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
  assert.throws(() =>
    assertMppxChallenge(
      { ...challenge, realm: "가".repeat(43) },
      expected,
      { ...railData, realm: "가".repeat(43) },
      now
    )
  );
  assert.throws(() =>
    assertMppxChallenge(
      { ...challenge, realm: "bad\ud800realm" },
      expected,
      { ...railData, realm: "bad\ud800realm" },
      now
    )
  );
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
  for (const status of [undefined, "failed", 1, null]) {
    const json = {
      externalId: expected.externalId,
      method: "tempo",
      reference: `0x${"94".repeat(32)}`,
      ...(status === undefined ? {} : { status }),
      timestamp: "2026-07-13T00:00:00.000Z"
    };
    const encoded = Buffer.from(JSON.stringify(json)).toString("base64url");
    assert.throws(
      () =>
        assertMppxSettlementReceipt(
          new Response('{"ok":true}', { status: 200, headers: { "payment-receipt": encoded } }),
          expected
        ),
      /outcome uncertain.*status is not success/
    );
  }
  assert.throws(
    () =>
      assertMppxSettlementReceipt(
        new Response('{"ok":true}', { status: 200, headers: { "payment-receipt": "not-json" } }),
        expected
      ),
    /outcome uncertain.*Payment-Receipt is invalid/
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

function feeTransaction(overrides = {}) {
  const memo = TEST_MEMO;
  const transferCall = {
    abi: TRANSFER_WITH_MEMO_ABI,
    address: TEMPO_USDCE,
    args: [RECIPIENT, EXPECTED_TRANSFER.amount, memo],
    data: encodeFunctionData({
      abi: TRANSFER_WITH_MEMO_ABI,
      functionName: "transferWithMemo",
      args: [RECIPIENT, EXPECTED_TRANSFER.amount, memo]
    }),
    functionName: "transferWithMemo",
    to: TEMPO_USDCE
  };
  return {
    account: PAYER,
    type: "tempo",
    chainId: TEMPO_CHAIN_ID,
    feeToken: TEMPO_USDCE,
    from: PAYER.address,
    gas: 100_000n,
    maxFeePerGas: 1_000_000_000n,
    maxPriorityFeePerGas: 100_000_000n,
    nonce: 0,
    nonceKey: MAX_UINT256,
    validBefore: Math.floor(Date.now() / 1000) + 25,
    calls: [transferCall],
    ...overrides
  };
}

function withTransferMemo(transaction, memo) {
  const call = transaction.calls[0];
  return {
    ...transaction,
    calls: [{
      ...call,
      args: [RECIPIENT, EXPECTED_TRANSFER.amount, memo],
      data: encodeFunctionData({
        abi: TRANSFER_WITH_MEMO_ABI,
        functionName: "transferWithMemo",
        args: [RECIPIENT, EXPECTED_TRANSFER.amount, memo]
      })
    }]
  };
}

function assertFeeCaps(transaction) {
  return assertMppxTransactionFeeCaps(transaction, EXPECTED_TRANSFER);
}

test("hard-caps every RPC-proposed Tempo fee field immediately before signing", async () => {
  const lower = feeTransaction({ gas: 1n, maxFeePerGas: 1n, maxPriorityFeePerGas: 0n });
  assert.deepEqual(assertFeeCaps(lower), {
    gas: 1n,
    maxFeePerGas: 1n,
    maxPriorityFeePerGas: 0n,
    totalFee: 1n
  });
  const upper = feeTransaction({
    gas: MPP_MAX_GAS,
    maxFeePerGas: MPP_MAX_FEE_PER_GAS,
    maxPriorityFeePerGas: MPP_MAX_PRIORITY_FEE_PER_GAS
  });
  assert.equal(assertFeeCaps(upper).totalFee, MPP_MAX_TOTAL_FEE);

  const forbiddenFields = [
    "_capabilities",
    "aaAuthorizationList",
    "authorizationList",
    "blobVersionedHashes",
    "blobs",
    "feePayer",
    "feePayerSignature",
    "gasPrice",
    "keyAuthorization",
    "keyData",
    "keyId",
    "keyType",
    "kzg",
    "maxFeePerBlobGas",
    "multisig",
    "multisigInit",
    "multisigSignatureCount",
    "multisigSignature",
    "signature",
    "signatures",
    "sidecars",
    "validAfter"
  ];
  for (const field of forbiddenFields) {
    assert.throws(
      () => assertFeeCaps(feeTransaction({ [field]: undefined })),
      new RegExp(`must not contain ${field}`)
    );
  }

  assert.throws(() => assertFeeCaps(feeTransaction({ injected: undefined })), /must not contain injected/);

  for (const field of [
    "account",
    "type",
    "chainId",
    "feeToken",
    "from",
    "gas",
    "maxFeePerGas",
    "maxPriorityFeePerGas",
    "nonce",
    "nonceKey",
    "validBefore"
  ]) {
    const transaction = feeTransaction();
    delete transaction[field];
    assert.throws(() => assertFeeCaps(transaction));
  }
  for (const [transaction, message] of [
    [feeTransaction({ type: "eip1559" }), /prepared type must be tempo/],
    [feeTransaction({ chainId: 1 }), /chainId must be 4217/],
    [feeTransaction({ feeToken: "0x2222222222222222222222222222222222222222" }), /feeToken/],
    [feeTransaction({ account: { ...PAYER, address: RECIPIENT } }), /account does not match/],
    [feeTransaction({ from: RECIPIENT }), /from does not match/],
    [feeTransaction({ nonce: 1 }), /nonce must be zero/],
    [feeTransaction({ nonceKey: 0n }), /nonceKey must be the expiring nonce key/],
    [feeTransaction({ validBefore: Math.floor(Date.now() / 1000) }), /outside the Pact challenge window/],
    [feeTransaction({ validBefore: Math.floor(Date.now() / 1000) + 26 }), /outside the Pact challenge window/],
    [feeTransaction({ gas: 1 }), /gas must be a bigint/],
    [feeTransaction({ maxFeePerGas: 1 }), /maxFeePerGas must be a bigint/],
    [feeTransaction({ maxPriorityFeePerGas: 1 }), /maxPriorityFeePerGas must be a bigint/],
    [feeTransaction({ gas: 0n }), /gas must be positive/],
    [feeTransaction({ gas: MPP_MAX_GAS + 1n, maxFeePerGas: 1n }), /gas exceeds/],
    [feeTransaction({ maxFeePerGas: 0n }), /maxFeePerGas must be positive/],
    [feeTransaction({ gas: 1n, maxFeePerGas: MPP_MAX_FEE_PER_GAS + 1n }), /maxFeePerGas exceeds/],
    [feeTransaction({ maxPriorityFeePerGas: -1n }), /must not be negative/],
    [feeTransaction({ maxPriorityFeePerGas: MPP_MAX_PRIORITY_FEE_PER_GAS + 1n }), /maxPriorityFeePerGas exceeds/],
    [feeTransaction({ maxFeePerGas: 1n, maxPriorityFeePerGas: 2n }), /exceeds maxFeePerGas/],
    [
      feeTransaction({ gas: MPP_MAX_GAS + 1n, maxFeePerGas: MPP_MAX_FEE_PER_GAS }),
      /total fee exceeds 0.01 USDC.e/
    ]
  ]) {
    assert.throws(() => assertFeeCaps(transaction), message);
  }

  assert.throws(() => assertFeeCaps(feeTransaction({ calls: [] })), /exactly one transfer call/);
  assert.throws(
    () => assertFeeCaps(feeTransaction({ calls: [feeTransaction().calls[0], feeTransaction().calls[0]] })),
    /exactly one transfer call/
  );
  assert.throws(
    () => assertFeeCaps(feeTransaction({ calls: [{ ...feeTransaction().calls[0], to: RECIPIENT }] })),
    /transfer call does not match/
  );
  assert.throws(
    () => assertFeeCaps(feeTransaction({ calls: [{ ...feeTransaction().calls[0], data: "0x95777d59" }] })),
    /transfer calldata does not match/
  );
  assert.throws(
    () => assertFeeCaps(feeTransaction({ calls: [{ ...feeTransaction().calls[0], value: 0n }] })),
    /transfer call must not contain value/
  );
  for (const memo of [
    mppAttributionMemo({
      challengeId: "B".repeat(43),
      clientId: MPP_CLIENT_ID,
      serverId: TEST_REALM
    }),
    mppAttributionMemo({
      challengeId: TEST_CHALLENGE_ID,
      clientId: MPP_CLIENT_ID,
      serverId: "Other Pact realm"
    }),
    mppAttributionMemo({
      challengeId: TEST_CHALLENGE_ID,
      clientId: "other-client",
      serverId: TEST_REALM
    })
  ]) {
    assert.throws(() => assertFeeCaps(withTransferMemo(feeTransaction(), memo)), /does not match the Pact charge/);
  }
  const nearExpiryPolicy = { ...EXPECTED_TRANSFER, expiresAt: Date.now() + 10_000 };
  assert.throws(
    () => assertMppxTransactionFeeCaps(
      feeTransaction({ validBefore: Math.floor(Date.now() / 1000) + 11 }),
      nearExpiryPolicy
    ),
    /outside the Pact challenge window/
  );

  const serializer = () => "serialized";
  const serializerOptions = { serializer };
  let calls = 0;
  let signedTransaction;
  let signedOptions;
  let signerThis;
  const account = {
    ...PAYER,
    async signTransaction(transaction, options) {
      calls += 1;
      signedTransaction = transaction;
      signedOptions = options;
      signerThis = this;
      return "0x76deadbeef";
    }
  };
  const guarded = withMppxTransactionFeeCaps(account, EXPECTED_TRANSFER);
  assert.equal(await guarded.signTransaction(upper, serializerOptions), "0x76deadbeef");
  assert.equal(calls, 1);
  assert.equal(signedTransaction, upper);
  assert.equal(signedOptions, serializerOptions);
  assert.equal(signerThis, account);
  await assert.rejects(guarded.signTransaction(feeTransaction({ gas: 0n }), serializerOptions), /gas must be positive/);
  assert.equal(calls, 1);

  const genericSigner = withMppxTransactionFeeCaps({
    ...account,
    async signTransaction() { return "0x02deadbeef"; }
  }, EXPECTED_TRANSFER);
  await assert.rejects(genericSigner.signTransaction(upper, serializerOptions), /canonical 0x76 transaction/);
});

test("pins production and injected Tempo clients to mainnet USDC.e fees", async () => {
  const production = await pinnedTempoClientResolver()({ chainId: TEMPO_CHAIN_ID });
  assert.equal(production.chain.id, TEMPO_CHAIN_ID);
  assert.equal(production.chain.feeToken.toLowerCase(), TEMPO_USDCE.toLowerCase());

  const injected = createClient({
    chain: Chain.mainnet.extend({ feeToken: TEMPO_USDCE }),
    transport: custom({ async request() { throw new Error("no RPC expected"); } })
  });
  assert.equal(await pinnedTempoClientResolver(() => injected)({ chainId: TEMPO_CHAIN_ID }), injected);
  await assert.rejects(
    pinnedTempoClientResolver(() => createClient({
      chain: Chain.mainnet,
      transport: custom({ async request() { throw new Error("no RPC expected"); } })
    }))({ chainId: TEMPO_CHAIN_ID }),
    /must pin mainnet feeToken to USDC.e/
  );
  await assert.rejects(pinnedTempoClientResolver(() => injected)({ chainId: 1 }), /chainId must be 4217/);
});

test("completes one standard MPP 402 challenge and paid retry with the exact SignedCall", async (t) => {
  withCleanKeyEnvironment(t);
  let signatures = 0;
  let preparedTransaction;
  let signedTransaction;
  const account = {
    ...PAYER,
    async signTransaction(transaction, ...args) {
      signatures += 1;
      preparedTransaction = transaction;
      signedTransaction = await PAYER.signTransaction(transaction, ...args);
      return signedTransaction;
    }
  };
  const tempoClient = createClient({
    account,
    chain: Chain.mainnet.extend({ feeToken: TEMPO_USDCE }),
    transport: custom({
      async request({ method, params }) {
        if (method === "eth_fillTransaction") {
          return {
            tx: {
              ...params?.[0],
              accessList: [],
              chainId: "0x1079",
              feeToken: TEMPO_USDCE,
              from: account.address,
              gas: "0x186a0",
              hash: `0x${"02".repeat(32)}`,
              input: "0x",
              maxFeePerGas: "0x3b9aca00",
              maxPriorityFeePerGas: "0x5f5e100",
              nonce: "0x0",
              type: "0x76"
            }
          };
        }
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
  assert.equal(preparedTransaction.type, "tempo");
  assert.equal(preparedTransaction.chainId, TEMPO_CHAIN_ID);
  assert.equal(preparedTransaction.from.toLowerCase(), account.address.toLowerCase());
  assert.equal(preparedTransaction.account.address.toLowerCase(), account.address.toLowerCase());
  assert.equal(preparedTransaction.nonce, 0);
  assert.equal(preparedTransaction.nonceKey, MAX_UINT256);
  assert.equal(
    preparedTransaction.calls[0].args[2],
    mppAttributionMemo({
      challengeId: challenge.id,
      clientId: MPP_CLIENT_ID,
      serverId: challenge.realm
    })
  );
  assert.match(signedTransaction, /^0x76[0-9a-f]+$/i);
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
