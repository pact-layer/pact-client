import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { PaymentRequest, Receipt } from "mppx";
import { resolveAccount as resolveMppxAccount } from "mppx/cli";
import { Fetch as MppxFetch, tempo as mppxTempo } from "mppx/client";
import {
  createClient,
  encodeFunctionData,
  getAddress,
  http,
  keccak256,
  stringToHex
} from "viem";
import { Chain } from "viem/tempo";

export const MPPX_VERSION = "0.8.6";
export const TEMPO_CHAIN_ID = 4217;
export const TEMPO_USDCE = "0x20C000000000000000000000b9537d11c60E8b50";
export const TEMPO_RPC_URL = "https://rpc.tempo.xyz";
export const MPP_MIN_FUNDING_AMOUNT = "10000";
export const MPP_MAX_GAS = 400_000n;
export const MPP_MAX_FEE_PER_GAS = 25_000_000_000n;
export const MPP_MAX_PRIORITY_FEE_PER_GAS = 5_000_000_000n;
export const MPP_MAX_TOTAL_FEE = 10_000_000_000_000_000n;
export const MPP_MAX_TOTAL_FEE_ATOMIC_USDCE = "10000";
export const MPP_MAX_TOTAL_FEE_USDCE = "0.01";
export const MPP_CLIENT_ID = "pact-agent";
const MPP_CHALLENGE_MAX_FUTURE_MS = 330_000;
const MAX_UINT256 = (1n << 256n) - 1n;
const TEMPO_MAINNET_CHAIN = Chain.mainnet.extend({ feeToken: TEMPO_USDCE });
const TEMPO_TRANSFER_WITH_MEMO_ABI = Object.freeze([{
  type: "function",
  name: "transferWithMemo",
  stateMutability: "nonpayable",
  inputs: [
    { name: "to", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "memo", type: "bytes32" }
  ],
  outputs: []
}]);
const ALLOWED_TRANSACTION_FIELDS = Object.freeze(new Set([
  "account",
  "calls",
  "chainId",
  "feeToken",
  "from",
  "gas",
  "maxFeePerGas",
  "maxPriorityFeePerGas",
  "nonce",
  "nonceKey",
  "type",
  "validBefore"
]));
const ALLOWED_TRANSFER_CALL_FIELDS = Object.freeze(new Set([
  "abi",
  "address",
  "args",
  "data",
  "functionName",
  "to"
]));
const FORBIDDEN_TRANSACTION_FIELDS = Object.freeze([
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
]);

function positiveAtomicAmount(value, label) {
  if (typeof value !== "string" || !/^\d+$/.test(value) || BigInt(value) <= 0n) {
    throw new Error(`${label} must be a positive atomic USDC amount`);
  }
  return BigInt(value);
}

export function usdMinorUnits(value) {
  const match = /^(\d+)(?:\.(\d{1,6}))?$/.exec(value ?? "");
  if (!match) throw new Error("--max-amount must be a positive USD amount with at most 6 decimals");
  const units = BigInt(match[1]) * 1_000_000n + BigInt((match[2] ?? "").padEnd(6, "0") || "0");
  if (units <= 0n) throw new Error("--max-amount must be a positive USD amount");
  return units;
}

function address(value, label) {
  try {
    return getAddress(value);
  } catch {
    throw new Error(`${label} must be a valid EVM address`);
  }
}

function sameAddress(left, right) {
  return address(left, "address").toLowerCase() === address(right, "address").toLowerCase();
}

function strictBigInt(value, label) {
  if (typeof value !== "bigint") throw new Error(`Tempo payment transaction ${label} must be a bigint`);
  return value;
}

function isCanonicalUtf8String(value, maxBytes) {
  if (typeof value !== "string") return false;
  const encoded = Buffer.from(value, "utf8");
  return encoded.length >= 1 && encoded.length <= maxBytes && encoded.toString("utf8") === value;
}

function attributionFingerprint(value, bytes) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("MPP attribution fields must be non-empty strings");
  }
  return keccak256(stringToHex(value)).slice(2, 2 + bytes * 2);
}

/** Mirror mppx 0.8.6 Attribution.encode for a locally pinned memo policy. */
export function mppAttributionMemo({ challengeId, clientId = MPP_CLIENT_ID, serverId }) {
  return `0x${attributionFingerprint("mpp", 4)}01${attributionFingerprint(
    serverId,
    10
  )}${attributionFingerprint(clientId, 10)}${attributionFingerprint(challengeId, 7)}`;
}

/**
 * Validate the fully prepared Tempo transaction immediately before the local
 * account signs it. This is the last point after all RPC-proposed fee fields
 * have been filled and before any irreversible credential can be created.
 */
export function assertMppxTransactionFeeCaps(transaction, expected) {
  if (!transaction || typeof transaction !== "object" || Array.isArray(transaction)) {
    throw new Error("Tempo payment transaction is invalid");
  }
  for (const field of FORBIDDEN_TRANSACTION_FIELDS) {
    if (Object.hasOwn(transaction, field)) {
      throw new Error(`Tempo payment transaction must not contain ${field}`);
    }
  }
  for (const field of Object.keys(transaction)) {
    if (!ALLOWED_TRANSACTION_FIELDS.has(field)) {
      throw new Error(`Tempo payment transaction must not contain ${field}`);
    }
  }
  if (transaction.type !== "tempo") {
    throw new Error("Tempo payment transaction prepared type must be tempo");
  }
  if (transaction.chainId !== TEMPO_CHAIN_ID) {
    throw new Error(`Tempo payment transaction chainId must be ${TEMPO_CHAIN_ID}`);
  }
  if (typeof transaction.feeToken !== "string" || !sameAddress(transaction.feeToken, TEMPO_USDCE)) {
    throw new Error("Tempo payment transaction feeToken must be Pact's configured USDC.e");
  }
  const expectedPayer = address(expected?.payer, "expected Tempo payment payer");
  if (
    !transaction.account ||
    typeof transaction.account !== "object" ||
    Array.isArray(transaction.account) ||
    typeof transaction.account.address !== "string" ||
    !sameAddress(transaction.account.address, expectedPayer)
  ) {
    throw new Error("Tempo payment transaction account does not match the Pact payer");
  }
  if (typeof transaction.from !== "string" || !sameAddress(transaction.from, expectedPayer)) {
    throw new Error("Tempo payment transaction from does not match the Pact payer");
  }
  if (transaction.nonce !== 0) {
    throw new Error("Tempo payment transaction nonce must be zero for an expiring nonce");
  }
  if (transaction.nonceKey !== MAX_UINT256) {
    throw new Error("Tempo payment transaction nonceKey must be the expiring nonce key");
  }
  const expiresAt = expected?.expiresAt;
  const validBefore = transaction.validBefore;
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (
    !Number.isFinite(expiresAt) ||
    !Number.isSafeInteger(validBefore) ||
    validBefore <= nowSeconds ||
    validBefore > nowSeconds + 25 ||
    validBefore > Math.floor(expiresAt / 1000)
  ) {
    throw new Error("Tempo payment transaction validBefore is outside the Pact challenge window");
  }
  if (!Array.isArray(transaction.calls) || transaction.calls.length !== 1) {
    throw new Error("Tempo payment transaction must contain exactly one transfer call");
  }
  const call = transaction.calls[0];
  const expectedAmount = expected?.amount;
  const expectedRecipient = address(expected?.recipient, "expected Tempo payment recipient");
  const expectedMemo = expected?.memo;
  if (!call || typeof call !== "object" || Array.isArray(call)) {
    throw new Error("Tempo payment transaction transfer call does not match the Pact charge");
  }
  for (const field of Object.keys(call)) {
    if (!ALLOWED_TRANSFER_CALL_FIELDS.has(field)) {
      throw new Error(`Tempo payment transaction transfer call must not contain ${field}`);
    }
  }
  if (
    !Object.hasOwn(call, "abi") ||
    !Array.isArray(call.abi) ||
    typeof expectedAmount !== "bigint" ||
    expectedAmount <= 0n ||
    typeof expectedMemo !== "string" ||
    !/^0x[0-9a-f]{64}$/i.test(expectedMemo) ||
    typeof call.to !== "string" ||
    !sameAddress(call.to, TEMPO_USDCE) ||
    typeof call.address !== "string" ||
    !sameAddress(call.address, TEMPO_USDCE) ||
    call.functionName !== "transferWithMemo" ||
    !Array.isArray(call.args) ||
    call.args.length !== 3 ||
    typeof call.args[0] !== "string" ||
    !sameAddress(call.args[0], expectedRecipient) ||
    call.args[1] !== expectedAmount ||
    call.args[2] !== expectedMemo
  ) {
    throw new Error("Tempo payment transaction transfer call does not match the Pact charge");
  }
  const expectedData = encodeFunctionData({
    abi: TEMPO_TRANSFER_WITH_MEMO_ABI,
    functionName: "transferWithMemo",
    args: [expectedRecipient, expectedAmount, expectedMemo]
  });
  if (call.data !== expectedData) {
    throw new Error("Tempo payment transaction transfer calldata does not match the Pact charge");
  }

  const gas = strictBigInt(transaction.gas, "gas");
  const maxFeePerGas = strictBigInt(transaction.maxFeePerGas, "maxFeePerGas");
  const maxPriorityFeePerGas = strictBigInt(
    transaction.maxPriorityFeePerGas,
    "maxPriorityFeePerGas"
  );
  if (gas < 1n) throw new Error("Tempo payment transaction gas must be positive");
  if (maxFeePerGas < 1n) {
    throw new Error("Tempo payment transaction maxFeePerGas must be positive");
  }
  if (maxPriorityFeePerGas < 0n) {
    throw new Error("Tempo payment transaction maxPriorityFeePerGas must not be negative");
  }

  const totalFee = gas * maxFeePerGas;
  if (totalFee > MPP_MAX_TOTAL_FEE) {
    throw new Error(`Tempo payment transaction total fee exceeds ${MPP_MAX_TOTAL_FEE_USDCE} USDC.e`);
  }
  if (gas > MPP_MAX_GAS) throw new Error(`Tempo payment transaction gas exceeds ${MPP_MAX_GAS}`);
  if (maxFeePerGas > MPP_MAX_FEE_PER_GAS) {
    throw new Error(`Tempo payment transaction maxFeePerGas exceeds ${MPP_MAX_FEE_PER_GAS}`);
  }
  if (maxPriorityFeePerGas > MPP_MAX_PRIORITY_FEE_PER_GAS) {
    throw new Error(
      `Tempo payment transaction maxPriorityFeePerGas exceeds ${MPP_MAX_PRIORITY_FEE_PER_GAS}`
    );
  }
  if (maxPriorityFeePerGas > maxFeePerGas) {
    throw new Error("Tempo payment transaction maxPriorityFeePerGas exceeds maxFeePerGas");
  }
  return { gas, maxFeePerGas, maxPriorityFeePerGas, totalFee };
}

/** Wrap a keychain account without changing its address or signer behavior. */
export function withMppxTransactionFeeCaps(account, expected) {
  const originalSignTransaction = account?.signTransaction;
  if (typeof originalSignTransaction !== "function") {
    throw new Error("mppx keychain account is not a local EVM signing account");
  }
  return {
    ...account,
    async signTransaction(transaction, ...args) {
      assertMppxTransactionFeeCaps(transaction, expected);
      const serialized = await Reflect.apply(originalSignTransaction, account, [transaction, ...args]);
      if (typeof serialized !== "string" || !/^0x76[0-9a-f]+$/i.test(serialized)) {
        throw new Error("Tempo payment signer did not return a canonical 0x76 transaction");
      }
      return serialized;
    }
  };
}

function productionTempoClient() {
  return createClient({
    chain: TEMPO_MAINNET_CHAIN,
    transport: http(TEMPO_RPC_URL)
  });
}

/** Require both production and injected clients to carry Pact's fee-token pin. */
export function pinnedTempoClientResolver(resolver = productionTempoClient) {
  return async ({ chainId } = {}) => {
    if (chainId !== undefined && chainId !== TEMPO_CHAIN_ID) {
      throw new Error(`Tempo payment client chainId must be ${TEMPO_CHAIN_ID}`);
    }
    const client = await resolver({ chainId: TEMPO_CHAIN_ID });
    if (
      client?.chain?.id !== TEMPO_CHAIN_ID ||
      typeof client?.chain?.feeToken !== "string" ||
      !sameAddress(client.chain.feeToken, TEMPO_USDCE)
    ) {
      throw new Error("Tempo payment client must pin mainnet feeToken to USDC.e");
    }
    return client;
  };
}

/**
 * Resolve only mppx's named OS-keychain account. The public resolver also has
 * an environment-key escape hatch; Pact deliberately refuses it so a raw key
 * is never supplied to, read by, or exported through this CLI path.
 */
export function assertMppxKeychainOnly() {
  if (process.env.MPPX_PRIVATE_KEY?.trim()) {
    throw new Error(
      "MPPX_PRIVATE_KEY is disabled for Pact payments; unset it and use: pact wallet mppx create --account <name>"
    );
  }
  if (process.env.X402_PRIVATE_KEY?.trim()) {
    throw new Error(
      "X402_PRIVATE_KEY is disabled for Pact payments; unset it and use an mppx OS-keychain account"
    );
  }
}

export async function resolveMppxKeychainAccount(name, resolver = resolveMppxAccount) {
  assertMppxKeychainOnly();
  const account = await resolver(name);
  address(account?.address, "mppx account address");
  if (typeof account?.signTypedData !== "function" || typeof account?.signTransaction !== "function") {
    throw new Error("mppx keychain account is not a local EVM signing account");
  }
  // Return the public signer interface unchanged. Pact never accesses a key field.
  return account;
}

export async function mppxAccountAddress(name, resolver = resolveMppxAccount) {
  return (await resolveMppxKeychainAccount(name, resolver)).address;
}

function pactScope(bodyText) {
  return `pact-signed-call-sha256:${createHash("sha256").update(bodyText).digest("hex")}`;
}

export function assertMppxRequirement(requirement, expected) {
  if (!requirement || typeof requirement !== "object") {
    throw new Error("Pact 402 response is missing a payment requirement");
  }
  const amount = positiveAtomicAmount(requirement.amount?.amount, "Pact payment requirement amount");
  if (amount !== expected.amount) throw new Error("Pact 402 amount does not match the locally calculated funding amount");
  if (!sameAddress(requirement.payTo, expected.recipient)) {
    throw new Error("Pact 402 recipient does not match the Pact escrow account");
  }
  const railData = requirement.railData;
  if (
    requirement.rail !== "mpp" ||
    requirement.asset !== "USDC" ||
    requirement.amount?.asset !== "USDC" ||
    !railData ||
    railData.protocol !== "mpp" ||
    railData.method !== "tempo" ||
    railData.intent !== "charge" ||
    railData.live !== true ||
    railData.network !== `eip155:${TEMPO_CHAIN_ID}` ||
    !sameAddress(railData.asset, TEMPO_USDCE) ||
    railData.assetSymbol !== "USDC.e" ||
    !sameAddress(railData.payTo, expected.recipient) ||
    positiveAtomicAmount(railData.amount, "Pact MPP rail amount") !== expected.amount ||
    railData.minFundingAmount !== MPP_MIN_FUNDING_AMOUNT ||
    railData.facilitator !== null ||
    !isCanonicalUtf8String(railData.realm, 128) ||
    railData.feeMode !== "payer" ||
    railData.nativeGasTokenRequired !== false
  ) {
    throw new Error("Pact 402 requirement is not Tempo 4217 USDC.e charge");
  }
  return railData;
}

function assertMppChallenge(challenge, expected, requirement, now) {
  const scope = { _mppx_scope: expected.scope };
  const expectedRequest = {
    amount: expected.amount.toString(),
    currency: TEMPO_USDCE,
    externalId: expected.externalId,
    methodDetails: {
      chainId: TEMPO_CHAIN_ID,
      supportedModes: ["pull"]
    },
    recipient: expected.recipient
  };
  const topLevelKeys = [
    "description",
    "expires",
    "id",
    "intent",
    "method",
    "opaque",
    "realm",
    "request"
  ];
  const expiresAt = typeof challenge?.expires === "string" ? Date.parse(challenge.expires) : Number.NaN;
  if (
    !challenge ||
    !isDeepStrictEqual(Object.keys(challenge).sort(), topLevelKeys) ||
    challenge.method !== "tempo" ||
    challenge.intent !== "charge" ||
    !isCanonicalUtf8String(challenge.realm, 128) ||
    !isCanonicalUtf8String(requirement?.realm, 128) ||
    challenge.realm !== requirement.realm ||
    challenge.description !== expected.description ||
    typeof challenge.id !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(challenge.id) ||
    !Number.isFinite(now) ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    expiresAt > now + MPP_CHALLENGE_MAX_FUTURE_MS ||
    challenge.opaque !== PaymentRequest.serialize(scope) ||
    !isDeepStrictEqual(challenge.request, expectedRequest)
  ) {
    throw new Error(
      "Pact MPP challenge is not the canonical issued realm, route, and immutable signed funding body"
    );
  }
}

export function assertMppxChallenge(challenge, expected, requirement, now = Date.now()) {
  assertMppChallenge(challenge, expected, requirement, now);
}

async function requirementFrom(response, expected) {
  let payload;
  try {
    payload = await response.clone().json();
  } catch {
    throw new Error("Pact 402 response is not JSON");
  }
  return assertMppxRequirement(payload?.requirement, expected);
}

function resultFrom(response, body, protocol) {
  return {
    status: response.ok ? 0 : 1,
    stdout: body ? `${body}\n` : "",
    stderr: response.ok ? "" : `mppx ${protocol} payment failed: HTTP ${response.status}\n`
  };
}

function uncertainSubmittedPayment() {
  return new Error(
    "payment outcome uncertain: a signed credential may have reached Pact; do not retry; reconcile on-chain first"
  );
}

function secureFundingUrl(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("mppx Pact funding URL is invalid");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error("mppx Pact funding requires an exact HTTPS URL without credentials, a query, or a fragment");
  }
  return url.href;
}

export function assertMppxSettlementReceipt(response, expected) {
  if (!response.ok) return;
  if (response.url && response.url !== expected.url) {
    throw new Error("payment outcome uncertain: Pact response URL changed; reconcile before retrying");
  }

  const encoded = response.headers.get("payment-receipt");
  if (!encoded) {
    throw new Error("payment outcome uncertain: Pact MPP response has no Payment-Receipt; reconcile before retrying");
  }
  let receiptJson;
  try {
    receiptJson = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
  } catch {
    throw new Error("payment outcome uncertain: Pact MPP Payment-Receipt is invalid; reconcile before retrying");
  }
  if (!receiptJson || typeof receiptJson !== "object" || receiptJson.status !== "success") {
    throw new Error(
      "payment outcome uncertain: Pact MPP Payment-Receipt status is not success; reconcile before retrying"
    );
  }
  let receipt;
  try {
    receipt = Receipt.deserialize(encoded);
  } catch {
    throw new Error("payment outcome uncertain: Pact MPP Payment-Receipt is invalid; reconcile before retrying");
  }
  if (receipt.status !== "success") {
    throw new Error(
      "payment outcome uncertain: Pact MPP Payment-Receipt status is not success; reconcile before retrying"
    );
  }
  if (receipt.method !== "tempo" || !/^0x[0-9a-f]{64}$/i.test(receipt.reference)) {
    throw new Error("payment outcome uncertain: Pact MPP settlement receipt does not match Tempo");
  }
  if (receipt.externalId !== expected.externalId) {
    throw new Error(
      "payment outcome uncertain: Pact MPP settlement receipt is not bound to this Pact funding action"
    );
  }
}

function immutableFundingRequest(request, account) {
  if (request.method !== "POST") throw new Error("mppx Pact funding requires an immutable POST request");
  const body = request.body;
  const expectedBodyKeys = ["action", "call", "issuedAt", "pactId", "sig", "signer", "stateNonce"];
  if (
    !body ||
    typeof body !== "object" ||
    !isDeepStrictEqual(Object.keys(body).sort(), expectedBodyKeys) ||
    body.action !== "pacts.fund" ||
    typeof body.pactId !== "string" ||
    body.pactId.length === 0 ||
    !Number.isSafeInteger(body.stateNonce) ||
    body.stateNonce < 0 ||
    !Number.isSafeInteger(body.issuedAt) ||
    body.issuedAt <= 0 ||
    typeof body.signer !== "string" ||
    body.signer.length === 0 ||
    typeof body.sig !== "string" ||
    !/^[0-9a-f]{128}$/i.test(body.sig) ||
    !body.call ||
    typeof body.call !== "object" ||
    !isDeepStrictEqual(Object.keys(body.call), ["railAddress"]) ||
    !sameAddress(body.call.railAddress, account.address)
  ) {
    throw new Error("mppx requires an action-bound Pact fund SignedCall for the active keychain address");
  }
  const fundingPath = `/pacts/${encodeURIComponent(body.pactId)}/fund`;
  if (new URL(request.url).pathname !== fundingPath) {
    throw new Error("mppx Pact funding URL does not match the signed Pact ID");
  }
  return {
    bodyText: JSON.stringify(body),
    description: `Pact ${body.pactId} funding`,
    externalId: `${body.pactId}:${body.signer}`
  };
}

const PAYMENT_HEADERS = new Set(["accept-payment", "authorization"]);

function assertImmutableHeaders(actualHeaders, originalHeaders) {
  const actual = new Headers(actualHeaders);
  const original = new Headers(originalHeaders);
  for (const [name, value] of original) {
    if (actual.get(name) !== value) throw new Error("mppx attempted to mutate Pact funding headers");
  }
  for (const name of actual.keys()) {
    if (!original.has(name) && !PAYMENT_HEADERS.has(name)) {
      throw new Error("mppx attempted to add an unexpected Pact funding header");
    }
  }
}

/**
 * Pay one immutable Pact funding request. There are exactly two external HTTP
 * calls on the payment path: the unsigned 402 probe and the credential retry.
 * Local caps and request binding are checked before the probe; the returned
 * requirement and challenge are pinned before the payment credential is signed.
 */
export async function runMppxPayment(request, options, runtime = {}) {
  assertMppxKeychainOnly();
  if (options.protocol !== "mpp") throw new Error("mppx Pact payment supports only the MPP rail");
  const amount = positiveAtomicAmount(options.expectedAmount, "expected Pact funding amount");
  const cap = usdMinorUnits(options.maxAmount);
  if (amount > cap) throw new Error("Pact funding amount exceeds --max-amount");
  const fundingUrl = secureFundingUrl(request.url);
  const recipient = address(options.expectedRecipient, "Pact escrow account");
  const account = runtime.account ?? await resolveMppxKeychainAccount(options.account, runtime.resolveAccount);
  if (options.expectedPayer && !sameAddress(account.address, options.expectedPayer)) {
    throw new Error("active mppx account changed after the signed Pact funding call was prepared");
  }

  const immutable = immutableFundingRequest({ ...request, url: fundingUrl }, account);
  const bodyText = immutable.bodyText;
  const expected = {
    amount,
    bodyText,
    description: immutable.description,
    externalId: immutable.externalId,
    method: request.method,
    protocol: options.protocol,
    payer: account.address,
    recipient,
    scope: pactScope(bodyText),
    url: fundingUrl
  };
  const baseFetch = runtime.fetch ?? globalThis.fetch;
  const requestInit = { method: request.method, headers: request.headers, body: bodyText, redirect: "error" };
  const first = await baseFetch(fundingUrl, requestInit);
  if (first.status !== 402) return resultFrom(first, await first.text(), options.protocol);
  const requirement = await requirementFrom(first, expected);
  const signingPolicy = {
    amount,
    expiresAt: undefined,
    memo: undefined,
    payer: account.address,
    recipient
  };
  const guardedAccount = withMppxTransactionFeeCaps(account, signingPolicy);

  const methods = [mppxTempo.charge({
    account: guardedAccount,
    clientId: MPP_CLIENT_ID,
    expectedChainId: TEMPO_CHAIN_ID,
    expectedRecipients: [recipient],
    getClient: pinnedTempoClientResolver(runtime.getTempoClient),
    mode: "pull",
  })];

  let replayedProbe = false;
  let credentialSubmitted = false;
  const guardedFetch = async (input, init) => {
    const retry = new Request(input, { ...init, redirect: "error" });
    const retryBody = await retry.clone().text();
    if (retry.url !== fundingUrl || retry.method !== request.method || retryBody !== bodyText) {
      throw new Error("mppx attempted to mutate the signed Pact funding request");
    }
    assertImmutableHeaders(retry.headers, request.headers);
    if (!replayedProbe) {
      replayedProbe = true;
      return first;
    }
    const credentialHeader = "authorization";
    if (!retry.headers.get(credentialHeader)) {
      throw new Error(`mppx did not attach the ${credentialHeader} credential`);
    }
    credentialSubmitted = true;
    try {
      return await baseFetch(retry);
    } catch {
      throw uncertainSubmittedPayment();
    }
  };

  const paidFetch = MppxFetch.from({
    acceptPaymentPolicy: "never",
    fetch: guardedFetch,
    methods,
    maxPaymentRetries: 1,
    async onChallenge(challenge, helpers) {
      assertMppxChallenge(challenge, expected, requirement);
      if (signingPolicy.memo !== undefined || signingPolicy.expiresAt !== undefined) {
        throw new Error("Pact MPP challenge may create only one payment credential");
      }
      signingPolicy.memo = mppAttributionMemo({
        challengeId: challenge.id,
        clientId: MPP_CLIENT_ID,
        serverId: challenge.realm
      });
      signingPolicy.expiresAt = Date.parse(challenge.expires);
      Object.freeze(signingPolicy);
      return helpers.createCredential();
    }
  });
  let response;
  try {
    response = await paidFetch(fundingUrl, requestInit);
  } catch (error) {
    if (credentialSubmitted) throw uncertainSubmittedPayment();
    throw error;
  }
  if (credentialSubmitted && !response.ok) throw uncertainSubmittedPayment();
  try {
    assertMppxSettlementReceipt(response, expected);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("payment outcome uncertain:")) throw error;
    throw uncertainSubmittedPayment();
  }
  let responseBody = "";
  try {
    responseBody = await response.text();
  } catch {
    // A validated settlement receipt is authoritative; a failed response-body
    // read must not invite a second payment.
  }
  return resultFrom(response, responseBody, options.protocol);
}
