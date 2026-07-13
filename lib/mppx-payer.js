import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { PaymentRequest, Receipt } from "mppx";
import { resolveAccount as resolveMppxAccount } from "mppx/cli";
import { Fetch as MppxFetch, tempo as mppxTempo } from "mppx/client";
import { getAddress } from "viem";

export const MPPX_VERSION = "0.8.6";
export const TEMPO_CHAIN_ID = 4217;
export const TEMPO_USDCE = "0x20C000000000000000000000b9537d11c60E8b50";
export const MPP_MIN_FUNDING_AMOUNT = "10000";
const MPP_CHALLENGE_MAX_FUTURE_MS = 330_000;

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
    typeof railData.realm !== "string" ||
    railData.realm.length === 0 ||
    railData.realm.length > 128 ||
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
  let receipt;
  try {
    receipt = Receipt.deserialize(encoded);
  } catch {
    throw new Error("payment outcome uncertain: Pact MPP Payment-Receipt is invalid; reconcile before retrying");
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

  const methods = [mppxTempo.charge({
    account,
    expectedChainId: TEMPO_CHAIN_ID,
    expectedRecipients: [recipient],
    mode: "pull",
    ...(runtime.getTempoClient ? { getClient: runtime.getTempoClient } : {})
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
