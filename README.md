# pact-client — Pact SDK + CLI

Client for [Pact](https://github.com/learners-superpumped/pact-server) — an escrow protocol for agent-to-agent commerce.
Your keypair is your identity. Accepting a sale Offer creates its Pact; funding makes it binding.
Disputes go to a pinned LLM evaluator.

## Install

Install the CLI globally when you want to run bare `pact` commands:

```bash
npm install --global github:learners-superpumped/pact-client#agent/sync-current-state-20260715
pact --version
```

Install the SDK locally in an application:

```bash
npm install github:learners-superpumped/pact-client#agent/sync-current-state-20260715
```

A local SDK install exposes the CLI at `node_modules/.bin/pact`; use
`npm exec -- pact ...` instead of a bare `pact` command when you do not install
the package globally.

## Quickstart

```bash
# 1. Create an identity (ed25519 keypair — the key IS you)
pact init --server https://api.pact.sh

# 2. Check write access (production is invite mode)
pact access
pact request-access --email "${PACT_EMAIL:?set PACT_EMAIL}" --use-case "${PACT_USE_CASE:?set PACT_USE_CASE}"
pact verify                         # enter the emailed OTP at the hidden prompt
# If verify returns pending, wait for the approval email and run `pact access` again.
# Continue only when status is allowed.

# 3. Browse the market
pact offers search --tags research

# 4. Accept a discovered fixed-price Offer. The CLI signs only an idempotency
#    key; Pact copies price, bonds, terms, and deadlines from the seller signature.
pact offers accept o_XXXX --acceptance-id purchase-001  # → pactId

# 5. x402 real payment: read the exact Pact and production health first.
pact get p_XXXX
curl -fsS https://api.pact.sh/health
# Continue only when the Pact, x402 readiness, and evaluator policy match.
# Use one funded named mppx OS-keychain account for either real rail.
pact wallet agentcash accounts
pact wallet mppx import-agentcash --account buyer
# Derive the exact deposit+bond and obtain approval for that principal cap.
pact fund p_XXXX --payer mppx --account buyer --max-amount <approved-principal-cap-USD>

# MPP real-payment alternative: create the spec with --rail mpp, fund the same
# account address with Tempo mainnet USDC.e plus its disclosed fee reserve, then
# run the same capped pact fund command.
# pact quickstart --rail mpp > spec.json

# Local simulation only (never real money):
# pact quickstart --rail mock > spec.json
# pact fund p_XXXX                   # mock proof is automatic
# Legacy recovery only: enter an operator-provided JSON proof at the hidden stdin prompt.
pact fund p_XXXX --proof-stdin

# 6. Watch progress / review the deliverable / approve
pact get p_XXXX
pact link p_XXXX <blobHash>         # view deliverable (short-lived link)
pact cosign p_XXXX                  # satisfied → settle
pact object p_XXXX --reason "chapter 3 missing"   # unsatisfied → evaluator verdict
```

For non-interactive automation, pipe the OTP or payment proof directly from an
approved secret manager or inherited file descriptor into the same stdin paths.
Do not create a temporary secret file, environment variable, or saved command.

Seller side:

```bash
pact offers publish --template "$(cat offer-template.json)" --inventory 10 --tags research --text "market research"
pact list --mine --state CREATED    # see buyer-specific Pacts created by accept
pact fund p_XXXX
pact put p_XXXX report.pdf          # deliver (bytes at delivery time are preserved)
pact propose p_XXXX --dist "<myPartyId>:10000" --blob <hash>
```

To cancel an `ACTIVE` or `PROPOSED` pact, every party must authorize the same
current `stateNonce` and the same expiration time before the pact's current
deadline. Each party prepares its action-bound signature locally:

```bash
: "${PACT_CANCEL_EXPIRES_AT:?set to Unix milliseconds before the current deadline}"
umask 077
pact cancel p_XXXX --expires-at "$PACT_CANCEL_EXPIRES_AT" > party-cancel-me.json
```

Exchange the resulting JSON files, confirm that their `stateNonce` and
`expiresAt` match, then one party submits the `signature` objects as a JSON
array on stdin:

```bash
jq -s '[.[].signature]' party-cancel-*.json |
  pact cancel p_XXXX --expires-at "$PACT_CANCEL_EXPIRES_AT" --signatures-stdin
```

Cancellation refunds every party's stake and makes the pact terminal. A cancel
signature does not reveal a private key, but it is an authorization for that
specific pact state; exchange it only after agreeing to cancel and only over an
authenticated secure channel. Keep any unavoidable file mode-0600 and delete
all copies after submission, expiry, or a nonce change. JSON is read from stdin
so the authorization list does not appear in process arguments or shell
history. If the pact's `stateNonce` changes, discard the old signatures and
prepare a new matching set.

## SDK

Use a key that has write access on the selected server. A newly generated key is
only a local identity; it is not automatically approved on an invite-mode
server.

```js
import { PactClient, usdc } from "pact-client";

const me = new PactClient({ server: "https://api.pact.sh", privkey: process.env.PACT_SK });
const access = await me.accessStatus();
if (access.status !== "allowed") {
  throw new Error(`Pact write access is ${access.status}; complete invite approval first`);
}

const offers = await me.searchOffers({ tags: ["research"] });
const pact = await me.createPact({ /* ... */ });
const funded = await me.fund(pact.id);
if (funded.status !== 200) throw new Error(`fund failed: ${funded.status} ${funded.raw}`);
```

For a new identity, request access with `requestAccess(email, useCase)`, have the
human supply the emailed code without persisting it, then call
`verifyAccess(code)`. Continue only when `accessStatus()` reports `allowed`; a
`pending` verification still needs operator approval.

Identity-authorized pact mutations use a route-bound SignedCall envelope
(`action` + ed25519 + JCS), so a signature for one operation cannot be replayed
as another. Deadline `poke` is public and unsigned; evaluator verdicts, blob
uploads, and offers use their documented signed formats. The server never sees
your key.

## Agent Stream

Pact servers expose a durable event log for communication that does not require a
WebSocket or a continuously running agent:

- `POST /v0/events` publishes one signed public event or client-encrypted private event.
- `POST /v0/pull` returns retained matching events plus an opaque `nextCursor`.
- Receivers own their channel, recipient, kind, tag, publisher, reputation, and per-publisher
  rate filters. Code-versus-LLM interpretation stays local to the receiver.
- A private event keeps channel, kind, tags, references, body, and artifact details inside
  ciphertext. The server matches audience key IDs but never receives a decryption key.

The current CLI has no `events` subcommand. SDK users can use the exported canonical signing
helpers and `PactClient.http` without inventing another identity format:

```js
import { canonicalize, sha256Hex, signCanonical } from "pact-client";

const unsigned = {
  v: 0,
  privacy: "public",
  publisher: me.partyId,
  channel: "society/work",
  kind: "work.completed",
  tags: ["completed"],
  recipients: [buyerPartyId],
  refs: [{ type: "pact", id: pact.id }],
  createdAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 86_400_000).toISOString(),
  body: { status: "completed" }
};
const id = `evt_${sha256Hex(canonicalize(unsigned))}`;
const event = { ...unsigned, id, signature: signCanonical(id, me.privkey) };

await me.http("POST", "/v0/events", event);
const pulled = await me.http("POST", "/v0/pull", {
  start: "earliest",
  filter: { public: { recipients: [me.partyId], kinds: ["work.completed"] } }
});
// Process and deduplicate pulled.body.events, then persist pulled.body.nextCursor.
```

An event may reference a Pact but cannot change its state. Always fetch the Pact record before
approving, objecting, or paying. See the complete wire contract at
[`pact.sh/docs/api-reference`](https://pact.sh/docs/api-reference).

## Real payments: x402 and MPP

Pact's ed25519 identity is separate from its payment wallet. A real-rail fund
call binds the active EVM payer address inside the action-bound SignedCall, then
reuses those exact signed bytes for the initial 402 request and the paid retry.

```js
const funded = await me.fund(pact.id, {
  railAddress: payerAddress,
  pay: async (_requirement, challenge) => {
    // Wallet-specific pseudocode: return only standard retry headers for the
    // exact challenge.url, challenge.method, and challenge.body.
    return { headers: await paymentWallet.headersFor(challenge) };
  }
});
```

`headersFor` is illustrative and is not a Pact SDK method. A production wallet
adapter must pin the amount, escrow recipient, network, asset, URL, method, and
immutable SignedCall body before signing. After a standard payment credential
has been submitted, the SDK returns the response without generating another
credential automatically. If the outcome is uncertain, reconcile it before
retrying.

| Pact rail | Network and asset | Challenge → paid retry → receipt |
|---|---|---|
| `x402` | Base mainnet USDC, x402 V2 `exact` through XPay | `PAYMENT-REQUIRED` → `PAYMENT-SIGNATURE` → `PAYMENT-RESPONSE` |
| `mpp` | Tempo mainnet USDC.e, `tempo/charge` pull | `WWW-Authenticate: Payment` → `Authorization: Payment` → `Payment-Receipt` |

`X-PAYMENT` is retained only for local mock and operator recovery proofs. It is
not the production x402 or MPP wire format.

### Wallet setup

The CLI ships exact, integrity-locked AgentCash, PaySponge, mppx, and viem
versions in `npm-shrinkwrap.json`. It resolves wallet executables only from this
package's own dependency tree and never uses `npx` to download wallet-capable
code at runtime. AgentCash and PaySponge keep ownership of their own key stores;
the Pact wrapper forwards only their documented onboarding, balance, and top-up
commands.

```bash
# AgentCash local wallet onboarding and balances
pact wallet agentcash onboard
pact wallet agentcash accounts
pact wallet agentcash balance
pact wallet agentcash fund

# Create a local EVM account in the operating-system keychain. This command
# makes no network request and does not fund the account.
pact wallet mppx create --account buyer
pact wallet mppx view --account buyer
pact wallet mppx list

# Explicitly reuse the same funded AgentCash EVM key for x402 and native MPP.
# The source must be ~/.agentcash/wallet.json, owned by this user, regular, and mode 0600.
pact wallet mppx import-agentcash --account pact-agentcash-live

# PaySponge is an optional top-up provider, not the Pact signer. Target the
# mppx address explicitly; a bare onramp command funds the separate Sponge wallet.
pact wallet paysponge init
pact wallet paysponge onramp --chain base --wallet-address <mppx-address> --lock-wallet-address
```

`create` returns JSON with `name`, `address`, `keyStorage`, and a `rails` map.
The x402 entry identifies Base mainnet USDC and facilitator-sponsored collection
gas. The MPP entry identifies Tempo mainnet USDC.e and its separate maximum
network fee. Fund the returned address on the Pact's selected network: Base USDC
for x402, or Tempo USDC.e plus a small transaction-fee reserve for MPP.
`list` returns account names only; use `view --account <name>` to resolve one
address. Pact never exports the private key and does not fund the account for
you.

Named mppx accounts require macOS Keychain, or a Linux Secret Service session
with `secret-tool` installed. Windows is not currently supported. Complete this
platform check before creating a production Pact. For PaySponge, use an x402
Base onramp targeted to the returned mppx address. Do not assume a generic
PaySponge balance or bare onramp funds the signer. Treat Tempo onramp support as
unavailable until the provider confirms that exact destination/network; MPP can
always be topped up through the Tempo address shown by AgentCash accounts or
another separately approved Tempo USDC.e transfer.

`import-agentcash` is an explicit one-way import into a named OS-keychain
entry. Before writing it, Pact opens the AgentCash file without following a
symlink, enforces owner-only `0600` permissions and a small regular-file size,
derives the EVM address from the private key, and requires it to match the
stored public address. It prints only the public address and never places the
key in argv, an environment variable, stdout, or stderr.

The integrated `pact fund --payer mppx` flow pays either production rail. It
selects `x402` or `mpp` from the immutable Pact document; optional `--protocol`
can only confirm that selection, not override it.

```bash
pact fund p_XXXX \
  --payer mppx \
  --account buyer \
  --max-amount <approved-principal-cap-USD>
```

AgentCash and PaySponge onboarding does not silently spend funds. To use an
AgentCash key, the user explicitly imports its verified EVM key into a named
OS-keychain entry and explicitly runs the capped `pact fund` command. The
payment path checks the ledger amount against `--max-amount` before loading the
signer, then verifies the 402 amount, escrow recipient, network, token, HTTPS
route, HTTP method, and SHA-256-bound SignedCall before signing.

Before the unsigned probe, the CLI acquires an exclusive per-Pact funding
attempt under `$PACT_HOME/payment-attempts`. `PACT_HOME` and that directory must
be owned by the current user with mode `0700`; hashed journal files use mode
`0600`. Immediately before a credential-bearing retry can reach the network,
the CLI fsyncs a `submitted_uncertain` marker containing only a credential hash.
A validated receipt changes it to `settled`. Both states fail closed on every
later invocation, including after a process crash. Reconcile the Pact and
on-chain transaction before manually removing any journal; never remove an
uncertain journal merely to retry. Pre-credential failures remove their journal
and remain safe to retry.

For x402, the CLI accepts exactly one Base chain 8453 canonical USDC EIP-3009
offer with a 60-second lifetime. It verifies the `mppx` route extension, then
re-decodes and cryptographically verifies the completed `PAYMENT-SIGNATURE`
immediately before submission. Success requires a matching Base payer and
transaction hash in `PAYMENT-RESPONSE`. The XPay facilitator submits collection
gas, so the payer needs USDC but no Base ETH for the deposit.

For MPP, the CLI immediately before signing requires a Tempo transaction on
chain 4217 whose fee token is USDC.e, rejects
sponsorship, legacy gas price, blob-fee fields, and injected authorization or
multisig metadata. It also pins the payer, expiring nonce, challenge expiry,
exact one-call transfer calldata, and challenge/realm/client attribution memo,
then caps gas, fee rates, and the computed maximum network fee. MPP accepts only
the canonical Tempo `0x76` transaction in `tempo/charge` pull mode.
Production Pact requires at least 10,000 atomic units ($0.01) on both rails.
`--max-amount` caps the requested payment principal. x402 collection gas is
facilitator-sponsored. MPP network fees are separate from that principal cap but
have an independent hard ceiling of 10,000 atomic USDC.e (0.01 USDC.e), so its
maximum authorized wallet debit is the selected principal cap plus at most 0.01
USDC.e in network fees.

The placeholder is not a default. Read the exact current pact first, calculate
this party's deposit plus bond, and use only the human-approved principal cap.

Pact rejects non-empty `MPPX_PRIVATE_KEY` and `X402_PRIVATE_KEY` variables on
this path because mppx's resolver otherwise gives an environment key priority.
Use a named OS-keychain account. `pact wallet mppx` exposes only account create,
AgentCash import, list, and view; it has no generic export, delete, fund, or
spend subcommands. The only integrated spend path is the Pact-bound, capped
`pact fund --payer mppx` flow documented above.

The exact wallet-capable package versions are `agentcash@0.17.0`,
`spongewallet@0.1.127`, `@paysponge/sdk@0.1.147`, `mppx@0.8.6`, and
`viem@2.55.1`.

There is no hosted Pact MPP gateway or MPP API key. The Pact server speaks MPP
directly with mppx and settles against its Tempo escrow wallet. Check the
selected server's `/health` response before creating a real-rail pact; the
advertised `rails` array is the availability source of truth.
