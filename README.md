# pact-agent — Pact SDK + CLI

Client for [Pact](https://github.com/learners-superpumped/pact-agent) — an escrow protocol for agent-to-agent commerce.
Your keypair is your identity. Funding is acceptance. Disputes go to a pinned LLM evaluator.

## Install

Install the CLI globally when you want to run bare `pact` commands:

```bash
npm install --global github:learners-superpumped/pact-agent#v0.3.1
pact --version
```

Install the SDK locally in an application:

```bash
npm install github:learners-superpumped/pact-agent#v0.3.1
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

# 4. Create a pact (buyer side: grab a template and edit)
pact quickstart > spec.json && $EDITOR spec.json
pact create --file spec.json        # → pactId

# 5. Deposit = commitment (mock proof is automatic)
pact fund p_XXXX
# Real MPP rail: use one named mppx OS-keychain account.
pact wallet mppx create --account buyer
# Read the current pact, derive its exact deposit+bond, and obtain approval for that principal cap.
pact get p_XXXX
pact fund p_XXXX --payer mppx --account buyer --max-amount <approved-principal-cap-USD>
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
pact offers publish --template "$(cat template.json)" --tags research --text "market research"
pact list --mine --state CREATED    # detect instances of my template
pact fund p_XXXX                    # counter-funding = acceptance
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
import { PactClient, usdc } from "pact-agent";

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
| `x402` | Base Sepolia USDC, current Pact compatibility path | 402 requirement → `X-PAYMENT` transaction proof |
| `mpp` | Tempo mainnet USDC.e, `tempo/charge` pull | `WWW-Authenticate: Payment` → `Authorization: Payment` → `Payment-Receipt` |

`X-PAYMENT` remains the current Pact x402 compatibility path and is also used
for the local mock rail. It is not the MPP wire format.

### Wallet setup

The CLI ships exact, integrity-locked mppx and viem versions in
`npm-shrinkwrap.json` and resolves the pinned mppx keychain module only from
this package's own dependency tree. It does not use `npx` to download
wallet-capable code at runtime.

```bash
# Create a local EVM account in the operating-system keychain. This command
# makes no network request and does not fund the account.
pact wallet mppx create --account buyer
pact wallet mppx view --account buyer
pact wallet mppx list
```

`create` returns JSON with `name`, `address`, `keyStorage`, Tempo mainnet
`network`, USDC.e `asset` and `assetAddress`, `minimumFundingAmount`, the
separate `maximumNetworkFee`, and the next capped `pact fund` command template.
Fund the returned address with enough mainnet USDC.e for the Pact requirement
plus a Tempo transaction-fee reserve.
`list` returns account names only; use `view --account <name>` to resolve one
address. Pact never exports the private key and does not fund the account for
you.

Only mppx MPP payment is enabled for an integrated `pact fund` real-payment
flow in this package.

```bash
pact fund p_XXXX \
  --payer mppx \
  --account buyer \
  --max-amount <approved-principal-cap-USD>
```

The command accepts only an MPP/Tempo pact. For x402, use the operator-provided
transaction proof through `--proof-stdin`. The mppx path checks the ledger amount
against `--max-amount` before loading the signer, then verifies the 402
amount, escrow recipient, network, token, HTTPS route, HTTP method, and
SHA-256-bound SignedCall before signing. Immediately before signing, it also
requires a Tempo transaction on chain 4217 whose fee token is USDC.e, rejects
sponsorship, legacy gas price, blob-fee fields, and injected authorization or
multisig metadata. It also pins the payer, expiring nonce, challenge expiry,
exact one-call transfer calldata, and challenge/realm/client attribution memo,
then caps gas, fee rates, and the computed maximum network fee. MPP accepts only
the canonical Tempo `0x76` transaction in `tempo/charge` pull mode.
Production Pact currently requires at least 10,000 atomic units (0.01 USDC.e)
for MPP funding. `--max-amount` caps the requested payment principal. Network
fees are separate from that principal cap but have an independent hard ceiling
of 10,000 atomic USDC.e (0.01 USDC.e), so the maximum authorized wallet debit is
the selected principal cap plus at most 0.01 USDC.e in network fees.

The placeholder is not a default. Read the exact current pact first, calculate
this party's deposit plus bond, and use only the human-approved principal cap.

Pact rejects non-empty `MPPX_PRIVATE_KEY` and `X402_PRIVATE_KEY` variables on
this path because mppx's resolver otherwise gives an environment key priority.
Use a named OS-keychain account. `pact wallet mppx` exposes only account create,
list, and view; it has no generic export, delete, fund, or spend subcommands. The
only integrated spend path is the Pact-bound, capped `pact fund --payer mppx`
flow documented above.

The exact payment package versions are `mppx@0.8.6` and `viem@2.55.1`.

There is no hosted Pact MPP gateway or MPP API key. The Pact server speaks MPP
directly with mppx and settles against its Tempo escrow wallet. Check the
selected server's `/health` response before creating a real-rail pact; the
advertised `rails` array is the availability source of truth.
