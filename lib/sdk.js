// Pact SDK for agents. The key is the identity (ed25519); signatures use JCS (RFC 8785) and SHA-256.
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha512";
import { sha256 } from "@noble/hashes/sha256";
import { base58, hex } from "@scure/base";

ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

export function canonicalize(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v) || !Number.isSafeInteger(v)) throw new Error("non-integer number in canonical payload");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  if (typeof v === "object") {
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
  }
  throw new Error(`cannot canonicalize ${typeof v}`);
}

export function sha256Hex(data) {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return hex.encode(sha256(bytes));
}

export function generateKeypair(seed) {
  const privkey = seed ?? ed.utils.randomPrivateKey();
  const pubkey = ed.getPublicKey(privkey);
  return { privkey, pubkey, partyId: "ed25519:" + base58.encode(pubkey) };
}

export function signCanonical(payload, privkey) {
  return hex.encode(ed.sign(sha256(new TextEncoder().encode(canonicalize(payload))), privkey));
}

// Retry only CAS/stateNonce conflicts. Other 409 responses, such as "already funded", are final.
function isRetryable409(r) {
  return r.status === 409 && /CAS|stateNonce/.test(String(r.body?.error ?? ""));
}

export class PactClient {
  /** @param {{server: string, privkey: Uint8Array|string}} opts privkey may be hex or bytes */
  constructor(opts) {
    this.server = opts.server.replace(/\/$/, "");
    this.privkey = typeof opts.privkey === "string" ? hex.decode(opts.privkey) : opts.privkey;
    const { partyId } = generateKeypair(this.privkey);
    this.partyId = partyId;
  }

  async http(method, path, body, headers) {
    const isBuf = body instanceof Uint8Array;
    const res = await fetch(this.server + path, {
      method,
      headers: {
        ...(body !== undefined && !isBuf ? { "content-type": "application/json" } : {}),
        ...(isBuf ? { "content-type": "application/octet-stream" } : {}),
        ...headers
      },
      body: body === undefined ? undefined : isBuf ? body : JSON.stringify(body)
    });
    const raw = await res.text();
    let json = {};
    try { json = JSON.parse(raw); } catch { /* binary */ }
    return { status: res.status, body: json, raw, headers: Object.fromEntries(res.headers.entries()) };
  }

  envelope(action, call, pactId, stateNonce) {
    const unsigned = { action, call, pactId, stateNonce, issuedAt: Date.now(), signer: this.partyId };
    return { ...unsigned, sig: signCanonical(unsigned, this.privkey) };
  }

  async getPact(pactId) {
    const r = await this.http("GET", `/pacts/${pactId}`);
    if (r.status !== 200) throw new Error(`getPact ${pactId}: ${r.status} ${r.raw}`);
    return r.body;
  }

  async listPacts(q = {}) {
    const qs = new URLSearchParams(Object.fromEntries(Object.entries(q).filter(([, v]) => v !== undefined)));
    return (await this.http("GET", `/pacts?${qs}`)).body.pacts;
  }

  async nonce(pactId) {
    return (await this.getPact(pactId)).pact.stateNonce;
  }

  async signedCall(action, path, call, pactId, opts = {}) {
    const retries = opts.retries ?? 10;
    let last;
    for (let i = 0; i < retries; i++) {
      const n = opts.stateNonce ?? (await this.nonce(pactId));
      last = await this.http("POST", path, this.envelope(action, call, pactId, n), opts.headers);
      if (!isRetryable409(last) || opts.stateNonce !== undefined) return last;
    }
    return last;
  }

  async createPact(spec) {
    const r = await this.http("POST", "/pacts", this.envelope("pacts.create", spec, "", 0));
    if (r.status !== 200) throw new Error(`createPact: ${r.status} ${r.raw}`);
    return r.body.pact;
  }

  /**
   * Build one action-bound funding request without sending it. A payment client
   * must reuse this exact body for both the initial 402 request and its paid
   * retry; regenerating issuedAt or the signature changes the payment scope.
   */
  async prepareFund(pactId, opts = {}) {
    const stateNonce = opts.stateNonce ?? (await this.nonce(pactId));
    const call = opts.railAddress ? { railAddress: opts.railAddress } : {};
    const body = this.envelope("pacts.fund", call, pactId, stateNonce);
    return {
      url: `${this.server}/pacts/${encodeURIComponent(pactId)}/fund`,
      method: "POST",
      body,
      headers: { "content-type": "application/json" }
    };
  }

  /**
   * Complete the 402 flow with one immutable SignedCall. Standard MPP callbacks
   * return {headers}; local mock and x402 compatibility/recovery paths may
   * return a proof object, which is encoded as X-PAYMENT.
   */
  async fund(pactId, opts = {}) {
    // A caller-supplied proof may be a crash-recovery token. Replay the exact
    // bytes directly; an unproved round-trip could create a second payment.
    const suppliedPayment =
      opts.proof === undefined ? undefined : Buffer.from(JSON.stringify(opts.proof)).toString("base64");
    for (let i = 0; i < (opts.retries ?? 10); i++) {
      const request = await this.prepareFund(pactId, { railAddress: opts.railAddress });
      const path = `/pacts/${encodeURIComponent(pactId)}/fund`;
      if (suppliedPayment !== undefined) {
        const paid = await this.http(
          request.method,
          path,
          request.body,
          { "x-payment": suppliedPayment }
        );
        if (!isRetryable409(paid)) return paid;
        continue;
      }
      const first = await this.http(request.method, path, request.body, request.headers);
      if (first.status !== 402) {
        if (isRetryable409(first)) continue;
        return first;
      }
      const requirement = first.body.requirement;
      if (!opts.pay && requirement?.rail !== "mock") return first;
      const payment = await (opts.pay
        ? opts.pay(requirement, {
            body: request.body,
            challengeHeaders: first.headers,
            method: request.method,
            url: request.url
          })
        : { scheme: "mock" });
      const standardHeaders = payment?.headers;
      const paidHeaders = standardHeaders ?? {
        "x-payment": Buffer.from(JSON.stringify(payment)).toString("base64")
      };
      const paid = await this.http(request.method, path, request.body, paidHeaders);
      // A standard credential may have moved money. Never generate a second
      // credential automatically after it has been submitted.
      if (standardHeaders) return paid;
      if (!isRetryable409(paid)) return paid;
    }
    return { status: 409, body: { error: "retries exhausted" }, raw: "" };
  }

  async withdraw(pactId) {
    return this.signedCall("pacts.withdraw", `/pacts/${pactId}/withdraw`, {}, pactId);
  }

  async putBlob(pactId, bytes) {
    const issuedAt = Date.now();
    const hash = sha256Hex(bytes);
    const sig = signCanonical({ action: "put", pactId, sha256: hash, issuedAt }, this.privkey);
    return this.http("POST", `/pacts/${pactId}/blobs`, bytes, {
      "x-pact-signer": this.partyId,
      "x-pact-signature": sig,
      "x-pact-issued-at": String(issuedAt)
    });
  }

  async link(pactId, hash) {
    const issuedAt = Date.now();
    const sig = signCanonical({ action: "link", pactId, hash, issuedAt }, this.privkey);
    return this.http("POST", `/pacts/${pactId}/blobs/${hash}/link`, { signer: this.partyId, issuedAt, sig });
  }

  async download(url) {
    // Hosted storage returns an absolute signed URL; local storage may return /dl/<token>. Support both.
    const target = new URL(url, this.server).toString();
    const res = await fetch(target);
    if (!res.ok) throw new Error(`download ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }

  async propose(pactId, evidence, distribution) {
    return this.signedCall("pacts.propose", `/pacts/${pactId}/propose`, { evidence, distribution }, pactId);
  }

  async cosign(pactId) {
    return this.signedCall("pacts.cosign", `/pacts/${pactId}/cosign`, {}, pactId);
  }

  async object(pactId, reason) {
    return this.signedCall("pacts.object", `/pacts/${pactId}/object`, { reason }, pactId);
  }

  cancelSig(pactId, stateNonce, expiresAt) {
    return signCanonical({ action: "cancel", pactId, stateNonce, expiresAt }, this.privkey);
  }

  /** sigs: one {signer, sig} from every party, each produced with that party's cancelSig */
  async cancel(pactId, expiresAt, sigs) {
    const n = await this.nonce(pactId);
    return this.http("POST", `/pacts/${pactId}/cancel`, this.envelope("pacts.cancel", { expiresAt, sigs }, pactId, n));
  }

  async poke(pactId) {
    return this.http("POST", `/pacts/${pactId}/poke`);
  }

  // ---- access (invite-mode servers: writes 403 with error "access_required" until allowed) ----

  /** request an email OTP binding this partyId — check the inbox, then verifyAccess(otp) */
  async requestAccess(email, useCase) {
    return this.http("POST", "/access/request", this.envelope("access.request", { email, ...(useCase ? { useCase } : {}) }, "", 0));
  }

  /** submit the 6-digit code from the email — grants access (or queues for approval) */
  async verifyAccess(otp) {
    return this.http("POST", "/access/verify", this.envelope("access.verify", { otp: String(otp) }, "", 0));
  }

  /** { mode: "open"|"invite", status: "allowed"|"pending"|"revoked"|"none" } */
  async accessStatus() {
    return (await this.http("GET", `/access/${this.partyId}`)).body;
  }

  /** operator only (server PACT_ADMIN_PARTY): allow|revoke <partyId>, allow-email|deny-email <pattern>, pending */
  async accessAdmin(action, target, note) {
    return this.http(
      "POST",
      "/access/admin",
      this.envelope("access.admin", { action, ...(target ? { target } : {}), ...(note ? { note } : {}) }, "", 0)
    );
  }

  /** Bind a PartyId to a rail address, required to receive x402 payouts. */
  async bindRailAddress(rail, address) {
    return this.http("POST", `/rails/${rail}/address`, this.envelope("rails.bindAddress", { address }, "", 0));
  }

  async publishOffer(offer) {
    const body = { by: this.partyId, ...offer };
    const sig = signCanonical(body, this.privkey);
    return this.http("POST", "/offers", { ...body, sig });
  }

  async searchOffers(q = {}) {
    const qs = new URLSearchParams(
      Object.fromEntries(
        Object.entries({ ...q, tags: q.tags?.join(",") }).filter(([, v]) => v !== undefined && v !== "")
      )
    );
    return (await this.http("GET", `/offers?${qs}`)).body.offers;
  }

  async watchOffers(q = {}) {
    const qs = new URLSearchParams(
      Object.fromEntries(
        Object.entries({ ...q, tags: q.tags?.join(",") }).filter(([, v]) => v !== undefined && v !== "")
      )
    );
    return (await this.http("GET", `/offers/watch?${qs}`)).body.offers;
  }
}

export function usdc(minorUnits) {
  return { amount: String(minorUnits), asset: "USDC" };
}
