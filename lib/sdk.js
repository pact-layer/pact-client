// Pact SDK — 에이전트용 클라이언트. 키 = 신원 (ed25519), 서명 = JCS(RFC 8785) sha256.
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

// 재시도 가능한 409 = CAS/stateNonce 충돌만. "already funded" 등은 최종 응답.
function isRetryable409(r) {
  return r.status === 409 && /CAS|stateNonce/.test(String(r.body?.error ?? ""));
}

export class PactClient {
  /** @param {{server: string, privkey: Uint8Array|string}} opts privkey는 hex 또는 bytes */
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
    return { status: res.status, body: json, raw };
  }

  envelope(call, pactId, stateNonce) {
    const unsigned = { call, pactId, stateNonce, issuedAt: Date.now(), signer: this.partyId };
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

  async signedCall(path, call, pactId, opts = {}) {
    const retries = opts.retries ?? 10;
    let last;
    for (let i = 0; i < retries; i++) {
      const n = opts.stateNonce ?? (await this.nonce(pactId));
      last = await this.http("POST", path, this.envelope(call, pactId, n), opts.headers);
      if (!isRetryable409(last) || opts.stateNonce !== undefined) return last;
    }
    return last;
  }

  async createPact(spec) {
    const r = await this.http("POST", "/pacts", this.envelope(spec, "", 0));
    if (r.status !== 200) throw new Error(`createPact: ${r.status} ${r.raw}`);
    return r.body.pact;
  }

  /** 402 플로우: 증빙 없이 → requirement → X-PAYMENT 재호출. mock rail은 proof 자동. */
  async fund(pactId, opts = {}) {
    for (let i = 0; i < (opts.retries ?? 10); i++) {
      const n = await this.nonce(pactId);
      const call = opts.railAddress ? { railAddress: opts.railAddress } : {};
      const first = await this.http("POST", `/pacts/${pactId}/fund`, this.envelope(call, pactId, n));
      if (first.status !== 402) {
        if (isRetryable409(first)) continue;
        return first;
      }
      const requirement = first.body.requirement;
      const proof = opts.proof ?? (await (opts.pay ? opts.pay(requirement) : { scheme: "mock" }));
      const xp = Buffer.from(JSON.stringify(proof)).toString("base64");
      const paid = await this.http("POST", `/pacts/${pactId}/fund`, this.envelope(call, pactId, n), {
        "x-payment": xp
      });
      if (!isRetryable409(paid)) return paid;
    }
    return { status: 409, body: { error: "retries exhausted" }, raw: "" };
  }

  async withdraw(pactId) {
    return this.signedCall(`/pacts/${pactId}/withdraw`, {}, pactId);
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
    // aic 백엔드 서버는 절대 signed URL을, local은 상대 /dl/<token>을 준다 — 둘 다 받는다
    const target = new URL(url, this.server).toString();
    const res = await fetch(target);
    if (!res.ok) throw new Error(`download ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }

  async propose(pactId, evidence, distribution) {
    return this.signedCall(`/pacts/${pactId}/propose`, { evidence, distribution }, pactId);
  }

  async cosign(pactId) {
    return this.signedCall(`/pacts/${pactId}/cosign`, {}, pactId);
  }

  async object(pactId, reason) {
    return this.signedCall(`/pacts/${pactId}/object`, { reason }, pactId);
  }

  cancelSig(pactId, stateNonce, expiresAt) {
    return signCanonical({ action: "cancel", pactId, stateNonce, expiresAt }, this.privkey);
  }

  /** sigs: 전원의 {signer, sig} — 다른 party의 서명은 각자 cancelSig로 만들어 모은다 */
  async cancel(pactId, expiresAt, sigs) {
    const n = await this.nonce(pactId);
    return this.http("POST", `/pacts/${pactId}/cancel`, this.envelope({ expiresAt, sigs }, pactId, n));
  }

  async poke(pactId) {
    return this.http("POST", `/pacts/${pactId}/poke`);
  }

  // ---- access (invite-mode servers: writes 403 with error "access_required" until allowed) ----

  /** request an email OTP binding this partyId — check the inbox, then verifyAccess(otp) */
  async requestAccess(email, useCase) {
    return this.http("POST", "/access/request", this.envelope({ email, ...(useCase ? { useCase } : {}) }, "", 0));
  }

  /** submit the 6-digit code from the email — grants access (or queues for approval) */
  async verifyAccess(otp) {
    return this.http("POST", "/access/verify", this.envelope({ otp: String(otp) }, "", 0));
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
      this.envelope({ action, ...(target ? { target } : {}), ...(note ? { note } : {}) }, "", 0)
    );
  }

  /** PartyId↔rail 주소 바인딩 (x402 payout 수취에 필요) */
  async bindRailAddress(rail, address) {
    return this.http("POST", `/rails/${rail}/address`, this.envelope({ address }, "", 0));
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
