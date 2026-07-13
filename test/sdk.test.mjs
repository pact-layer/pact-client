import assert from "node:assert/strict";
import test from "node:test";
import { PactClient } from "../lib/sdk.js";

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
