import assert from "node:assert/strict";
import {
  chmodSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import test from "node:test";
import { acquirePaymentAttempt } from "../lib/payment-attempt-journal.js";

const FUNDING = Object.freeze({
  fundingUrl: "https://api.pact.sh/pacts/p_secret-id/fund",
  pactId: "p_secret-id",
  protocol: "x402",
  signer: "ed25519:secret-party"
});

test("payment attempt journals use an exclusive hashed 0600 file and retain only evidence hashes", () => {
  const pactHome = mkdtempSync(join(tmpdir(), "pact-attempt-journal-"));
  const attempt = acquirePaymentAttempt({ ...FUNDING, pactHome });
  assert.match(basename(attempt.path), /^[0-9a-f]{64}\.json$/);
  assert.doesNotMatch(basename(attempt.path), /secret|party|pact/i);
  assert.equal(statSync(pactHome).mode & 0o777, 0o700);
  assert.equal(statSync(join(pactHome, "payment-attempts")).mode & 0o777, 0o700);
  assert.equal(statSync(attempt.path).mode & 0o777, 0o600);
  assert.throws(
    () => acquirePaymentAttempt({ ...FUNDING, pactHome }),
    /already in progress/
  );
  assert.throws(
    () => acquirePaymentAttempt({
      ...FUNDING,
      fundingUrl: "https://api.pact.sh/a-different-signed-call-path",
      pactHome,
      protocol: "mpp"
    }),
    /already in progress/
  );

  const credential = `Payment ${"credential-secret".repeat(20)}`;
  attempt.markSubmitted(credential);
  const uncertain = readFileSync(attempt.path, "utf8");
  assert.equal(JSON.parse(uncertain).state, "submitted_uncertain");
  assert.equal(uncertain.includes(credential), false);
  assert.throws(
    () => acquirePaymentAttempt({ ...FUNDING, pactHome }),
    /submitted uncertain; do not retry/
  );

  const receipt = `receipt-${"public-evidence".repeat(20)}`;
  attempt.markSettled(receipt);
  const settled = readFileSync(attempt.path, "utf8");
  assert.equal(JSON.parse(settled).state, "settled");
  assert.equal(settled.includes(credential), false);
  assert.equal(settled.includes(receipt), false);
  assert.throws(
    () => acquirePaymentAttempt({ ...FUNDING, pactHome }),
    /settled; do not retry/
  );
});

test("payment attempt journals release only a retry-safe probing state", () => {
  const pactHome = mkdtempSync(join(tmpdir(), "pact-attempt-release-"));
  const first = acquirePaymentAttempt({ ...FUNDING, pactHome });
  first.releaseRetrySafe();
  const second = acquirePaymentAttempt({ ...FUNDING, pactHome });
  second.releaseRetrySafe();

  const other = acquirePaymentAttempt({
    ...FUNDING,
    pactHome,
    pactId: "p_other",
    fundingUrl: "https://api.pact.sh/pacts/p_other/fund"
  });
  other.releaseRetrySafe();
});

test("payment attempt journals reject permissive directories and symlinks", () => {
  const permissiveHome = mkdtempSync(join(tmpdir(), "pact-attempt-mode-"));
  chmodSync(permissiveHome, 0o755);
  assert.throws(
    () => acquirePaymentAttempt({ ...FUNDING, pactHome: permissiveHome }),
    /PACT_HOME must have mode 0700/
  );

  const symlinkParent = mkdtempSync(join(tmpdir(), "pact-attempt-home-link-"));
  const realHome = join(symlinkParent, "real");
  mkdirSync(realHome, { mode: 0o700 });
  const linkedHome = join(symlinkParent, "linked");
  symlinkSync(realHome, linkedHome);
  assert.throws(
    () => acquirePaymentAttempt({ ...FUNDING, pactHome: linkedHome }),
    /not a symlink/
  );

  const home = mkdtempSync(join(tmpdir(), "pact-attempt-dir-link-"));
  const target = mkdtempSync(join(tmpdir(), "pact-attempt-target-"));
  symlinkSync(target, join(home, "payment-attempts"));
  assert.throws(
    () => acquirePaymentAttempt({ ...FUNDING, pactHome: home }),
    /not a symlink/
  );

  const fileHome = mkdtempSync(join(tmpdir(), "pact-attempt-file-link-"));
  const first = acquirePaymentAttempt({ ...FUNDING, pactHome: fileHome });
  const journalPath = first.path;
  first.releaseRetrySafe();
  const targetFile = join(fileHome, "target.json");
  writeFileSync(targetFile, '{"state":"settled","version":1}\n', { mode: 0o600 });
  symlinkSync(targetFile, journalPath);
  assert.throws(
    () => acquirePaymentAttempt({ ...FUNDING, pactHome: fileHome }),
    /not a regular file/
  );
});
