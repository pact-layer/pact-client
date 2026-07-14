import { createHash } from "node:crypto";
import {
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  ftruncateSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  unlinkSync,
  writeSync
} from "node:fs";
import { join, resolve } from "node:path";

const DIRECTORY_MODE = 0o700;
const JOURNAL_MODE = 0o600;
const MAX_JOURNAL_BYTES = 4096;

function currentUid() {
  if (typeof process.getuid !== "function") {
    throw new Error("Pact payment-attempt journals require an operating system user identity");
  }
  return process.getuid();
}

function permissionMode(stat) {
  return stat.mode & 0o777;
}

function assertSecureDirectory(path, label) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error(`${label} must be a real directory, not a symlink`);
  }
  if (stat.uid !== currentUid()) throw new Error(`${label} must be owned by the current user`);
  if (permissionMode(stat) !== DIRECTORY_MODE) {
    throw new Error(`${label} must have mode 0700`);
  }
}

function ensureSecureDirectory(path, label, recursive) {
  if (!existsSync(path)) mkdirSync(path, { mode: DIRECTORY_MODE, recursive });
  assertSecureDirectory(path, label);
}

function fsyncDirectory(path) {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_DIRECTORY ?? 0));
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function writeState(fd, value) {
  const encoded = Buffer.from(`${JSON.stringify(value)}\n`, "utf8");
  if (encoded.length > MAX_JOURNAL_BYTES) throw new Error("Pact payment-attempt journal is too large");
  ftruncateSync(fd, 0);
  let offset = 0;
  while (offset < encoded.length) offset += writeSync(fd, encoded, offset, encoded.length - offset, offset);
  fsyncSync(fd);
}

function assertSecureJournal(path) {
  const stat = lstatSync(path);
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error("existing Pact payment-attempt journal is not a regular file; refusing payment");
  }
  if (stat.uid !== currentUid()) {
    throw new Error("existing Pact payment-attempt journal is not owned by the current user; refusing payment");
  }
  if (permissionMode(stat) !== JOURNAL_MODE) {
    throw new Error("existing Pact payment-attempt journal must have mode 0600; refusing payment");
  }
  if (stat.size < 1 || stat.size > MAX_JOURNAL_BYTES) {
    throw new Error("existing Pact payment-attempt journal is invalid; refusing payment");
  }
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new Error("existing Pact payment-attempt journal is unreadable; refusing payment");
  }
  if (
    !parsed ||
    parsed.version !== 1 ||
    !["probing", "submitted_uncertain", "settled"].includes(parsed.state)
  ) {
    throw new Error("existing Pact payment-attempt journal has an unknown state; refusing payment");
  }
  return parsed;
}

function intentDigest({ fundingUrl, pactId, signer }) {
  const url = new URL(fundingUrl);
  return createHash("sha256")
    .update(JSON.stringify({ origin: url.origin, pactId, signer, version: 1 }))
    .digest("hex");
}

function evidenceDigest(value) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("Pact payment evidence must be a non-empty string");
  }
  return createHash("sha256").update(value).digest("hex");
}

function existingAttemptError(path) {
  const existing = assertSecureJournal(path);
  if (existing.state === "probing") {
    return new Error(
      "Pact funding payment is already in progress or its pre-submit process stopped; verify it before removing the journal"
    );
  }
  return new Error(
    `Pact funding payment is ${existing.state.replace("_", " ")}; do not retry; reconcile Pact and chain state first`
  );
}

/**
 * Acquire one fail-closed, cross-process funding attempt.
 *
 * The filename binds the Pact server origin, Pact ID, and Pact signer rather
 * than a particular SignedCall timestamp. This prevents two processes from
 * racing different but otherwise valid fund calls for the same obligation.
 */
export function acquirePaymentAttempt({ pactHome, fundingUrl, pactId, protocol, signer }) {
  if (typeof pactHome !== "string" || pactHome.length === 0) {
    throw new Error("Pact payment-attempt journal requires PACT_HOME");
  }
  if (protocol !== "mpp" && protocol !== "x402") {
    throw new Error("Pact payment-attempt journal requires mpp or x402");
  }
  if (typeof pactId !== "string" || pactId.length === 0 || typeof signer !== "string" || signer.length === 0) {
    throw new Error("Pact payment-attempt journal requires the Pact ID and signer");
  }

  const home = resolve(pactHome);
  ensureSecureDirectory(home, "PACT_HOME", true);
  const directory = join(home, "payment-attempts");
  ensureSecureDirectory(directory, "Pact payment-attempt directory", false);

  const intent = intentDigest({ fundingUrl, pactId, signer });
  const path = join(directory, `${intent}.json`);
  let fd;
  try {
    fd = openSync(
      path,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0),
      JOURNAL_MODE
    );
  } catch (error) {
    if (error?.code === "EEXIST") throw existingAttemptError(path);
    throw error;
  }

  const opened = fstatSync(fd);
  if (!opened.isFile() || opened.uid !== currentUid() || permissionMode(opened) !== JOURNAL_MODE) {
    closeSync(fd);
    try { unlinkSync(path); } catch {}
    throw new Error("new Pact payment-attempt journal failed its owner or mode check");
  }

  let state = "probing";
  let closed = false;
  const createdAt = new Date().toISOString();
  try {
    writeState(fd, { createdAt, intent, protocol, state, version: 1 });
    fsyncDirectory(directory);
  } catch (error) {
    closeSync(fd);
    closed = true;
    try {
      unlinkSync(path);
      fsyncDirectory(directory);
    } catch {}
    throw error;
  }

  function closeJournal() {
    if (!closed) {
      closeSync(fd);
      closed = true;
    }
  }

  return Object.freeze({
    get path() { return path; },
    get state() { return state; },
    markSubmitted(credential) {
      if (closed || state !== "probing") throw new Error("Pact payment-attempt journal is not probing");
      const nextState = "submitted_uncertain";
      writeState(fd, {
        createdAt,
        credentialHash: evidenceDigest(credential),
        intent,
        protocol,
        state: nextState,
        updatedAt: new Date().toISOString(),
        version: 1
      });
      state = nextState;
    },
    markSettled(receipt) {
      if (closed || state !== "submitted_uncertain") {
        throw new Error("Pact payment-attempt journal has no submitted payment to settle");
      }
      const nextState = "settled";
      writeState(fd, {
        createdAt,
        intent,
        protocol,
        receiptHash: evidenceDigest(receipt),
        state: nextState,
        updatedAt: new Date().toISOString(),
        version: 1
      });
      state = nextState;
      closeJournal();
    },
    leaveFailClosed() {
      closeJournal();
    },
    releaseRetrySafe() {
      if (state !== "probing") {
        closeJournal();
        throw new Error("submitted Pact payment-attempt journals cannot be released for retry");
      }
      closeJournal();
      unlinkSync(path);
      fsyncDirectory(directory);
    }
  });
}
