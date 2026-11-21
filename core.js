/**
 * Proof Gatekeeper agent — core module (single file, no web framework).
 *
 * zkVerify Agent Games, Season 01, Proof Gatekeeper track.
 * Protocol source of truth: https://agentgames.zkverify.io/build
 * ("Agent interface", "Circuit artifacts", "Security", "Deploy and test").
 *
 * Pipeline (per task):
 *   1. HMAC-SHA256 over the RAW request body vs the x-agent-games-signature
 *      header — BEFORE any JSON parsing. Bad/missing signature -> 401.
 *   2. Preflight (type agent-games.preflight.v1) -> signed
 *      { ok: true, protocolVersion: "v1" }.
 *   3. Task: timestamp sanity, structural validation, deterministic policy
 *      evaluation (fail closed), local Groth16 proof with snarkjs + the
 *      official gatekeeper circuit, optional Kurier submission (bounded),
 *      signed response { decision, reason_code, proof, public_signals,
 *      proof_tx }.
 *
 * Only dependency: snarkjs (loaded lazily, only when proving, so the
 * preflight path — which the platform times out after 10s — stays fast).
 * Everything else is Node.js built-ins.
 *
 * Secrets come from environment variables only. Never log them.
 */

"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------- constants

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const PROTOCOL_VERSION = "v1";
const SIGNATURE_HEADER = "x-agent-games-signature";

// BN128 scalar field prime (snarkjs / circom BN128).
const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Registered gatekeeper vk_hash on zkVerify mainnet (from /build and
// /api/circuit-info). Overridable via GATEKEEPER_VK_HASH.
const DEFAULT_VK_HASH =
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";

const DEFAULT_KURIER_URL = "https://api.kurier.xyz/api/v1";

// Reason codes from the platform's trap taxonomy (/events/proof-gatekeeper).
// INVALID_TASK is defensive only (envelope-level failure outside the taxonomy).
const REASONS = {
  VALID: "VALID_CONDITION",
  VK: "VK_SUBSTITUTION",
  REUSED: "PROOF_REUSED",
  THRESHOLD: "THRESHOLD_MISMATCH",
  EXPIRED: "EXPIRED_CONDITION",
  RECIPIENT: "RECIPIENT_MISMATCH",
  AMOUNT: "AMOUNT_OVERFLOW",
  INVALID: "INVALID_TASK",
};

// ------------------------------------------------------------------- config

function defaultCircuitsDir() {
  const candidates = [
    path.resolve(__dirname, "circuits"),
    path.resolve(process.cwd(), "circuits"),
    // Netlify bundled-function layout: circuits sit next to the function dir.
    path.resolve(__dirname, "..", "circuits"),
    path.resolve(__dirname, "..", "..", "circuits"),
  ];
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, "gatekeeper.wasm"))) return c;
  }
  return candidates[0];
}

function isServerlessEnv() {
  return Boolean(process.env.VERCEL || process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME);
}

function defaultSeenStorePath() {
  // Serverless filesystems are writable only under /tmp (and ephemeral).
  if (isServerlessEnv()) return "/tmp/gatekeeper-seen.json";
  return path.resolve(process.cwd(), "data", "seen.json");
}

function defaultAuditLogPath() {
  if (isServerlessEnv()) return "/tmp/gatekeeper-audit.jsonl";
  return path.resolve(process.cwd(), "data", "audit.jsonl");
}

function loadConfig(env = process.env) {
  return {
    hmacSecret: env.AGENT_GAMES_HMAC_SECRET || "",
    kurierApiKey: env.KURIER_API_KEY || null,
    kurierApiUrl: env.KURIER_API_URL || DEFAULT_KURIER_URL,
    gatekeeperVkHash: env.GATEKEEPER_VK_HASH || DEFAULT_VK_HASH,
    circuitsDir: env.CIRCUITS_DIR || defaultCircuitsDir(),
    seenStorePath: env.SEEN_STORE_PATH || defaultSeenStorePath(),
    auditLogPath: env.AUDIT_LOG_PATH || defaultAuditLogPath(),
    kurierPollBudgetMs: Number(env.KURIER_POLL_BUDGET_MS || 15000),
    kurierPollIntervalMs: Number(env.KURIER_POLL_INTERVAL_MS || 3000),
    taskSoftDeadlineMs: Number(env.TASK_SOFT_DEADLINE_MS || 50000),
    port: Number(env.PORT || 8787),
  };
}

// --------------------------------------------------------------------- HMAC

/** Outbound signing: HMAC-SHA256, lowercase hex digest. */
function signBody(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest("hex");
}

function macBytes(secret, rawBody) {
  return crypto.createHmac("sha256", secret).update(rawBody).digest();
}

function decodeCandidate(headerValue) {
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  if (/^[0-9a-fA-F]{64}$/.test(v)) return Buffer.from(v, "hex");
  try {
    const b = Buffer.from(v, "base64");
    if (b.length === 32) return b;
  } catch {
    /* not base64 */
  }
  return null;
}

/**
 * Inbound verification: accepts the same MAC bytes in hex OR base64 (with an
 * optional "sha256=" prefix), compared in constant time. Accepting both
 * encodings of the identical MAC is a representation tolerance, not a
 * weakening — the caller must still know the secret.
 */
function verifyBodySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  const candidate = decodeCandidate(headerValue);
  if (!candidate) return false;
  const expected = macBytes(secret, rawBody);
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

// ------------------------------------------------------- field-element math

/**
 * Convert an envelope value to a BN128 field element (decimal string).
 * Hex values are reduced mod p (a 32-byte hash does not fit the field);
 * reduction preserves equality, which is all the circuit checks.
 * Free-form identifiers (e.g. a task_id like "gk_8d31_...") are hashed with
 * SHA-256 into the field first.
 *
 * NOTE (open question, see README): the official /build spec does not pin
 * either mapping. Both follow the published reference implementation whose
 * practice tasks passed with platform-verified proofs (4/4, 2026-11-15).
 */
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else if (typeof v === "number") {
    n = BigInt(v);
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else {
      const digest = crypto.createHash("sha256").update(s).digest();
      n = BigInt("0x" + digest.toString("hex"));
    }
  }
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}

/**
 * Deterministic per-task salt for the circuit's private `salt` input:
 * HMAC(secret, "gatekeeper-salt:" + task_id) mod p. Fresh for every task
 * (task_ids are unique), secret-bound (unpredictable to third parties), and
 * reproducible — so an idempotent redelivery regenerates identical proof
 * inputs instead of a second, divergent proof. The salt is also written to
 * the append-only audit log for disputes.
 */
function deriveSalt(secret, taskId) {
  const digest = crypto
    .createHmac("sha256", secret || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

// ------------------------------------------------------------------ decision

function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

function normalizeHex(v) {
  return (v || "").trim().toLowerCase();
}

/** Structural validation + parsing. Returns null on any malformed field. */
function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const minimum = parseUint(input.minimum);
  const publicBalance = parseUint(input.public_balance);
  const amount = parseUint(input.amount);
  const maxTransfer = parseUint(input.max_transfer);
  const expiryBlock = parseUint(input.expiry_block);
  const currentBlock = parseUint(input.current_block);
  if (
    minimum === null || publicBalance === null || amount === null ||
    maxTransfer === null || expiryBlock === null || currentBlock === null
  ) {
    return null;
  }
  if (
    typeof input.registered_vk !== "string" || !input.registered_vk ||
    typeof input.proof_vk !== "string" || !input.proof_vk ||
    typeof input.recipient !== "string" || !input.recipient ||
    typeof input.condition_recipient !== "string" || !input.condition_recipient ||
    typeof input.proof_tx !== "string" || !input.proof_tx
  ) {
    return null;
  }
  return {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum,
    publicBalance,
    expiryBlock,
    currentBlock,
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount,
    maxTransfer,
    proofTx: input.proof_tx,
  };
}

/**
 * Deterministic policy, fail closed. Check order follows the platform's trap
 * taxonomy. Boundary semantics mirror the circuit exactly: balance >=
 * minimum passes, amount <= max_transfer passes, current_block <
 * expiry_block passes. The circuit enforces decision == AND(all five field
 * checks), so the evaluation here and the circuit inputs must agree — a
 * mismatch fails witness generation, which the handler treats as fatal.
 *
 * PROOF_REUSED is the documented special case: a task whose proof_tx was
 * already used for another task has no proof to submit (provable: false).
 */
function evaluate(parsed, isProofTxSeen) {
  if (normalizeHex(parsed.proofVk) !== normalizeHex(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: REASONS.VK, provable: true };
  }
  if (isProofTxSeen(parsed.proofTx)) {
    return { decision: "REJECT", reason_code: REASONS.REUSED, provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: REASONS.THRESHOLD, provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: REASONS.EXPIRED, provable: true };
  }
  if (normalizeHex(parsed.recipient) !== normalizeHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: REASONS.RECIPIENT, provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: REASONS.AMOUNT, provable: true };
  }
  return { decision: "APPROVE", reason_code: REASONS.VALID, provable: true };
}

/**
 * Circuit inputs for gatekeeper.wasm. Signal names were recovered from the
 * artifact itself; public-signal order (verified empirically):
 *   [0]=Poseidon([salt,taskId]), [1]=registeredVkHash, [2]=proofVkHash,
 *   [3]=minimum, [4]=publicBalance, [5]=expiryBlock, [6]=currentBlock,
 *   [7]=recipient, [8]=conditionRecipient, [9]=amount, [10]=maxTransfer,
 *   [11]=decision, [12]=taskId
 */
function buildCircuitInputs(envelope, parsed, decision, salt) {
  return {
    taskId: toFieldElement(envelope.task_id),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: salt.toString(10),
  };
}

// -------------------------------------------------------------------- prover

let snarkjsModule = null;
function getSnarkjs() {
  // Lazy: the preflight path must never pay the snarkjs load cost.
  if (!snarkjsModule) snarkjsModule = require("snarkjs");
  return snarkjsModule;
}

class Prover {
  constructor(circuitsDir) {
    this.wasmPath = path.join(circuitsDir, "gatekeeper.wasm");
    this.zkeyPath = path.join(circuitsDir, "gatekeeper_final.zkey");
  }

  async prove(circuitInputs) {
    const snarkjs = getSnarkjs();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      circuitInputs,
      this.wasmPath,
      this.zkeyPath,
    );
    return { proof, publicSignals };
  }
}

// ------------------------------------------------------------------- Kurier

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Kurier (zkVerify) proof submission — mainnet.
 *   POST {apiUrl}/submit-proof/{key}
 *     { proofType: "groth16", vkRegistered: true,
 *       proofOptions: { library: "snarkjs", curve: "bn128" },
 *       proofData: { proof, publicSignals, vk: <vk_hash> } }
 *   -> { jobId, optimisticVerify }
 *   GET {apiUrl}/job-status/{key}/{jobId}
 *   lifecycle: Queued -> Valid -> Submitted -> IncludedInBlock -> Finalized | Failed
 *
 * The txHash exists from the Submitted status onward, so polling returns as
 * soon as a txHash is known instead of blocking the task response on
 * finalization; the Kurier job keeps finalizing server-side regardless.
 * This function never throws: any failure returns null and the caller still
 * answers the task with the proof + public_signals. Without a KURIER_API_KEY
 * the submission is skipped entirely (the agent still competes — proof_tx
 * then echoes the task's input reference).
 */
async function submitProofAndPoll(cfg, proof, publicSignals, budgetMs) {
  if (!cfg.kurierApiKey) return null;
  const key = cfg.kurierApiKey;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const submitRes = await fetch(`${cfg.kurierApiUrl}/submit-proof/${key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: cfg.gatekeeperVkHash },
      }),
    });
    if (!submitRes.ok) {
      console.error(`[kurier] submit-proof HTTP ${submitRes.status}`);
      return null;
    }
    const job = await submitRes.json();
    if (!job.jobId) {
      console.error("[kurier] submit-proof response missing jobId");
      return null;
    }

    let status = "Submitted";
    let lastTxHash;
    while (Date.now() < deadline) {
      await sleep(Math.min(cfg.kurierPollIntervalMs, Math.max(0, deadline - Date.now())));
      const statusRes = await fetch(`${cfg.kurierApiUrl}/job-status/${key}/${job.jobId}`);
      if (!statusRes.ok) {
        console.error(`[kurier] job-status HTTP ${statusRes.status}`);
        continue;
      }
      const s = await statusRes.json();
      status = s.status || status;
      const txHash = s.txHash || (s.transactionInfo && s.transactionInfo.txHash);
      if (txHash) lastTxHash = txHash;
      if (status === "Failed") {
        return { jobId: job.jobId, status, txHash, finalized: false };
      }
      if (txHash) {
        return { jobId: job.jobId, status, txHash, finalized: status === "Finalized" };
      }
    }
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (err) {
    console.error("[kurier] submission error:", err.message);
    return null;
  }
}

// --------------------------------------------------------------- seen store

/**
 * Seen-set for proof_tx references ("The proof reference has not already
 * been used for another task" — /build Security checklist; PROOF_REUSED
 * trap). In-memory Set is authoritative for the life of the process; a JSON
 * file backs it across restarts (best-effort: on serverless the file lives
 * in /tmp and may vanish on cold start, so PROOF_REUSED detection there is
 * best-effort). Also caches task_id -> serialized response so a redelivered
 * task is answered idempotently instead of being misread as proof reuse.
 */
class SeenStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.seenProofTx = new Set();
    this.responseByTaskId = new Map();
    this.load();
  }

  load() {
    try {
      const raw = fs.readFileSync(this.filePath, "utf8");
      const data = JSON.parse(raw);
      for (const tx of data.proofTx || []) this.seenProofTx.add(normalizeTx(tx));
      for (const [k, v] of Object.entries(data.responses || {})) {
        this.responseByTaskId.set(k, v);
      }
    } catch {
      /* missing/corrupt file -> start empty */
    }
  }

  persist() {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const tmp = `${this.filePath}.tmp`;
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          proofTx: [...this.seenProofTx],
          responses: Object.fromEntries(this.responseByTaskId),
        }),
      );
      fs.renameSync(tmp, this.filePath);
    } catch (err) {
      console.error("[seen-store] persist failed:", err.message);
    }
  }

  hasProofTx(proofTx) {
    return this.seenProofTx.has(normalizeTx(proofTx));
  }

  recordProofTx(proofTx) {
    const key = normalizeTx(proofTx);
    if (!key) return;
    if (!this.seenProofTx.has(key)) {
      this.seenProofTx.add(key);
      this.persist();
    }
  }

  getResponse(taskId) {
    return this.responseByTaskId.get(taskId) || null;
  }

  recordResponse(taskId, serializedResponse) {
    if (!this.responseByTaskId.has(taskId)) {
      this.responseByTaskId.set(taskId, serializedResponse);
      this.persist();
    }
  }

  get size() {
    return this.seenProofTx.size;
  }
}

function normalizeTx(tx) {
  return (tx || "").trim().toLowerCase();
}

// ----------------------------------------------------------------- audit log

/**
 * Append-only audit log: one JSON line per answered task (task_id, salt,
 * decision, reason_code, proof_tx, timings, Kurier job). The salt is the
 * circuit's private input — the file is created mode 600 and must never be
 * committed (see .gitignore). Writes are best-effort and never fail a task.
 */
class AuditLog {
  constructor(filePath) {
    this.filePath = filePath;
  }

  append(entry) {
    try {
      fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
      const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
      const fd = fs.openSync(this.filePath, "a", 0o600);
      try {
        fs.writeSync(fd, line);
      } finally {
        fs.closeSync(fd);
      }
      try {
        fs.chmodSync(this.filePath, 0o600);
      } catch {
        /* ignore */
      }
    } catch (err) {
      console.error("[audit] append failed:", err.message);
    }
  }
}

// ------------------------------------------------------------------ handler

/** Tolerant timestamp parse: ISO string, epoch seconds, or epoch ms. */
function parseTimestamp(v) {
  if (typeof v === "number" && Number.isFinite(v)) {
    return v < 1e12 ? v * 1000 : v;
  }
  if (typeof v === "string") {
    const asNum = Number(v);
    if (/^[0-9]+$/.test(v.trim()) && Number.isFinite(asNum)) {
      return asNum < 1e12 ? asNum * 1000 : asNum;
    }
    const t = Date.parse(v);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

class AgentHandler {
  constructor(cfg, store, audit) {
    this.cfg = cfg;
    this.store = store;
    this.audit = audit || new AuditLog(cfg.auditLogPath);
    this.prover = new Prover(cfg.circuitsDir);
  }

  health() {
    const body = JSON.stringify({ ok: true, protocolVersion: PROTOCOL_VERSION });
    return { status: 200, body, signature: null };
  }

  async handlePost(rawBody, signatureHeader) {
    const startedAt = Date.now();

    if (!this.cfg.hmacSecret) {
      return {
        status: 500,
        body: JSON.stringify({ error: "server_misconfigured", detail: "AGENT_GAMES_HMAC_SECRET not set" }),
        signature: null,
      };
    }

    // 1. Authenticate the raw body BEFORE parsing.
    if (!verifyBodySignature(this.cfg.hmacSecret, rawBody, signatureHeader)) {
      return {
        status: 401,
        body: JSON.stringify({ error: "invalid_signature" }),
        signature: null,
      };
    }

    let envelope;
    try {
      envelope = JSON.parse(rawBody.toString("utf8"));
    } catch {
      return this.signed(400, { decision: "REJECT", reason_code: REASONS.INVALID });
    }

    // 2. Preflight handshake.
    if (envelope.type === PREFLIGHT_TYPE) {
      return this.signed(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
    }

    if (envelope.type !== TASK_TYPE) {
      return this.signed(400, { decision: "REJECT", reason_code: REASONS.INVALID });
    }

    // 3. Task. Any error or uncertainty fails closed to REJECT.
    try {
      return await this.handleTask(envelope, startedAt);
    } catch (err) {
      console.error("[agent] task handling error:", err.message);
      return this.signed(200, { decision: "REJECT", reason_code: REASONS.INVALID });
    }
  }

  async handleTask(task, startedAt) {
    // Idempotent redelivery: answer from the cache, never re-evaluate
    // (a redelivery must not be mistaken for proof reuse).
    if (task.task_id) {
      const cached = this.store.getResponse(task.task_id);
      if (cached) return this.signedRaw(200, cached);
    }

    // Timestamp / deadline sanity (HMAC already authenticates the sender;
    // this is anti-replay hygiene). Unparseable timestamps are logged, not
    // fatal — only a clearly-past deadline fails the task.
    const now = Date.now();
    const deadlineMs = parseTimestamp(task.deadline_at);
    const issuedMs = parseTimestamp(task.issued_at);
    if (deadlineMs !== null && now > deadlineMs) {
      return this.signed(200, { decision: "REJECT", reason_code: REASONS.INVALID });
    }
    if (issuedMs !== null && issuedMs > now + 5 * 60 * 1000) {
      return this.signed(200, { decision: "REJECT", reason_code: REASONS.INVALID });
    }

    const parsed = parseInput(task.input);
    if (!parsed || !task.task_id) {
      return this.signed(200, { decision: "REJECT", reason_code: REASONS.INVALID });
    }

    const evaluation = evaluate(parsed, (tx) => this.store.hasProofTx(tx));

    const response = {
      decision: evaluation.decision,
      reason_code: evaluation.reason_code,
    };
    let salt = null;
    let proveMs = null;
    let kurier = null;

    if (evaluation.provable) {
      salt = deriveSalt(this.cfg.hmacSecret, task.task_id);
      const circuitInputs = buildCircuitInputs(task, parsed, evaluation.decision, salt);
      try {
        const t0 = Date.now();
        const { proof, publicSignals } = await this.prover.prove(circuitInputs);
        proveMs = Date.now() - t0;
        response.proof = proof;
        response.public_signals = publicSignals;

        // zkVerify submission via Kurier, bounded so the response stays well
        // inside the 60s deadline. Never blocks the answer on finalization:
        // on budget expiry we still return the proof + public_signals.
        const remaining = this.cfg.taskSoftDeadlineMs - (Date.now() - startedAt);
        const budget = Math.min(this.cfg.kurierPollBudgetMs, Math.max(0, remaining));
        kurier = await submitProofAndPoll(this.cfg, proof, publicSignals, budget);
        response.proof_tx = kurier && kurier.txHash ? kurier.txHash : parsed.proofTx;
      } catch (err) {
        // Proving failed: fail closed. A claimed APPROVE without a valid
        // proof is the worst outcome, so downgrade to REJECT with no proof.
        console.error("[agent] proof generation failed:", err.message);
        return this.signed(200, {
          decision: "REJECT",
          reason_code: evaluation.decision === "APPROVE" ? REASONS.INVALID : evaluation.reason_code,
          proof_tx: parsed.proofTx,
        });
      }
    } else {
      // PROOF_REUSED: documented as having no proof to submit; echo the
      // reference, matching the sample response shape on /build.
      response.proof_tx = parsed.proofTx;
    }

    const result = this.signed(200, response);
    // Record only after a successful evaluation, so a task never flags itself.
    this.store.recordProofTx(parsed.proofTx);
    this.store.recordResponse(task.task_id, result.body);
    this.audit.append({
      task_id: task.task_id,
      salt: salt !== null ? salt.toString(10) : null,
      decision: response.decision,
      reason_code: response.reason_code,
      proof_tx: response.proof_tx,
      prove_ms: proveMs,
      total_ms: Date.now() - startedAt,
      kurier_job: kurier ? { jobId: kurier.jobId, status: kurier.status, finalized: kurier.finalized } : null,
    });
    return result;
  }

  signed(status, obj) {
    return this.signedRaw(status, JSON.stringify(obj));
  }

  signedRaw(status, body) {
    return { status, body, signature: signBody(this.cfg.hmacSecret, body) };
  }
}

module.exports = {
  TASK_TYPE,
  PREFLIGHT_TYPE,
  PROTOCOL_VERSION,
  SIGNATURE_HEADER,
  BN128_PRIME,
  DEFAULT_VK_HASH,
  REASONS,
  loadConfig,
  signBody,
  verifyBodySignature,
  toFieldElement,
  deriveSalt,
  parseUint,
  parseInput,
  evaluate,
  buildCircuitInputs,
  Prover,
  submitProofAndPoll,
  SeenStore,
  AuditLog,
  parseTimestamp,
  AgentHandler,
};
