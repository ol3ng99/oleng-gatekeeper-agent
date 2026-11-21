/**
 * Local test harness for the Proof Gatekeeper agent.
 *
 * Boots the real HTTP server on an ephemeral port with a throwaway HMAC
 * secret and temp seen-store/audit paths, then replays signed envelopes
 * built from the /build + /events/proof-gatekeeper samples:
 *   - preflight handshake shape + response signature
 *   - HMAC sign/verify roundtrip (hex + base64), tamper + wrong-secret rejects
 *   - one VALID_CONDITION approve, with the returned Groth16 proof verified
 *     locally against the circuit verification key
 *   - every documented trap: VK_SUBSTITUTION, PROOF_REUSED,
 *     THRESHOLD_MISMATCH, EXPIRED_CONDITION, RECIPIENT_MISMATCH,
 *     AMOUNT_OVERFLOW (decision + reason_code asserted, proof verified
 *     where the spec requires one)
 *   - idempotent redelivery of the same task_id
 *   - fail-closed behaviour (bad/missing HMAC, malformed input, past deadline)
 *   - proof-generation timing per decision (must fit a 10s serverless budget)
 *
 * Run: npm test   (KURIER_API_KEY is unset here, so submission is skipped
 * and the answers are unaffected — the Kurier path is exercised only with
 * a real key.)
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");

const TEST_SECRET = "test-secret-for-local-harness-only";
process.env.AGENT_GAMES_HMAC_SECRET = TEST_SECRET;
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "gk-test-"));
process.env.SEEN_STORE_PATH = path.join(tmpDir, "seen.json");
process.env.AUDIT_LOG_PATH = path.join(tmpDir, "audit.jsonl");
delete process.env.KURIER_API_KEY;

const VK_HASH = "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
const OTHER_RECIPIENT = "0x742d35Cc6634C0532925a3b844Bc454e4438f44f";

let passed = 0;
let failed = 0;
const failures = [];
function check(name, cond, extra) {
  if (cond) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  FAIL  ${name}${extra ? ` — ${extra}` : ""}`);
  }
}

function tx(seed) {
  return "0x" + crypto.createHash("sha256").update(seed).digest("hex");
}

function makeTask(taskId, overrides = {}) {
  const now = Date.now();
  return {
    type: "agent-games.proof-gatekeeper.v1",
    task_id: taskId,
    mode: "competition",
    issued_at: new Date(now).toISOString(),
    deadline_at: new Date(now + 55000).toISOString(),
    input: {
      registered_vk: VK_HASH,
      proof_vk: VK_HASH,
      minimum: "1000",
      public_balance: "1460",
      expiry_block: 8430000,
      current_block: 8420000,
      recipient: RECIPIENT,
      condition_recipient: RECIPIENT,
      amount: "500",
      max_transfer: "1000",
      proof_tx: tx("proof-" + taskId),
      ...overrides,
    },
  };
}

async function main() {
  const { createAgentServer } = require("../server");
  const core = require("../core");
  const snarkjs = require("snarkjs");
  const verificationKey = JSON.parse(
    fs.readFileSync(path.resolve(__dirname, "..", "circuits", "verification_key.json"), "utf8"),
  );

  const server = createAgentServer();
  await new Promise((resolve) => server.listen(0, resolve));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  const proveTimings = [];

  async function post(body, opts = {}) {
    const headers = { "content-type": "application/json" };
    if (opts.sign !== false) {
      headers["x-agent-games-signature"] =
        opts.signature !== undefined
          ? opts.signature
          : core.signBody(opts.secret || TEST_SECRET, body);
    }
    const t0 = Date.now();
    const res = await fetch(`${base}/agent`, { method: "POST", headers, body });
    const elapsed = Date.now() - t0;
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* keep null */
    }
    return { status: res.status, json, text, sig: res.headers.get("x-agent-games-signature"), elapsed };
  }

  console.log("== HMAC unit checks ==");
  {
    const body = JSON.stringify({ hello: "world" });
    const hexSig = core.signBody(TEST_SECRET, body);
    check("hex signature verifies", core.verifyBodySignature(TEST_SECRET, body, hexSig));
    const b64Sig = crypto.createHmac("sha256", TEST_SECRET).update(body).digest("base64");
    check("base64 signature verifies", core.verifyBodySignature(TEST_SECRET, body, b64Sig));
    check("prefixed signature verifies", core.verifyBodySignature(TEST_SECRET, body, "sha256=" + hexSig));
    check("tampered body rejected", !core.verifyBodySignature(TEST_SECRET, body + " ", hexSig));
    check("wrong secret rejected", !core.verifyBodySignature("other-secret", body, hexSig));
    check("missing header rejected", !core.verifyBodySignature(TEST_SECRET, body, undefined));
    check("empty header rejected", !core.verifyBodySignature(TEST_SECRET, body, ""));
  }

  console.log("== Preflight ==");
  {
    const body = JSON.stringify({
      type: "agent-games.preflight.v1",
      agent_id: "agt_test",
      issued_at: new Date().toISOString(),
      nonce: "abc123",
    });
    const r = await post(body);
    check("preflight status 200", r.status === 200, `got ${r.status}`);
    check("preflight body shape", r.json && r.json.ok === true && r.json.protocolVersion === "v1", JSON.stringify(r.json));
    check(
      "preflight response signed",
      r.sig !== null && core.verifyBodySignature(TEST_SECRET, r.text, r.sig),
    );
    check(`preflight answered in ${r.elapsed}ms (< 10s platform window)`, r.elapsed < 10000);
    const bad = await post(body, { secret: "wrong-secret" });
    check("preflight with bad HMAC -> 401", bad.status === 401, `got ${bad.status}`);
    const unsigned = await post(body, { sign: false });
    check("preflight with missing HMAC -> 401", unsigned.status === 401, `got ${unsigned.status}`);
  }

  console.log("== Health ==");
  {
    const res = await fetch(`${base}/agent`);
    const json = await res.json();
    check("GET /agent health", res.status === 200 && json.ok === true && json.protocolVersion === "v1");
    const res2 = await fetch(`${base}/health`);
    check("GET /health", res2.status === 200);
  }

  async function expectTask(label, task, decision, reason, withProof) {
    const r = await post(JSON.stringify(task));
    proveTimings.push({ label, ms: r.elapsed });
    check(`${label}: status 200`, r.status === 200, `got ${r.status}`);
    check(`${label}: decision ${decision}`, r.json && r.json.decision === decision, JSON.stringify(r.json));
    check(`${label}: reason ${reason}`, r.json && r.json.reason_code === reason, JSON.stringify(r.json));
    check(
      `${label}: response signed`,
      r.sig !== null && core.verifyBodySignature(TEST_SECRET, r.text, r.sig),
    );
    check(`${label}: answered in ${r.elapsed}ms (< 60s deadline)`, r.elapsed < 60000);
    check(`${label}: answered in ${r.elapsed}ms (< 10s serverless budget)`, r.elapsed < 10000);
    if (withProof) {
      check(`${label}: proof present`, !!(r.json && r.json.proof) && Array.isArray(r.json.public_signals));
      check(
        `${label}: 13 public signals`,
        Array.isArray(r.json && r.json.public_signals) && r.json.public_signals.length === 13,
        `got ${r.json && r.json.public_signals && r.json.public_signals.length}`,
      );
      if (r.json && r.json.proof && r.json.public_signals) {
        const ok = await snarkjs.groth16.verify(verificationKey, r.json.public_signals, r.json.proof);
        check(`${label}: proof verifies locally against circuit VK`, ok === true);
        const expectedDecisionSignal = decision === "APPROVE" ? "1" : "0";
        check(
          `${label}: decision signal = ${expectedDecisionSignal}`,
          r.json.public_signals[11] === expectedDecisionSignal,
          `got ${r.json.public_signals[11]}`,
        );
        // Public-signal field order spot-check: minimum/balance/amount/max.
        check(
          `${label}: public signals carry the task values`,
          r.json.public_signals[3] === "1000" &&
            r.json.public_signals[4] === String(task.input.public_balance) &&
            r.json.public_signals[9] === String(task.input.amount) &&
            r.json.public_signals[10] === String(task.input.max_transfer),
          JSON.stringify(r.json.public_signals),
        );
      }
    } else {
      check(`${label}: no proof attached (documented for PROOF_REUSED)`, !(r.json && r.json.proof));
      check(`${label}: proof_tx echoed`, r.json && r.json.proof_tx === task.input.proof_tx);
    }
    return r.json;
  }

  console.log("== Valid condition ==");
  const validTask = makeTask("gk_test_valid");
  await expectTask("valid", validTask, "APPROVE", "VALID_CONDITION", true);

  console.log("== Idempotent redelivery ==");
  {
    const r = await post(JSON.stringify(validTask));
    check(
      "redelivery still APPROVE (not PROOF_REUSED)",
      r.json && r.json.decision === "APPROVE" && r.json.reason_code === "VALID_CONDITION",
      JSON.stringify(r.json),
    );
    check("redelivery is fast (cached, no re-prove)", r.elapsed < 1000, `${r.elapsed}ms`);
  }

  console.log("== Traps ==");
  await expectTask(
    "vk-substitution",
    makeTask("gk_test_vk", { proof_vk: "0x13ab00000000000000000000000000000000000000000000000000000000aa" }),
    "REJECT",
    "VK_SUBSTITUTION",
    true,
  );

  const reusedTx = tx("proof-gk_test_reuse_source");
  await expectTask("reuse-source", makeTask("gk_test_reuse_source", { proof_tx: reusedTx }), "APPROVE", "VALID_CONDITION", true);
  await expectTask(
    "proof-reused",
    makeTask("gk_test_reuse", { proof_tx: reusedTx }),
    "REJECT",
    "PROOF_REUSED",
    false,
  );

  await expectTask(
    "threshold-mismatch",
    makeTask("gk_test_threshold", { public_balance: "999" }),
    "REJECT",
    "THRESHOLD_MISMATCH",
    true,
  );
  await expectTask(
    "expired-condition",
    makeTask("gk_test_expired", { current_block: 8430000 }),
    "REJECT",
    "EXPIRED_CONDITION",
    true,
  );
  await expectTask(
    "recipient-mismatch",
    makeTask("gk_test_recipient", { recipient: OTHER_RECIPIENT }),
    "REJECT",
    "RECIPIENT_MISMATCH",
    true,
  );
  await expectTask(
    "amount-overflow",
    makeTask("gk_test_amount", { amount: "1001" }),
    "REJECT",
    "AMOUNT_OVERFLOW",
    true,
  );

  console.log("== Boundary semantics (must match the circuit exactly) ==");
  await expectTask(
    "boundary-balance-eq-minimum",
    makeTask("gk_test_bnd_bal", { public_balance: "1000" }),
    "APPROVE",
    "VALID_CONDITION",
    true,
  );
  await expectTask(
    "boundary-amount-eq-max",
    makeTask("gk_test_bnd_amt", { amount: "1000" }),
    "APPROVE",
    "VALID_CONDITION",
    true,
  );
  await expectTask(
    "boundary-current-one-before-expiry",
    makeTask("gk_test_bnd_blk", { current_block: 8429999 }),
    "APPROVE",
    "VALID_CONDITION",
    true,
  );

  console.log("== Fail-closed behaviour ==");
  {
    const r = await post(JSON.stringify(makeTask("gk_test_tampered")), { sign: false, signature: "deadbeef" });
    check("bad signature -> 401", r.status === 401, `got ${r.status}`);
    const r2 = await post(JSON.stringify(makeTask("gk_test_nosig")), { sign: false });
    check("missing signature -> 401", r2.status === 401, `got ${r2.status}`);
    const malformed = await post(
      JSON.stringify({ type: "agent-games.proof-gatekeeper.v1", task_id: "gk_test_bad", input: { minimum: "x" } }),
    );
    check(
      "malformed input -> REJECT/INVALID_TASK",
      malformed.json && malformed.json.decision === "REJECT" && malformed.json.reason_code === "INVALID_TASK",
      JSON.stringify(malformed.json),
    );
    const pastDeadline = makeTask("gk_test_past");
    pastDeadline.deadline_at = new Date(Date.now() - 60000).toISOString();
    const pd = await post(JSON.stringify(pastDeadline));
    check(
      "past deadline -> REJECT/INVALID_TASK",
      pd.json && pd.json.decision === "REJECT" && pd.json.reason_code === "INVALID_TASK",
      JSON.stringify(pd.json),
    );
    const wrongType = await post(JSON.stringify({ type: "agent-games.unknown.v1" }));
    check("unknown envelope type -> 400", wrongType.status === 400, `got ${wrongType.status}`);
    const garbage = await post("{not json", {});
    check("unparseable JSON -> 400", garbage.status === 400, `got ${garbage.status}`);
  }

  console.log("== Audit log ==");
  {
    const logPath = process.env.AUDIT_LOG_PATH;
    const lines = fs.readFileSync(logPath, "utf8").trim().split("\n").filter(Boolean);
    check("audit log has one line per answered task", lines.length >= 10, `${lines.length} lines`);
    const first = JSON.parse(lines[0]);
    check(
      "audit entry carries task_id + salt + decision",
      typeof first.task_id === "string" && typeof first.salt === "string" && typeof first.decision === "string",
      JSON.stringify(first).slice(0, 200),
    );
    const mode = (fs.statSync(logPath).mode & 0o777).toString(8);
    check("audit log file mode is 600", mode === "600", `mode ${mode}`);
  }

  console.log("\n== Proof-generation timing (round-trip per task, incl. HTTP) ==");
  const times = proveTimings.map((t) => t.ms);
  for (const t of proveTimings) console.log(`  ${t.label}: ${t.ms}ms`);
  const min = Math.min(...times);
  const max = Math.max(...times);
  const mean = Math.round(times.reduce((a, b) => a + b, 0) / times.length);
  console.log(`  min ${min}ms, max ${max}ms, mean ${mean}ms over ${times.length} proving tasks`);
  check("slowest task round-trip under the 10s serverless budget", max < 10000, `${max}ms`);

  server.close();
  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) console.log("failures:", failures.join(", "));
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error("harness crashed:", err);
  process.exit(1);
});
