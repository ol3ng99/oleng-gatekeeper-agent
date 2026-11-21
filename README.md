# Proof Gatekeeper agent — @oleng

Live agent for the zkVerify Agent Games, Season 01, Proof Gatekeeper track.
Tournament ends **2026-11-21**; judging 2026-11-22–30.

Account: @oleng (competitionUserId `b4643f35-ee9b-44f8-9ee6-bba079ce5b1c`),
registered 2026-11-15. See `../REPORT.md` for the registration + first-proof
record. This folder is the deployable agent project (self-contained:
circuits + code + tests).

## What it does

Public HTTPS endpoint that receives signed task envelopes from the platform,
decides APPROVE/REJECT with deterministic, fail-closed policy code, generates
a Groth16 proof locally with snarkjs + the official gatekeeper circuit,
optionally submits the proof to zkVerify via Kurier, and returns a signed
response — all well inside the 60s task deadline.

## Files

| File | Purpose |
| --- | --- |
| `core.js` | The whole agent in one file: config, HMAC, field mapping, salt, decision policy, prover (lazy snarkjs), Kurier client, seen store, audit log, request handler. No web framework; only dependency is snarkjs. |
| `server.js` | Standalone Node HTTP server adapter (`POST /agent`, `GET /agent` + `/health`). |
| `api/agent.js` | Vercel serverless adapter → `https://<project>.vercel.app/api/agent`. |
| `netlify/functions/agent.js` | Netlify Functions adapter → `https://<site>.netlify.app/.netlify/functions/agent`. |
| `netlify.toml` | Netlify config: bundles `circuits/**`, function timeout 26s. |
| `vercel.json` | Includes `circuits/**` in the `api/agent.js` function bundle (`includeFiles`) — required, because Node File Trace cannot trace the dynamically-built wasm/zkey paths. |
| `.vercelignore` | Keeps `test/`, `data/`, `node_modules/` out of the deployment (repo files are otherwise served as static assets). |
| `package.json` | `snarkjs ^0.7.6`, `npm start`, `npm test`. |
| `circuits/` | Official artifacts: `gatekeeper.wasm` (sha256 `be00aefe…2764f`), `gatekeeper_final.zkey` (`adfe95a4…f80d`), `verification_key.json` (exported from the zkey — the site does not serve it). |
| `test/harness.js` | Automated test suite (145 checks, see below). |
| `.env.example` / `.gitignore` | Env template; secrets + `data/` never committed. |

## Protocol (from https://agentgames.zkverify.io/build)

- Task envelope: `agent-games.proof-gatekeeper.v1`, `task_id` like `gk_8d31_…`,
  `input` with `registered_vk`, `proof_vk`, `minimum`, `public_balance`,
  `expiry_block`, `current_block`, `recipient`, `condition_recipient`,
  `amount`, `max_transfer`, `proof_tx`.
- Response: `{ decision, reason_code, proof, public_signals, proof_tx }`
  (proof omitted only for PROOF_REUSED), signed with
  `x-agent-games-signature` (HMAC-SHA256, lowercase hex) over the raw body.
- Inbound HMAC verified over the RAW body before parsing; hex or base64
  accepted (optional `sha256=` prefix), constant-time compare.
- Preflight: `{ type: "agent-games.preflight.v1", ... }` →
  `{ ok: true, protocolVersion: "v1" }`, signed. **The platform times out
  preflight after 10s** (from the dashboard's own error text) and rejects
  responses over 16 KB — the preflight path here never touches snarkjs.
- Reason codes (platform trap taxonomy): `VALID_CONDITION`,
  `VK_SUBSTITUTION`, `PROOF_REUSED`, `THRESHOLD_MISMATCH`,
  `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`, `AMOUNT_OVERFLOW`;
  `INVALID_TASK` is defensive only (malformed envelope / past deadline).
- Decision checks (order): VK match → proof_tx not reused → balance ≥
  minimum → current_block < expiry_block → recipient match → amount ≤
  max_transfer. Boundary semantics mirror the circuit exactly
  (`>=`, `<=`, `<`) — verified by boundary tests below.
- Salt: deterministic per task, `HMAC-SHA256(secret, "gatekeeper-salt:" +
  task_id) mod p` — fresh per task, secret-bound, reproducible, so a
  redelivered task regenerates identical proof inputs. Salt + task_id are
  also appended to the audit log (`data/audit.jsonl`, mode 600).
- Idempotency: responses are cached per task_id; a redelivery returns the
  cached response instead of being misread as PROOF_REUSED.
- Seen store: proof_tx references are recorded after each successful
  evaluation (in-memory + JSON file, atomic write). On serverless the file
  lives in `/tmp` and may vanish on cold start — PROOF_REUSED detection is
  best-effort there.
- Kurier submission is optional and bounded (default 15s poll budget,
  capped by the 50s soft task deadline). It returns as soon as a txHash
  exists (Submitted status); finalization continues server-side. Without a
  key, `proof_tx` echoes the task's input reference.

## Open questions — resolved (with evidence) / flagged

The official /build spec does not pin these two mappings. Both follow the
published open-source reference implementation (andruu21/proof-gatekeeper-agent,
live on Vercel, preflight "Healthy" and 4/4 practice decisions with
platform-verified proofs on 2026-11-15):

1. **String `task_id` → numeric circuit `taskId`:** `SHA-256(task_id) mod p`
   (free-form strings are hashed into the field; hex/decimal values are
   parsed directly). ASSUMPTION — not pinned in the spec, but the reference
   implementation's platform-verified practice proofs are the evidence.
2. **32-byte vk hash → field element:** `BigInt(hex) mod p`. Same status:
   assumption with the same evidence. (Our own local proof used the same
   reduction and verifies against the circuit VK.)

If the platform rejects proofs in practice with a taskId/vk mismatch, these
two mappings are the first suspects.

## Test results (2026-11-15, `npm test`)

**145 passed, 0 failed.** Coverage: HMAC unit (7), preflight (6), health
(2), valid approve (11, proof verified locally against the circuit VK),
idempotent redelivery (2), all six traps + reuse source (each: decision,
reason, signature, proof verified where required), boundary semantics (3:
balance == minimum, amount == max, current == expiry − 1 — all APPROVE),
fail-closed (6: bad/missing HMAC → 401, malformed input, past deadline,
unknown type, unparseable JSON), audit log (3, file mode 600).

## Timing (measured on this VM)

- Pure `snarkjs.groth16.fullProve`: **~0.5s steady-state**
  (1st call 1.54s incl. first snarkjs/wasm load, then 0.59s, 0.49s).
- Full task round-trip (HTTP + prove + response): 411–1,443ms across 11
  proving tasks (mean 539ms); slowest was the first call (cold snarkjs).
- Preflight: 29ms. PROOF_REUSED (no proof): 5ms.
- Verdict: comfortably inside the 10s serverless budget AND the 60s task
  deadline, with ~9s of margin even on a cold start. Kurier polling is
  separately bounded (15s default) and never blocks the answer.
- Note: `fullProve` leaves the Node event loop alive after proving, so
  one-shot scripts must call `process.exit()` explicitly. Irrelevant for
  the server and serverless adapters (long-running / runtime-managed).

## HMAC secret — status: BLOCKED until an agent is registered

Rotation needs a registered agent: the dashboard action is
`rotateAgentSecret(agentId)` (server action id
`401d2a0d4da0b58a3ad2f76340f07faffe712d96f6`), and no agent exists yet
(0/3 slots used). Creating an agent requires a **public GitHub repo URL**
on a personal account (client validation: name ≥ 2 chars, ≥ 1 event,
repoUrl ≥ 5 chars; the endpoint URL itself is optional at creation).
No GitHub account/repo exists for this project yet, and no accounts were
created in this task.

Exact steps once a repo exists:
1. Dashboard → My Agents → Register agent: name (e.g. `oleng-gatekeeper`),
   select `Proof Gatekeeper`, paste the public repo URL, leave the endpoint
   empty for now → Register. **The HMAC secret is returned in the creation
   response and shown once — copy it immediately** into
   `AGENT_GAMES_HMAC_SECRET` (locally: `../.hmac_secret`, mode 600).
2. After deploying (below): Edit agent → set the endpoint URL → Save.
   Saving runs a signed preflight check against the URL (10s window).
3. To rotate later: Edit agent → "Rotate secret" (two-click confirm) →
   the new value is shown once; update the env var and restart/redeploy.

Server actions (same raw-JSON + `Next-Action` header pattern as the
account `registerAction`, for programmatic use later):
- `addAgentAction`: `406c653ffdf23ce1306a90d56bab9777bd095b4999`
- `rotateAgentSecret`: `401d2a0d4da0b58a3ad2f76340f07faffe712d96f6`
- `updateAgentEndpoint`: `60034c90cfac0d0a2c276e06558fcc69411ada008e`
- `preflightAgent`: `4004a8c359b186f7c18dcf3670b6660e389580c550`

## Kurier API key — how to obtain (not obtained; optional)

1. Go to https://kurier.xyz → Sign up (goes to `/login`; the page is a
   login/signup app). Create a **free** account with email + password.
   No wallet, no KYC mentioned anywhere in the docs.
2. In the dashboard, generate a **mainnet** API key.
3. Set it as `KURIER_API_KEY` in the hosting env vars (and keep the base
   URL `https://api.kurier.xyz/api/v1`).
4. No `register-vk` call is needed: the gatekeeper vk_hash
   (`0x6b79c6…77b0`) is already registered on mainnet, so submissions use
   `vkRegistered: true`.
5. Reference: https://docs.zkverify.io/overview/getting-started/kurier,
   Swagger at https://api.kurier.xyz/docs. Measured live 2026-11-15 by the
   reference implementation: txHash at ~4s, Finalized at ~27s.
6. Testnet alternative: https://api-testnet.kurier.xyz/api/v1 (separate key).
7. **The agent competes fine without a key** — it still returns the local
   proof + public_signals; only the on-chain `proof_tx` pointer is missing
   (the input reference is echoed instead).

## Hosting — recommendation: Vercel Hobby

| Option | Verdict |
| --- | --- |
| **Vercel Hobby (RECOMMENDED)** | Free. Function max duration **300s** (Fluid compute, current — the old 10s/60s figures are legacy pre-April-2025). 1M invocations, 100GB transfer, 4 CPU-hours/month. Proven by the reference implementation (live endpoint, preflight healthy). Cold start ~3s observed in the wild — inside the 10s preflight window, and our preflight path never loads snarkjs. Deploy via Git import (needs a GitHub account — already needed for the agent registration) or the Vercel CLI. Env vars in the dashboard. Caveats: Hobby is non-commercial personal use only (a competition entry fits); hitting a quota pauses the project until the next cycle (our usage is tiny: ~8 rounds/day). |
| Netlify Functions | Works, but weaker: **drag-and-drop does NOT deploy functions** (confirmed by Netlify staff) — needs Git-connected or CLI deploy. Timeout 10s default, **26s max on the free tier** (set in `netlify.toml`, already done). Credit model: 300 credits/month hard limit; at zero, **every site on the account pauses** — risky if shared with the user's project sites. Env vars need dashboard access. Use only if Vercel is unavailable. |
| cloudflared tunnel from this VM | Not recommended: trycloudflare.com URLs are random per run (no stable URL without a Cloudflare account + domain for a named tunnel), the VM restarts, and the tunnel dying mid-round scores −2 per task. Only as a last-resort test rig. |

### Deploy steps (Vercel, recommended)

1. Create a GitHub account (if none) and push this `gatekeeper/` folder as
   a public repo (e.g. `oleng-gatekeeper-agent`). This same repo URL is
   what the Agent Games agent registration requires.
2. Create a Vercel account (sign up with GitHub), Import Project → select
   the repo → Deploy (no build command needed; Node 18+).
3. Project → Settings → Environment Variables: set
   `AGENT_GAMES_HMAC_SECRET` (from the agent-creation step above) and
   optionally `KURIER_API_KEY` → Redeploy.
4. Verify: `curl https://<project>.vercel.app/api/agent` →
   `{"ok":true,"protocolVersion":"v1"}`.
5. On the Agent Games dashboard: Edit agent → endpoint
   `https://<project>.vercel.app/api/agent` → Save (runs preflight).
6. Run the platform's practice tasks first; check the dashboard marks the
   agent active before scored rounds.

### Deploy steps (Netlify, alternative)

1. Same GitHub repo as above. Netlify → Add new site → Import from Git →
   select the repo. (Or `npm i -g netlify-cli`, `netlify login`,
   `netlify deploy --prod --dir=. --functions=netlify/functions` from this
   folder — needs a `netlify.toml`, already included.)
2. Site settings → Environment variables: `AGENT_GAMES_HMAC_SECRET`,
   optional `KURIER_API_KEY`.
3. Endpoint: `https://<site>.netlify.app/.netlify/functions/agent`.
4. Prefer a **separate Netlify account** from the project sites if
   possible, so a credit exhaustion cannot pause them.

## Run locally

```sh
npm install
AGENT_GAMES_HMAC_SECRET=<secret from dashboard> npm start   # :8787
npm test                                                      # 145 checks
```

## Security notes

- Secrets only via env vars; never in code, logs, or prompts.
- The audit log contains per-task salts — mode 600, gitignored, never
  published. The seen-store JSON contains only public references.
- Fail closed everywhere: bad signature → 401; any uncertainty → REJECT.
- No funds, no wallet keys, no on-chain transactions in this agent. The
  registration wallet (`../.wallet_key`) is a throwaway used only for the
  SIWE sign-in, never for signing transactions.
