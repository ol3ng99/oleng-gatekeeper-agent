/**
 * Vercel serverless adapter for the Proof Gatekeeper agent.
 *
 * Deploy this file at api/agent.js in the project root; the endpoint is
 * https://<project>.vercel.app/api/agent — register that full path on the
 * Agent Games dashboard (NOT the root domain).
 *
 * The handler instance is created once per warm function instance, so the
 * in-memory seen-set survives across invocations on the same instance.
 * snarkjs is loaded lazily by the core, so preflight stays fast on cold
 * start. Set AGENT_GAMES_HMAC_SECRET (and optionally KURIER_API_KEY) in the
 * Vercel dashboard: Project -> Settings -> Environment Variables.
 */

"use strict";

const { loadConfig, AgentHandler, SeenStore, SIGNATURE_HEADER } = require("../core");

let handler = null;

function getHandler() {
  if (!handler) {
    const cfg = loadConfig();
    handler = new AgentHandler(cfg, new SeenStore(cfg.seenStorePath));
  }
  return handler;
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > 1_048_576) {
        reject(new Error("payload_too_large"));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

module.exports = async (req, res) => {
  const h = getHandler();

  if (req.method === "GET") {
    const r = h.health();
    res.status(r.status).json(JSON.parse(r.body));
    return;
  }

  if (req.method !== "POST") {
    res.status(404).json({ error: "not_found" });
    return;
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch {
    res.status(413).json({ error: "payload_too_large" });
    return;
  }

  const signature = req.headers[SIGNATURE_HEADER];
  const result = await h.handlePost(rawBody, Array.isArray(signature) ? signature[0] : signature);
  res.setHeader("content-type", "application/json");
  if (result.signature) res.setHeader(SIGNATURE_HEADER, result.signature);
  res.status(result.status).send(result.body);
};
