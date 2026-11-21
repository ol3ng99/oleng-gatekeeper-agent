/**
 * Netlify Functions adapter for the Proof Gatekeeper agent.
 *
 * Deploy via Git-connected site or the Netlify CLI (drag-and-drop does NOT
 * deploy functions). The endpoint is
 * https://<site>.netlify.app/.netlify/functions/agent — register that full
 * path on the Agent Games dashboard.
 *
 * Requires netlify.toml with:
 *   [functions]
 *     included_files = ["circuits/**"]
 * so the wasm/zkey are bundled with the function, and a per-function
 * timeout (max 26s on the free tier). Set AGENT_GAMES_HMAC_SECRET (and
 * optionally KURIER_API_KEY) in Site settings -> Environment variables.
 */

"use strict";

const { loadConfig, AgentHandler, SeenStore, SIGNATURE_HEADER } = require("../../core");

let handler = null;

function getHandler() {
  if (!handler) {
    const cfg = loadConfig();
    handler = new AgentHandler(cfg, new SeenStore(cfg.seenStorePath));
  }
  return handler;
}

exports.handler = async (event) => {
  const h = getHandler();

  if (event.httpMethod === "GET") {
    const r = h.health();
    return { statusCode: r.status, headers: { "content-type": "application/json" }, body: r.body };
  }

  if (event.httpMethod !== "POST") {
    return { statusCode: 404, headers: { "content-type": "application/json" }, body: JSON.stringify({ error: "not_found" }) };
  }

  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body || "", "base64")
    : Buffer.from(event.body || "", "utf8");

  const headers = {};
  for (const [k, v] of Object.entries(event.headers || {})) headers[k.toLowerCase()] = v;
  const result = await h.handlePost(rawBody, headers[SIGNATURE_HEADER]);

  const outHeaders = { "content-type": "application/json" };
  if (result.signature) outHeaders[SIGNATURE_HEADER] = result.signature;
  return { statusCode: result.status, headers: outHeaders, body: result.body };
};
