import { Hono } from "hono";
import { z } from "zod";

type RateLimit = { limit: (opts: { key: string }) => Promise<{ success: boolean }> };

interface Env {
  DB: D1Database;
  NONCES: KVNamespace;
  AE: AnalyticsEngineDataset;
  FREE_RL: RateLimit;
  PAID_RL: RateLimit;
  NODE_BROKER: DurableObjectNamespace;

  API_KEY_PEPPER: string;
  NODE_SHARED_SECRET: string;
  INTERNAL_ADMIN_TOKEN: string;
}

type AuthCtx = { userId: string; apiKeyId: string; plan: "free" | "paid" | "provider" };

const app = new Hono<{ Bindings: Env; Variables: { auth?: AuthCtx; requestId: string } }>();

/** ---------- helpers ---------- **/
const nowSec = () => Math.floor(Date.now() / 1000);
const uuid = () => crypto.randomUUID();

function jsonError(status: number, code: string, message: string) {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}

async function sha256Hex(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function decimalUsdToNano(usdPerUnit: string): bigint {
  const s = usdPerUnit.trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error(`Invalid decimal: ${usdPerUnit}`);
  const [w, fRaw = ""] = s.split(".");
  const f = (fRaw + "000000000").slice(0, 9);
  return BigInt(w) * 1_000_000_000n + BigInt(f);
}

// Shared HMAC signing format: ts.nonce.METHOD.PATH.sha256(body)
async function hmacSign(secret: string, msg: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
}

async function signToNode(env: Env, method: string, path: string, body: string, ts: number, nonce: string) {
  const bodyHash = await sha256Hex(body);
  const msg = `${ts}.${nonce}.${method.toUpperCase()}.${path}.${bodyHash}`;
  return hmacSign(env.NODE_SHARED_SECRET, msg);
}

async function verifyNodeSignature(env: Env, req: Request, bodyText: string): Promise<boolean> {
  const tsStr = req.headers.get("x-edge-timestamp") || "";
  const nonce = req.headers.get("x-edge-nonce") || "";
  const sig = req.headers.get("x-edge-signature") || "";

  const ts = Number(tsStr);
  if (!Number.isFinite(ts) || !nonce || !sig) return false;

  // time window (60s)
  const skew = Math.abs(nowSec() - ts);
  if (skew > 60) return false;

  // replay protection with KV (5 minutes)
  const nonceKey = `n:${nonce}`;
  const seen = await env.NONCES.get(nonceKey);
  if (seen) return false;
  await env.NONCES.put(nonceKey, "1", { expirationTtl: 300 });

  const bodyHash = await sha256Hex(bodyText);
  const url = new URL(req.url);
  const msg = `${ts}.${nonce}.${req.method.toUpperCase()}.${url.pathname}.${bodyHash}`;
  const expected = await hmacSign(env.NODE_SHARED_SECRET, msg);

  // constant-time-ish compare
  if (expected.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}

/** ---------- middleware: request id + basic headers ---------- **/
app.use("*", async (c, next) => {
  c.set("requestId", uuid());
  await next();
});

/** ---------- internal/admin auth ---------- **/
app.use("/internal/*", async (c, next) => {
  const token = c.req.header("authorization")?.replace(/^Bearer\s+/i, "")?.trim();
  if (!token || token !== c.env.INTERNAL_ADMIN_TOKEN) return jsonError(401, "unauthorized", "Bad admin token");
  await next();
});

/** ---------- public auth + fast rate limit ---------- **/
app.use("/v1/*", async (c, next) => {
  const authz = c.req.header("authorization") || "";
  const m = authz.match(/^Bearer\s+(.+)$/i);
  if (!m) return jsonError(401, "invalid_api_key", "Missing Bearer token");

  const rawKey = m[1].trim();
  const keyHash = await sha256Hex(c.env.API_KEY_PEPPER + rawKey);

  const row = await c.env.DB.prepare(
    `SELECT k.id as api_key_id, k.status as key_status, u.id as user_id, u.plan as plan
     FROM api_keys k JOIN users u ON u.id = k.user_id
     WHERE k.key_hash = ? LIMIT 1`
  ).bind(keyHash).first<{ api_key_id: string; key_status: string; user_id: string; plan: string }>();

  if (!row || row.key_status !== "active") return jsonError(401, "invalid_api_key", "Invalid API key");

  const plan = row.plan as AuthCtx["plan"];
  c.set("auth", { userId: row.user_id, apiKeyId: row.api_key_id, plan });

  const rl = plan === "paid" || plan === "provider" ? c.env.PAID_RL : c.env.FREE_RL;
  const { success } = await rl.limit({ key: `${row.api_key_id}:${new URL(c.req.url).pathname}` });
  if (!success) return jsonError(429, "rate_limit_exceeded", "Rate limit exceeded");

  await next();
});

// Internal route for nodes to connect via websocket (for job control, etc)
app.get("/internal/nodes/connect/:nodeId", async (c) => {
  const nodeId = c.req.param("nodeId");

  // Must be websocket upgrade
  const up = c.req.header("Upgrade");
  if (!up || up.toLowerCase() !== "websocket") {
    return new Response("Expected websocket", { status: 426 });
  }

  const stub = c.env.NODE_BROKER.getByName(nodeId);

  // Forward to DO /connect, but add x-radiance-node-id header (so DO knows which node name this is)
  const url = new URL(c.req.url);
  url.pathname = "/connect";

  const headers = new Headers(c.req.raw.headers);
  headers.set("x-radiance-node-id", nodeId);

  const forwarded = new Request(url.toString(), {
    method: "GET",
    headers
  });

  return stub.fetch(forwarded);
});

/** ---------- health ---------- **/
app.get("/health", (c) => c.json({ ok: true, service: "radiance-api" }));

/** ---------- OpenAI-ish models ---------- **/
app.get("/v1/models", async (c) => {
  const rows = await c.env.DB.prepare(`SELECT id, created_at FROM models ORDER BY created_at DESC`).all<any>();
  return c.json({
    object: "list",
    data: rows.results.map((r: any) => ({ id: r.id, object: "model", created: r.created_at, owned_by: "radiance" })),
  });
});

/** ---------- OpenRouter provider models (public) ---------- **/
app.get("/openrouter/models", async (c) => {
  const rows = await c.env.DB.prepare(`SELECT * FROM models ORDER BY created_at DESC`).all<any>();
  return c.json({
    data: rows.results.map((m: any) => ({
      id: m.id,
      hugging_face_id: "",
      name: m.name,
      created: m.created_at,
      input_modalities: ["text"],
      output_modalities: ["text"],
      quantization: m.quantization,
      context_length: m.context_length,
      max_output_length: m.max_output_length,
      pricing: {
        prompt: m.pricing_prompt,
        completion: m.pricing_completion,
        image: "0",
        request: "0",
        input_cache_read: "0",
      },
      supported_sampling_parameters: JSON.parse(m.supported_sampling_parameters),
      supported_features: JSON.parse(m.supported_features),
      description: m.description ?? "",
      openrouter: { slug: m.id },
      datacenters: [],
    })),
  });
});

/** ---------- internal: node register + heartbeat ---------- **/
const RegisterNode = z.object({ id: z.string(), base_url: z.string() });
app.post("/internal/nodes/register", async (c) => {
  const payload = RegisterNode.parse(await c.req.json());
  await c.env.DB.prepare(
    `INSERT INTO nodes (id, base_url, status, last_seen) VALUES (?, ?, 'healthy', ?)
     ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url, status='healthy', last_seen=excluded.last_seen`
  ).bind(payload.id, payload.base_url, nowSec()).run();
  return c.json({ ok: true });
});

const Heartbeat = z.object({ id: z.string(), status: z.enum(["healthy", "unhealthy", "draining"]) });
app.post("/internal/nodes/heartbeat", async (c) => {
  const payload = Heartbeat.parse(await c.req.json());
  await c.env.DB.prepare(`UPDATE nodes SET status=?, last_seen=? WHERE id=?`)
    .bind(payload.status, nowSec(), payload.id).run();
  return c.json({ ok: true });
});

/** ---------- proxy: chat/completions ---------- **/
const ProxyReqSchema = z.object({ model: z.string(), stream: z.boolean().optional() }).passthrough();

async function pickNodeForModel(env: Env, modelId: string) {
  const cutoff = nowSec() - 120;
  return env.DB.prepare(
    `SELECT n.id as node_id, n.base_url as base_url
     FROM nodes n JOIN node_models nm ON nm.node_id = n.id
     WHERE nm.model_id=? AND n.status='healthy' AND n.last_seen > ?
     ORDER BY RANDOM() LIMIT 1`
  ).bind(modelId, cutoff).first<{ node_id: string; base_url: string }>();
}

async function prepaidGate(env: Env, auth: AuthCtx) {
  if (auth.plan === "provider") return true; // important for OpenRouter-style uptime handling
  const wallet = await env.DB.prepare(`SELECT balance_nano_usd FROM wallets WHERE user_id=? LIMIT 1`)
    .bind(auth.userId).first<{ balance_nano_usd: number }>();
  if (!wallet) return false;
  return wallet.balance_nano_usd > -1_000_000_000; // allow up to -$1 drift
}

async function proxyToNode(c: any, path: string) {
  const env = c.env as Env;
  const auth = c.get("auth") as AuthCtx;
  const requestId = c.get("requestId") as string;

  let body: any;
  try {
    body = ProxyReqSchema.parse(await c.req.json());
  } catch {
    return jsonError(400, "invalid_request_error", "Invalid JSON or missing required fields");
  }

  // NOTE: Cloudflare enforces request body limits by plan; oversized payloads return 413. :contentReference[oaicite:7]{index=7}
  const modelId = body.model;

  const model = await env.DB.prepare(`SELECT id FROM models WHERE id=? LIMIT 1`).bind(modelId).first();
  if (!model) return jsonError(404, "model_not_found", `Unknown model: ${modelId}`);

  const okFunds = await prepaidGate(env, auth);
  if (!okFunds) return jsonError(402, "payment_required", "No wallet or insufficient balance");

  const node = await pickNodeForModel(env, modelId);
  if (!node) return jsonError(429, "overloaded", "No capacity available for this model");

  const jobId = uuid();
  await env.DB.prepare(
    `INSERT INTO jobs (id, user_id, api_key_id, model_id, node_id, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'running', ?)`
  ).bind(jobId, auth.userId, auth.apiKeyId, modelId, node.node_id, nowSec()).run();

  const jsonBody = JSON.stringify(body);
  const ts = nowSec();
  const nonce = uuid();
  const sig = await signToNode(env, "POST", path, jsonBody, ts, nonce);

  const upstream = await fetch(new URL(path, node.base_url), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-radiance-job-id": jobId,
      "x-radiance-request-id": requestId,

      "x-edge-timestamp": String(ts),
      "x-edge-nonce": nonce,
      "x-edge-signature": sig
    },
    body: jsonBody
  });

  const headers = new Headers(upstream.headers);
  headers.set("x-radiance-job-id", jobId);
  headers.set("x-radiance-node-id", node.node_id);
  headers.set("x-request-id", requestId);
  headers.set("cache-control", "no-store");
  headers.delete("content-length");

  // streaming pass-through (don’t buffer)
  return new Response(upstream.body, { status: upstream.status, headers });
}

app.post("/v1/chat/completions", (c) => proxyToNode(c, "/v1/chat/completions"));
app.post("/v1/completions", (c) => proxyToNode(c, "/v1/completions"));

/** ---------- internal: usage report (billing + metrics) ---------- **/
const UsageReportSchema = z.object({
  job_id: z.string(),
  user_id: z.string(),
  api_key_id: z.string(),
  model_id: z.string(),
  status: z.enum(["succeeded", "failed", "cancelled"]),
  prompt_tokens: z.number().int().nonnegative(),
  completion_tokens: z.number().int().nonnegative(),
  ttft_ms: z.number().int().nonnegative().optional(),
  tokens_per_sec: z.number().nonnegative().optional(),
  error: z.string().nullable().optional()
});

app.post("/internal/usage-report", async (c) => {
  const bodyText = await c.req.text();
  const okSig = await verifyNodeSignature(c.env, c.req.raw, bodyText);
  if (!okSig) return jsonError(401, "unauthorized", "Bad node signature");

  const r = UsageReportSchema.parse(JSON.parse(bodyText));

  const m = await c.env.DB.prepare(
    `SELECT pricing_prompt, pricing_completion FROM models WHERE id=? LIMIT 1`
  ).bind(r.model_id).first<{ pricing_prompt: string; pricing_completion: string }>();
  if (!m) return jsonError(400, "invalid_request_error", "Unknown model_id");

  const promptNano = decimalUsdToNano(m.pricing_prompt);
  const completionNano = decimalUsdToNano(m.pricing_completion);
  const costNano = BigInt(r.prompt_tokens) * promptNano + BigInt(r.completion_tokens) * completionNano;

  const finishedAt = nowSec();

  await c.env.DB.batch([
    c.env.DB.prepare(
      `UPDATE jobs SET status=?, finished_at=?, prompt_tokens=?, completion_tokens=?, cost_nano_usd=?, error=? WHERE id=?`
    ).bind(r.status, finishedAt, r.prompt_tokens, r.completion_tokens, costNano.toString(), r.error ?? null, r.job_id),

    c.env.DB.prepare(
      `INSERT INTO usage_ledger (id, job_id, user_id, model_id, prompt_tokens, completion_tokens, cost_nano_usd, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(uuid(), r.job_id, r.user_id, r.model_id, r.prompt_tokens, r.completion_tokens, costNano.toString(), finishedAt),

    c.env.DB.prepare(
      `UPDATE wallets SET balance_nano_usd = balance_nano_usd - ?, updated_at=? WHERE user_id=?`
    ).bind(costNano.toString(), finishedAt, r.user_id)
  ]);

  // Observability datapoint (AE dataset auto-created on first write)
  c.env.AE.writeDataPoint({
    blobs: [r.user_id, r.model_id, r.status],
    doubles: [r.prompt_tokens, r.completion_tokens, Number(costNano) / 1e9, r.ttft_ms ?? 0, r.tokens_per_sec ?? 0],
    indexes: [r.user_id]
  });

  return c.json({ ok: true });
});

export default app;
