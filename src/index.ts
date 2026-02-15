import { Hono } from "hono";
import { z } from "zod";

// Environment bindings for Cloudflare Worker
interface Env {
  DB: D1Database;
  NONCES: KVNamespace;
  AE: AnalyticsEngineDataset;
  FREE_RL: { limit(opts: { key: string }): Promise<{ success: boolean }> };
  PAID_RL: { limit(opts: { key: string }): Promise<{ success: boolean }> };
  API_KEY_PEPPER: string;
  NODE_SHARED_SECRET: string;
  INTERNAL_ADMIN_TOKEN: string;
  NODE_BROKER: DurableObjectNamespace; // Durable Object for node routing
}

type AuthCtx = {
  userId: string;
  apiKeyId: string;
  plan: "free" | "paid" | "provider";
};

const app = new Hono<{ Bindings: Env; Variables: { auth?: AuthCtx; requestId: string } }>();

/** Utility helpers */
const nowSec = () => Math.floor(Date.now() / 1000);
const uuid = () => crypto.randomUUID();

function jsonError(status: number, code: string, message: string) {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" }
  });
}

async function sha256Hex(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// HMAC signing function for Worker → node requests
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

/** Middleware: assign a request ID */
app.use("*", async (c, next) => {
  c.set("requestId", uuid());
  await next();
});

/** Middleware: internal admin auth for /internal routes */
app.use("/internal/*", async (c, next) => {
  const token = c.req.header("authorization")?.replace(/^Bearer\s+/i, "").trim();
  if (!token || token !== c.env.INTERNAL_ADMIN_TOKEN) {
    return jsonError(401, "unauthorized", "Bad admin token");
  }
  await next();
});

/** Middleware: public auth and rate limiting for /v1 routes */
app.use("/v1/*", async (c, next) => {
  const authz = c.req.header("authorization") || "";
  const m = authz.match(/^Bearer\s+(.+)$/i);
  if (!m) return jsonError(401, "invalid_api_key", "Missing Bearer token");

  const rawKey = m[1].trim();
  const keyHash = await sha256Hex(c.env.API_KEY_PEPPER + rawKey);

  // find user and key
  const row = await c.env.DB.prepare(
    `SELECT k.id AS api_key_id, k.status AS key_status, u.id AS user_id, u.plan AS plan
       FROM api_keys k
       JOIN users u ON u.id = k.user_id
       WHERE k.key_hash = ? LIMIT 1`
  ).bind(keyHash).first<{ api_key_id: string; key_status: string; user_id: string; plan: string }>();

  if (!row || row.key_status !== "active") return jsonError(401, "invalid_api_key", "Invalid API key");

  const plan = row.plan as AuthCtx["plan"];
  c.set("auth", { userId: row.user_id, apiKeyId: row.api_key_id, plan });

  // Rate limiting: free vs paid vs provider
  const limiter = plan === "paid" || plan === "provider" ? c.env.PAID_RL : c.env.FREE_RL;
  const { success } = await limiter.limit({ key: `${row.api_key_id}:${new URL(c.req.url).pathname}` });
  if (!success) return jsonError(429, "rate_limit_exceeded", "Rate limit exceeded");

  await next();
});

/** Health endpoint */
app.get("/health", (c) => c.json({ ok: true, service: "radiance-api" }));

/** Models list (minimal) */
app.get("/v1/models", async (c) => {
  const models = await c.env.DB.prepare(`SELECT id, created_at FROM models ORDER BY created_at DESC`).all<any>();
  return c.json({
    object: "list",
    data: models.results.map((m: any) => ({ id: m.id, object: "model", created: m.created_at, owned_by: "radiance" }))
  });
});

/** OpenRouter provider models list (rich) */
app.get("/openrouter/models", async (c) => {
  const models = await c.env.DB.prepare(`SELECT * FROM models ORDER BY created_at DESC`).all<any>();
  return c.json({
    data: models.results.map((m: any) => ({
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
      datacenters: []
    }))
  });
});

// ---------- Durable Object invocation helper ----------
async function invokeViaDO(c: any, nodeId: string, path: string, body: any, headers: Record<string, string>) {
  // get stub for node's durable object
  const stub = c.env.NODE_BROKER.getByName(nodeId);
  const payload = {
    __path: path,
    __headers: headers,
    __body: body,
    stream: Boolean(body?.stream)
  };
  const resp = await stub.fetch("https://do/invoke", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-radiance-internal-token": c.env.INTERNAL_ADMIN_TOKEN
    },
    body: JSON.stringify(payload)
  });
  return resp;
}

// Utility to pick a healthy node for a given model
async function pickNode(env: Env, modelId: string) {
  const cutoff = nowSec() - 120;
  return await env.DB.prepare(
    `SELECT n.id AS node_id FROM nodes n
       JOIN node_models nm ON nm.node_id = n.id
       WHERE nm.model_id = ? AND n.status = 'healthy' AND n.last_seen > ?
       ORDER BY RANDOM() LIMIT 1`
  ).bind(modelId, cutoff).first<{ node_id: string }>();
}

// Check wallet for prepaid plan (skip for provider)
async function prepaidCheck(env: Env, auth: AuthCtx) {
  if (auth.plan === "provider") return true;
  const wallet = await env.DB.prepare(`SELECT balance_nano_usd FROM wallets WHERE user_id = ? LIMIT 1`).bind(auth.userId).first<{ balance_nano_usd: number }>();
  return wallet ? wallet.balance_nano_usd > -1_000_000_000 : false;
}

// ---------- Core proxy route (chat completions & completions) ----------
const ChatReqSchema = z.object({ model: z.string(), stream: z.boolean().optional() }).passthrough();

async function handleCompletion(c: any, path: string) {
  const auth = c.get("auth") as AuthCtx;
  const requestId = c.get("requestId");

  let body: any;
  try {
    body = ChatReqSchema.parse(await c.req.json());
  } catch {
    return jsonError(400, "invalid_request_error", "Invalid JSON body or missing model");
  }

  const modelId = body.model;
  // Ensure model exists
  const model = await c.env.DB.prepare(`SELECT id FROM models WHERE id = ? LIMIT 1`).bind(modelId).first();
  if (!model) return jsonError(404, "model_not_found", `Unknown model: ${modelId}`);

  // Prepaid check
  if (!(await prepaidCheck(c.env, auth))) return jsonError(402, "payment_required", "Insufficient balance");

  // Pick a healthy node serving this model
  const node = await pickNode(c.env, modelId);
  if (!node) return jsonError(429, "overloaded", "No capacity available for this model");

  const jobId = uuid();
  // Insert a running job record
  await c.env.DB.prepare(
    `INSERT INTO jobs (id, user_id, api_key_id, model_id, node_id, status, created_at)
       VALUES (?, ?, ?, ?, ?, 'running', ?)`
  ).bind(jobId, auth.userId, auth.apiKeyId, modelId, node.node_id, nowSec()).run();

  // Create headers to forward to DO/node
  const forwardHeaders: Record<string, string> = {
    "x-radiance-job-id": jobId,
    "x-radiance-request-id": requestId,
    "x-radiance-user-id": auth.userId,
    "x-radiance-api-key-id": auth.apiKeyId,
  };

  // Invoke via Durable Object
  const upstream = await invokeViaDO(c, node.node_id, path, body, forwardHeaders);

  // Pass through the upstream response body and status
  const headers = new Headers(upstream.headers);
  headers.set("x-radiance-job-id", jobId);
  headers.set("x-radiance-node-id", node.node_id);
  headers.set("x-request-id", requestId);
  headers.delete("content-length");
  return new Response(upstream.body, { status: upstream.status, headers });
}

// Mount completion routes
app.post("/v1/chat/completions", (c) => handleCompletion(c, "/v1/chat/completions"));
app.post("/v1/completions", (c) => handleCompletion(c, "/v1/completions"));

/** Internal endpoint for usage report from node */
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
  error: z.string().nullable().optional(),
});

function decimalToNano(str: string): bigint {
  // Convert decimal USD string to nano USD (1e-9)
  const [whole, fracRaw = ""] = str.trim().split(".");
  const frac = (fracRaw + "000000000").slice(0, 9);
  return BigInt(whole) * 1_000_000_000n + BigInt(frac);
}

app.post("/internal/usage-report", async (c) => {
  // verify signature from node (request body and headers). Implementation omitted for brevity.
  const report = UsageReportSchema.parse(await c.req.json());

  // lookup pricing
  const pricing = await c.env.DB.prepare(
    `SELECT pricing_prompt, pricing_completion FROM models WHERE id = ? LIMIT 1`
  ).bind(report.model_id).first<{ pricing_prompt: string; pricing_completion: string }>();
  if (!pricing) return jsonError(400, "invalid_request_error", "Unknown model_id");

  const costNano =
    BigInt(report.prompt_tokens) * decimalToNano(pricing.pricing_prompt) +
    BigInt(report.completion_tokens) * decimalToNano(pricing.pricing_completion);

  const finishedAt = nowSec();

  // Update job record and ledger
  await c.env.DB.batch([
    c.env.DB.prepare(
      `UPDATE jobs SET status = ?, finished_at = ?, prompt_tokens = ?, completion_tokens = ?, cost_nano_usd = ?, error = ? WHERE id = ?`
    ).bind(report.status, finishedAt, report.prompt_tokens, report.completion_tokens, costNano.toString(), report.error ?? null, report.job_id),
    c.env.DB.prepare(
      `INSERT INTO usage_ledger (id, job_id, user_id, model_id, prompt_tokens, completion_tokens, cost_nano_usd, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(uuid(), report.job_id, report.user_id, report.model_id, report.prompt_tokens, report.completion_tokens, costNano.toString(), finishedAt),
    c.env.DB.prepare(
      `UPDATE wallets SET balance_nano_usd = balance_nano_usd - ?, updated_at = ? WHERE user_id = ?`
    ).bind(costNano.toString(), finishedAt, report.user_id),
  ]);

  // log to analytics
  c.env.AE.writeDataPoint({
    blobs: [report.user_id, report.model_id, report.status],
    doubles: [report.prompt_tokens, report.completion_tokens, Number(costNano) / 1e9, report.ttft_ms ?? 0, report.tokens_per_sec ?? 0],
    indexes: [report.user_id],
  });

  return c.json({ ok: true });
});

export default app;
