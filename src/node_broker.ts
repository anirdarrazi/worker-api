// src/node_broker.ts
import { DurableObjectState, DurableObject } from "cloudflare:workers";

export interface Env {
  DB: D1Database;
  NONCES: KVNamespace;
  NODE_SHARED_SECRET: string;
  INTERNAL_ADMIN_TOKEN: string; // used Worker->DO invoke only
}

// Message types sent from node to DO
type NodeHello = {
  type: "hello";
  v: 1;
  node_id: string;
  max_inflight: number;
  models: Array<{ model_id: string; max_inflight?: number }>;
};
type NodePing = {
  type: "ping";
  t: number;
  inflight: number;
  max_inflight?: number;
};
type NodeSse = { type: "sse"; rid: string; chunk: string };
type NodeDone = { type: "done"; rid: string };
type NodeResult = { type: "result"; rid: string; status: number; json: unknown };
type NodeError = {
  type: "error";
  rid: string;
  status: number;
  error: { code: string; message: string };
};
type NodeToDo = NodeHello | NodePing | NodeSse | NodeDone | NodeResult | NodeError;

// Messages sent from DO to node
type DoInvoke = {
  type: "invoke";
  rid: string;
  path: "/v1/chat/completions" | "/v1/completions";
  body: any;
  headers: Record<string, string>;
};
type DoCancel = { type: "cancel"; rid: string };
type DoToNode = DoInvoke | DoCancel;

type StreamSession = {
  rid: string;
  writer: WritableStreamDefaultWriter<Uint8Array>;
  encoder: TextEncoder;
  lastActivityMs: number;
  closed: boolean;
  done: Promise<void>;
  resolveDone: () => void;
};

type RpcSession = {
  rid: string;
  resolve: (v: { status: number; json: unknown }) => void;
  reject: (e: unknown) => void;
  timer: number;
};

const KEEPALIVE_MS = 10_000;
const IDLE_TIMEOUT_MS = 60_000;
const SEND_BP_LIMIT = 1_000_000;

function jsonError(status: number, code: string, message: string) {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" }
  });
}

function b64urlFromBytes(bytes: Uint8Array) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function hmacB64Url(secret: string, msg: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
  return b64urlFromBytes(new Uint8Array(sig));
}

async function sleep(ms: number) {
  await new Promise((r) => setTimeout(r, ms));
}

export class NodeBroker extends DurableObject<Env> {
  private nodeWs: WebSocket | null = null;
  private nodeId: string | null = null;
  private inflight = 0;
  private maxInflight = 1;
  private streams = new Map<string, StreamSession>();
  private rpcs = new Map<string, RpcSession>();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    // Restore hibernated websocket(s)
    const existing = this.ctx.getWebSockets("node");
    if (existing.length > 0) {
      this.nodeWs = existing[0];
      const att = this.nodeWs.deserializeAttachment?.() as any;
      if (att?.node_id) this.nodeId = att.node_id;
      if (att?.max_inflight) this.maxInflight = att.max_inflight;
    }
  }

  // ---- WebSocket events (hibernation API) ----
  async webSocketMessage(ws: WebSocket, message: ArrayBuffer | string) {
    if (ws !== this.nodeWs) return;
    const text = typeof message === "string" ? message : new TextDecoder().decode(new Uint8Array(message));
    let msg: NodeToDo;
    try {
      msg = JSON.parse(text);
    } catch {
      ws.close(1003, "bad json");
      return;
    }
    if (msg.type === "hello") {
      this.nodeId = msg.node_id;
      this.maxInflight = Math.max(1, msg.max_inflight || 1);
      ws.serializeAttachment?.({ node_id: this.nodeId, max_inflight: this.maxInflight });
      await this.upsertNode("healthy");
      await this.replaceNodeModels(msg.models);
      return;
    }
    if (msg.type === "ping") {
      this.inflight = msg.inflight;
      if (msg.max_inflight) this.maxInflight = Math.max(1, msg.max_inflight);
      await this.touchNode("healthy");
      return;
    }
    if (msg.type === "sse") {
      const s = this.streams.get(msg.rid);
      if (!s || s.closed) return;
      s.lastActivityMs = Date.now();
      await s.writer.write(s.encoder.encode(msg.chunk));
      return;
    }
    if (msg.type === "done") {
      const s = this.streams.get(msg.rid);
      if (s && !s.closed) await this.closeStream(s);
      this.clearRpcIfAny(msg.rid);
      return;
    }
    if (msg.type === "result") {
      const rpc = this.rpcs.get(msg.rid);
      if (!rpc) return;
      clearTimeout(rpc.timer);
      this.rpcs.delete(msg.rid);
      rpc.resolve({ status: msg.status, json: msg.json });
      return;
    }
    if (msg.type === "error") {
      const s = this.streams.get(msg.rid);
      if (s && !s.closed) {
        const payload = JSON.stringify({ error: msg.error });
        await s.writer.write(s.encoder.encode(`data: ${payload}\n\n`));
        await s.writer.write(s.encoder.encode(`data: [DONE]\n\n`));
        await this.closeStream(s);
      }
      const rpc = this.rpcs.get(msg.rid);
      if (rpc) {
        clearTimeout(rpc.timer);
        this.rpcs.delete(msg.rid);
        rpc.resolve({ status: msg.status, json: { error: msg.error } });
      }
      return;
    }
  }

  async webSocketClose(ws: WebSocket) {
    if (ws !== this.nodeWs) return;
    this.nodeWs = null;
    await this.touchNode("unhealthy");
    await this.failAllInFlight("node_disconnected", "Node disconnected");
  }

  async webSocketError(ws: WebSocket) {
    if (ws !== this.nodeWs) return;
    this.nodeWs = null;
    await this.touchNode("unhealthy");
    await this.failAllInFlight("node_socket_error", "Node socket error");
  }

  // ---- HTTP endpoints to this DO ----
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/connect") {
      return this.handleConnect(request);
    }
    if (url.pathname === "/invoke") {
      return this.handleInvoke(request);
    }
    if (url.pathname === "/cancel") {
      return this.handleCancel(request);
    }
    return new Response("Not found", { status: 404 });
  }

  private async handleConnect(request: Request): Promise<Response> {
    const up = request.headers.get("Upgrade");
    if (!up || up.toLowerCase() !== "websocket") {
      return new Response("Expected Upgrade: websocket", { status: 426 });
    }
    if (request.method !== "GET") {
      return new Response("Expected GET", { status: 400 });
    }
    const url = new URL(request.url);
    const nodeId = request.headers.get("x-radiance-node-id");
    if (!nodeId) return new Response("Missing node id", { status: 400 });
    const ts = url.searchParams.get("ts") || "";
    const nonce = url.searchParams.get("nonce") || "";
    const sig = url.searchParams.get("sig") || "";
    if (!ts || !nonce || !sig) return new Response("Missing auth params", { status: 401 });
    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum) || Math.abs(Math.floor(Date.now() / 1000) - tsNum) > 60) {
      return new Response("Stale timestamp", { status: 401 });
    }
    // Replay protection via KV
    const nk = `n:${nonce}`;
    if (await this.env.NONCES.get(nk)) return new Response("Replay", { status: 401 });
    await this.env.NONCES.put(nk, "1", { expirationTtl: 300 });
    const msg = `${ts}.${nonce}.CONNECT.${nodeId}`;
    const expected = await hmacB64Url(this.env.NODE_SHARED_SECRET, msg);
    if (expected !== sig) return new Response("Bad signature", { status: 401 });
    if (this.nodeId && this.nodeId !== nodeId) {
      return new Response("NodeId mismatch", { status: 409 });
    }
    this.nodeId = nodeId;
    // Accept hibernatable WebSocket
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    // Only keep one active connector; close previous if any
    if (this.nodeWs) {
      try {
        this.nodeWs.close(1012, "Replaced by new connection");
      } catch {}
    }
    this.ctx.acceptWebSocket(server, ["node"]);
    this.nodeWs = server;
    server.serializeAttachment?.({ node_id: nodeId, max_inflight: this.maxInflight });
    await this.upsertNode("healthy");
    return new Response(null, { status: 101, webSocket: client });
  }

  private async handleInvoke(request: Request): Promise<Response> {
    const token = request.headers.get("x-radiance-internal-token") || "";
    if (token !== this.env.INTERNAL_ADMIN_TOKEN) {
      return jsonError(401, "unauthorized", "Bad internal token");
    }
    if (!this.nodeWs || this.nodeWs.readyState !== 1) {
      return jsonError(429, "overloaded", "Node not connected");
    }
    if (this.inflight >= this.maxInflight) {
      return jsonError(429, "overloaded", "Node at capacity");
    }
    const body = await request.json<any>();
    const path = (body?.__path as string) || "/v1/chat/completions";
    const stream = Boolean(body?.stream);
    const headers = (body?.__headers as Record<string, string>) || {};
    const payload = body?.__body;
    // Use provided job id as rid if present; otherwise generate uuid
    const providedRid = headers["x-radiance-job-id"];
    const rid = providedRid ? providedRid : crypto.randomUUID();
    if (!stream) {
      const res = await this.invokeRpc(rid, path as any, payload, headers);
      return new Response(JSON.stringify(res.json), {
        status: res.status,
        headers: { "content-type": "application/json", "cache-control": "no-store" }
      });
    }
    // Streaming response to Worker (SSE)
    const ts = new TransformStream<Uint8Array, Uint8Array>();
    const writer = ts.writable.getWriter();
    const encoder = new TextEncoder();
    let resolveDone!: () => void;
    const done = new Promise<void>((r) => (resolveDone = r));
    const session: StreamSession = {
      rid,
      writer,
      encoder,
      lastActivityMs: Date.now(),
      closed: false,
      done,
      resolveDone,
    };
    this.streams.set(rid, session);
    this.ctx.waitUntil(this.keepAliveLoop(session));
    this.ctx.waitUntil(this.sendToNode({ type: "invoke", rid, path: path as any, body: payload, headers }));
    return new Response(ts.readable, {
      status: 200,
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store",
        "connection": "keep-alive"
      }
    });
  }

  private async handleCancel(request: Request): Promise<Response> {
    const token = request.headers.get("x-radiance-internal-token") || "";
    if (token !== this.env.INTERNAL_ADMIN_TOKEN) {
      return jsonError(401, "unauthorized", "Bad internal token");
    }
    const { rid } = await request.json<{ rid: string }>();
    await this.sendToNode({ type: "cancel", rid });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" }
    });
  }

  // ---- helpers ----
  private async sendToNode(msg: DoToNode) {
    if (!this.nodeWs || this.nodeWs.readyState !== 1) throw new Error("node not connected");
    const data = JSON.stringify(msg);
    while (this.nodeWs.bufferedAmount > SEND_BP_LIMIT) {
      await sleep(10);
    }
    this.nodeWs.send(data);
  }

  private async invokeRpc(
    rid: string,
    path: DoInvoke["path"],
    payload: any,
    headers: Record<string, string>
  ) {
    return await new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.rpcs.delete(rid);
        reject(new Error("node rpc timeout"));
      }, 30_000) as unknown as number;
      this.rpcs.set(rid, { rid, resolve, reject, timer });
      this.sendToNode({ type: "invoke", rid, path, body: payload, headers }).catch((e) => {
        clearTimeout(timer);
        this.rpcs.delete(rid);
        reject(e);
      });
    });
  }

  private async keepAliveLoop(s: StreamSession) {
    while (!s.closed) {
      await sleep(KEEPALIVE_MS);
      if (s.closed) return;
      if (Date.now() - s.lastActivityMs > IDLE_TIMEOUT_MS) {
        const payload = JSON.stringify({ error: { code: "timeout", message: "Node stalled mid-stream" } });
        await s.writer.write(s.encoder.encode(`data: ${payload}\n\n`));
        await s.writer.write(s.encoder.encode(`data: [DONE]\n\n`));
        await this.closeStream(s);
        return;
      }
      await s.writer.write(s.encoder.encode(":\n\n"));
    }
  }

  private async closeStream(s: StreamSession) {
    if (s.closed) return;
    s.closed = true;
    this.streams.delete(s.rid);
    try {
      await s.writer.close();
    } catch {}
    s.resolveDone();
  }

  private clearRpcIfAny(rid: string) {
    const rpc = this.rpcs.get(rid);
    if (!rpc) return;
    clearTimeout(rpc.timer);
    this.rpcs.delete(rid);
    rpc.resolve({ status: 499, json: { error: { code: "cancelled", message: "cancelled" } } });
  }

  private async failAllInFlight(code: string, message: string) {
    for (const s of [...this.streams.values()]) {
      if (s.closed) continue;
      const payload = JSON.stringify({ error: { code, message } });
      try {
        await s.writer.write(s.encoder.encode(`data: ${payload}\n\n`));
        await s.writer.write(s.encoder.encode(`data: [DONE]\n\n`));
      } catch {}
      await this.closeStream(s);
    }
    for (const rpc of [...this.rpcs.values()]) {
      clearTimeout(rpc.timer);
      this.rpcs.delete(rpc.rid);
      rpc.resolve({ status: 503, json: { error: { code, message } } });
    }
  }

  private async upsertNode(status: "healthy" | "unhealthy" | "draining") {
    if (!this.nodeId) return;
    const t = Math.floor(Date.now() / 1000);
    await this.env.DB.prepare(
      `INSERT INTO nodes (id, base_url, status, last_seen)
       VALUES (?, '', ?, ?)
       ON CONFLICT(id) DO UPDATE SET status=excluded.status, last_seen=excluded.last_seen`
    ).bind(this.nodeId, status, t).run();
  }
  private async touchNode(status: "healthy" | "unhealthy" | "draining") {
    if (!this.nodeId) return;
    const t = Math.floor(Date.now() / 1000);
    await this.env.DB.prepare(`UPDATE nodes SET status=?, last_seen=? WHERE id=?`)
      .bind(status, t, this.nodeId)
      .run();
  }
  private async replaceNodeModels(models: Array<{ model_id: string; max_inflight?: number }>) {
    if (!this.nodeId) return;
    await this.env.DB.prepare(`DELETE FROM node_models WHERE node_id=?`).bind(this.nodeId).run();
    const stmts = models.map((m) =>
      this.env.DB.prepare(
        `INSERT INTO node_models (node_id, model_id, max_concurrency) VALUES (?, ?, ?)`
      ).bind(this.nodeId!, m.model_id, Math.max(1, m.max_inflight ?? this.maxInflight))
    );
    if (stmts.length) await this.env.DB.batch(stmts);
  }
}