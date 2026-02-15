-- Migration number: 0001 	 2026-02-14T16:01:48.676Z
PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT,
  plan TEXT NOT NULL, -- free/paid/provider
  created_at INTEGER NOT NULL
);

CREATE TABLE api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  label TEXT,
  status TEXT NOT NULL, -- active/revoked
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE wallets (
  user_id TEXT PRIMARY KEY,
  balance_nano_usd INTEGER NOT NULL, -- nano-USD
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE models (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  created_at INTEGER NOT NULL,
  context_length INTEGER NOT NULL,
  max_output_length INTEGER NOT NULL,
  quantization TEXT NOT NULL,
  pricing_prompt TEXT NOT NULL,      -- USD/token decimal string
  pricing_completion TEXT NOT NULL,  -- USD/token decimal string
  supported_features TEXT NOT NULL,  -- JSON array string
  supported_sampling_parameters TEXT NOT NULL -- JSON array string
);

CREATE TABLE nodes (
  id TEXT PRIMARY KEY,
  base_url TEXT NOT NULL,
  status TEXT NOT NULL, -- healthy/unhealthy/draining
  last_seen INTEGER NOT NULL
);

CREATE TABLE node_models (
  node_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  max_concurrency INTEGER NOT NULL,
  PRIMARY KEY (node_id, model_id),
  FOREIGN KEY(node_id) REFERENCES nodes(id),
  FOREIGN KEY(model_id) REFERENCES models(id)
);

CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  api_key_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  node_id TEXT,
  status TEXT NOT NULL, -- running/succeeded/failed/cancelled
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  prompt_tokens INTEGER,
  completion_tokens INTEGER,
  cost_nano_usd INTEGER,
  error TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(api_key_id) REFERENCES api_keys(id)
);

CREATE TABLE usage_ledger (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  prompt_tokens INTEGER NOT NULL,
  completion_tokens INTEGER NOT NULL,
  cost_nano_usd INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
