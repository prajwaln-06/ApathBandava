-- 001_init.sql — SRS 6.1 schema (binding), plus additive indexes and the verdict cache (FR-29).
-- Idempotent: applied by the analyzer at startup.
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE TABLE IF NOT EXISTS registry_entities (
  id SERIAL PRIMARY KEY, name TEXT NOT NULL, aliases TEXT[], regulator TEXT,
  kind TEXT CHECK (kind IN ('bank','insurer','nbfc','wallet','govt')),
  domains TEXT[], legacy_domains TEXT[], sms_headers TEXT[], call_prefixes TEXT[],
  support_numbers TEXT[], official_upi_handles TEXT[], app_packages TEXT[],
  last_verified DATE, status TEXT DEFAULT 'approved');
CREATE TABLE IF NOT EXISTS registry_policies (
  id SERIAL PRIMARY KEY, entity_id INT REFERENCES registry_entities(id),
  rule_code TEXT, rule_text TEXT, quote TEXT, source_url TEXT, last_verified DATE);
CREATE TABLE IF NOT EXISTS playbooks (
  id SERIAL PRIMARY KEY, code TEXT UNIQUE, name TEXT, description TEXT,
  indicators TEXT[], example TEXT, advice TEXT, embedding VECTOR(1024));
CREATE TABLE IF NOT EXISTS checks (
  id UUID PRIMARY KEY, sender_hash TEXT, created_at TIMESTAMPTZ DEFAULT now(),
  input_type TEXT, raw_text TEXT, findings JSONB, verdict TEXT, score INT,
  reply TEXT, latency_ms INT);
CREATE TABLE IF NOT EXISTS artifacts (
  id SERIAL PRIMARY KEY, check_id UUID REFERENCES checks(id), kind TEXT,
  value TEXT, value_hash TEXT, verdict TEXT);
CREATE TABLE IF NOT EXISTS campaigns (
  id SERIAL PRIMARY KEY, value_hash TEXT UNIQUE, kind TEXT, first_seen TIMESTAMPTZ,
  sender_count INT, playbook_code TEXT, status TEXT DEFAULT 'open');
CREATE TABLE IF NOT EXISTS registry_review_queue (
  id SERIAL PRIMARY KEY, entity_id INT, field TEXT, proposed JSONB,
  quote TEXT, source_url TEXT, status TEXT DEFAULT 'pending');

-- Additive (not in SRS 6.1, required by FR-29 / seed loader / NFR-10)
CREATE TABLE IF NOT EXISTS verdict_cache (
  cache_key TEXT PRIMARY KEY, result JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE UNIQUE INDEX IF NOT EXISTS registry_entities_name_uq ON registry_entities (name);
CREATE INDEX IF NOT EXISTS artifacts_value_hash_idx ON artifacts (value_hash);
CREATE INDEX IF NOT EXISTS checks_created_at_idx ON checks (created_at);
ALTER TABLE checks ADD COLUMN IF NOT EXISTS trace_id TEXT;
ALTER TABLE registry_entities ADD COLUMN IF NOT EXISTS sources TEXT[];
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS advice_hi TEXT;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS alerted BOOLEAN DEFAULT false;
ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS sample_value TEXT;
