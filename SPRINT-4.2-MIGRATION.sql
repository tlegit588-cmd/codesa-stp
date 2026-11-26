-- CODEYSA-STP Marketplace Sprint 4.2
-- Run this once in Cloudflare D1 database: codesa-marketplace
CREATE TABLE IF NOT EXISTS rfqs (
 id TEXT PRIMARY KEY,
 product TEXT NOT NULL,
 quantity TEXT NOT NULL DEFAULT '',
 destination TEXT NOT NULL,
 requirements TEXT NOT NULL DEFAULT '',
 buyer_name TEXT NOT NULL,
 buyer_contact TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','in_review','contacted','quoted','closed')),
 admin_note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_rfqs_status_created ON rfqs(status,created_at);
