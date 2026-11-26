-- CODEYSA-STP Marketplace Sprint 4.3
-- Run once in Cloudflare D1 database: codesa-marketplace
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY,
 reference TEXT NOT NULL UNIQUE,
 rfq_id TEXT NOT NULL UNIQUE REFERENCES rfqs(id) ON DELETE RESTRICT,
 buyer_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 buyer_name TEXT NOT NULL,
 buyer_email TEXT NOT NULL DEFAULT '',
 product TEXT NOT NULL,
 quantity TEXT NOT NULL DEFAULT '',
 destination TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','confirmed','processing','shipped','delivered','cancelled')),
 admin_note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT (datetime('now')),
 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_orders_buyer_created ON orders(buyer_email,created_at);
CREATE INDEX IF NOT EXISTS idx_orders_status_created ON orders(status,created_at);
