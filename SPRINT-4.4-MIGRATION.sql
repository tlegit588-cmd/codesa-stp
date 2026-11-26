-- CODEYSA-STP Marketplace Sprint 4.4
-- Run once in Cloudflare D1 database: codesa-marketplace
ALTER TABLE orders ADD COLUMN supplier_id TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE orders ADD COLUMN supplier_note TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_orders_supplier_created ON orders(supplier_id,created_at);
