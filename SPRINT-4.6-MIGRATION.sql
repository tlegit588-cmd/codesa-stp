-- Sprint 4.6: private order conversations
CREATE TABLE IF NOT EXISTS order_messages (
 id TEXT PRIMARY KEY,
 order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 sender_role TEXT NOT NULL CHECK(sender_role IN ('buyer','supplier','admin')),
 message TEXT NOT NULL CHECK(length(message) BETWEEN 1 AND 2000),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_order_messages_order_created ON order_messages(order_id,created_at);
