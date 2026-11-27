-- Sprint 4.7: in-app notifications
CREATE TABLE IF NOT EXISTS notifications (
 id TEXT PRIMARY KEY,
 recipient_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 type TEXT NOT NULL CHECK(type IN ('message','order_status')),
 title TEXT NOT NULL,
 message TEXT NOT NULL,
 order_id TEXT REFERENCES orders(id) ON DELETE CASCADE,
 read_at TEXT,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notifications_recipient_unread
ON notifications(recipient_id,read_at,created_at);
