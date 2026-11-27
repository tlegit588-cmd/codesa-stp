PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, password_salt TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('buyer','supplier','admin')),
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','pending','rejected','suspended')),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_users_role_status ON users(role,status);
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
CREATE TABLE IF NOT EXISTS supplier_profiles (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 business_name TEXT NOT NULL DEFAULT '', country TEXT NOT NULL DEFAULT 'São Tomé and Príncipe',
 description TEXT NOT NULL DEFAULT '', phone TEXT NOT NULL DEFAULT '', website TEXT NOT NULL DEFAULT '',
 verification_note TEXT NOT NULL DEFAULT '', verified_at TEXT,
 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_supplier_verified ON supplier_profiles(verified_at);
CREATE TABLE IF NOT EXISTS products (
 id TEXT PRIMARY KEY, supplier_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name TEXT NOT NULL, category TEXT NOT NULL, description TEXT NOT NULL,
 unit TEXT NOT NULL DEFAULT '', origin TEXT NOT NULL DEFAULT 'São Tomé and Príncipe',
 image_url TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','published','rejected')),
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_products_status ON products(status,created_at);

-- Sprint 3: administrator audit trail
CREATE TABLE IF NOT EXISTS audit_logs (
 id TEXT PRIMARY KEY,
 actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 action TEXT NOT NULL,
 target_type TEXT NOT NULL,
 target_id TEXT NOT NULL,
 details TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);


-- Sprint 4.2: buyer requests for quotation (RFQs)
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


-- Sprint 4.3: marketplace orders created from quoted buyer enquiries
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
 updated_at TEXT NOT NULL DEFAULT (datetime('now')),
 supplier_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 supplier_note TEXT NOT NULL DEFAULT ''
,
 carrier_name TEXT NOT NULL DEFAULT '',
 tracking_number TEXT NOT NULL DEFAULT '',
 tracking_url TEXT NOT NULL DEFAULT '',
 shipped_at TEXT,
 delivered_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_orders_supplier_created ON orders(supplier_id,created_at);
CREATE INDEX IF NOT EXISTS idx_orders_buyer_created ON orders(buyer_email,created_at);
CREATE INDEX IF NOT EXISTS idx_orders_status_created ON orders(status,created_at);


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


-- Sprint 4.8: shipment and order status history
CREATE TABLE IF NOT EXISTS order_status_events (
 id TEXT PRIMARY KEY,
 order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 actor_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 actor_role TEXT NOT NULL CHECK(actor_role IN ('admin','supplier','system')),
 status TEXT NOT NULL,
 note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_order_status_events_order ON order_status_events(order_id,created_at);
