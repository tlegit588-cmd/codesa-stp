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
 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
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
 updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_orders_buyer_created ON orders(buyer_email,created_at);
CREATE INDEX IF NOT EXISTS idx_orders_status_created ON orders(status,created_at);
