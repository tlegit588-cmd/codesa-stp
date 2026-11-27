-- CODEYSA-STP Sprint 4.12: Customer support and order disputes
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS support_cases (
    id TEXT PRIMARY KEY,
    reference TEXT NOT NULL UNIQUE,
    order_id TEXT NOT NULL REFERENCES orders(id) ON DELETE RESTRICT,
    opened_by TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    reporter_role TEXT NOT NULL CHECK(reporter_role IN ('buyer','supplier')),
    category TEXT NOT NULL CHECK(category IN (
        'order_issue','delivery_delay','damaged_goods',
        'missing_items','product_quality','other'
    )),
    subject TEXT NOT NULL CHECK(length(subject) BETWEEN 4 AND 160),
    description TEXT NOT NULL CHECK(length(description) BETWEEN 10 AND 3000),
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN (
        'open','in_review','waiting_supplier','waiting_buyer','resolved','closed'
    )),
    resolution_note TEXT NOT NULL DEFAULT '',
    resolved_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    resolved_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_support_cases_order_created
ON support_cases(order_id, created_at);

CREATE INDEX IF NOT EXISTS idx_support_cases_status_updated
ON support_cases(status, updated_at);

CREATE INDEX IF NOT EXISTS idx_support_cases_opened_by
ON support_cases(opened_by, created_at);

CREATE TABLE IF NOT EXISTS support_case_messages (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES support_cases(id) ON DELETE CASCADE,
    sender_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    sender_role TEXT NOT NULL CHECK(sender_role IN ('buyer','supplier','admin')),
    message TEXT NOT NULL CHECK(length(message) BETWEEN 1 AND 2000),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_support_case_messages_case_created
ON support_case_messages(case_id, created_at);
