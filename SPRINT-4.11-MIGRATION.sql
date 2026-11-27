-- CODEYSA-STP Sprint 4.11: Verified-purchase product reviews
-- Run this migration once against the production D1 database.

CREATE TABLE IF NOT EXISTS product_reviews (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    order_id TEXT NOT NULL UNIQUE REFERENCES orders(id) ON DELETE CASCADE,
    buyer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
    comment TEXT NOT NULL DEFAULT '' CHECK (length(comment) <= 1500),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'published', 'hidden')),
    moderated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    moderated_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_product_reviews_product_status
    ON product_reviews(product_id, status, created_at);

CREATE INDEX IF NOT EXISTS idx_product_reviews_buyer_created
    ON product_reviews(buyer_id, created_at);

CREATE INDEX IF NOT EXISTS idx_product_reviews_status_created
    ON product_reviews(status, created_at);
