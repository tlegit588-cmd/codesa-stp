-- Sprint 5.6: administrator-managed marketplace categories
CREATE TABLE IF NOT EXISTS product_categories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL COLLATE NOCASE UNIQUE,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_product_categories_status_name
ON product_categories(status,name);

-- Seed standard marketplace filters and preserve categories already used by listings.
INSERT OR IGNORE INTO product_categories (id,name,status) VALUES
 (lower(hex(randomblob(16))),'Agriculture & Food','active'),
 (lower(hex(randomblob(16))),'Cocoa & Coffee','active'),
 (lower(hex(randomblob(16))),'Crafts & Culture','active'),
 (lower(hex(randomblob(16))),'Beauty & Wellness','active'),
 (lower(hex(randomblob(16))),'Business Services','active');
INSERT OR IGNORE INTO product_categories (id,name,status)
SELECT lower(hex(randomblob(16))),trim(category),'active'
FROM products
WHERE trim(category)<>''
GROUP BY trim(category);
