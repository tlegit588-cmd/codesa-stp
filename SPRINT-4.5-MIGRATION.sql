-- CODEYSA-STP Sprint 4.5: supplier verification metadata
ALTER TABLE supplier_profiles ADD COLUMN verification_note TEXT NOT NULL DEFAULT '';
ALTER TABLE supplier_profiles ADD COLUMN verified_at TEXT;
CREATE INDEX IF NOT EXISTS idx_supplier_verified ON supplier_profiles(verified_at);