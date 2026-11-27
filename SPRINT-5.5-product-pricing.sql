-- CODEYSA-STP Sprint 5.5: product pricing
-- Safe additive migration; existing supplier products retain "Price on request".
ALTER TABLE products ADD COLUMN price_amount REAL;
ALTER TABLE products ADD COLUMN price_currency TEXT NOT NULL DEFAULT 'EUR';
