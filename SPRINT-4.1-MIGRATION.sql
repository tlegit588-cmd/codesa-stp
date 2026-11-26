-- Run once in the existing CODEYSA marketplace D1 database.
ALTER TABLE products ADD COLUMN image_url TEXT NOT NULL DEFAULT '';
