-- Adds a NOT NULL column with no default on an existing table.
ALTER TABLE orders ADD COLUMN customer_ref text NOT NULL;
