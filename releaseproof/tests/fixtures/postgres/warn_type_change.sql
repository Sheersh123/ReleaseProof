-- Warning-level: column type change can rewrite a large table.
ALTER TABLE invoices ALTER COLUMN amount TYPE bigint;
