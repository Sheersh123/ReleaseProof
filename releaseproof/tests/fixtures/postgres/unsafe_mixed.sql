-- Several risky patterns in one migration.
DROP TABLE audit_log_old;

ALTER TABLE accounts RENAME COLUMN email TO email_address;

ALTER TABLE events ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

CREATE INDEX idx_events_type ON events (event_type);

TRUNCATE sessions;
