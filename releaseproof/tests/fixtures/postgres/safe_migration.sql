-- Safe, backward-compatible migration: nullable column + concurrent index.
ALTER TABLE users ADD COLUMN last_seen_at timestamptz;

CREATE INDEX CONCURRENTLY idx_users_last_seen ON users (last_seen_at);
