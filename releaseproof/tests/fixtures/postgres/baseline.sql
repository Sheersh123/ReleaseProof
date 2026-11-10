-- Representative non-production baseline schema the migrations build on.
-- Applied inside the disposable test schema before migrations (Layer B).
CREATE TABLE users    (id serial PRIMARY KEY, legacy_token text, email text);
CREATE TABLE orders   (id serial PRIMARY KEY);
CREATE TABLE events   (id serial PRIMARY KEY, event_type text);
CREATE TABLE invoices (id serial PRIMARY KEY, amount integer);
CREATE TABLE accounts (id serial PRIMARY KEY, email text);
CREATE TABLE sessions (id serial PRIMARY KEY);
CREATE TABLE audit_log_old (id serial PRIMARY KEY);
