CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	email TEXT UNIQUE NOT NULL,
	password_hash TEXT NOT NULL,
	created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
	token TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_attempts (
	key TEXT NOT NULL,
	ts INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_attempts_key ON auth_attempts(key, ts);
CREATE INDEX IF NOT EXISTS idx_auth_attempts_ts ON auth_attempts(ts);

CREATE TABLE IF NOT EXISTS post_views (
	slug TEXT PRIMARY KEY,
	count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS site_config (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
