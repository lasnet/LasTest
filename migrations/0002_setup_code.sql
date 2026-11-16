CREATE TABLE setup_code (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
