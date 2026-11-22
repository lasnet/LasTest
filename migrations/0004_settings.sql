CREATE TABLE provider_credentials (
    provider TEXT PRIMARY KEY NOT NULL,
    ciphertext BLOB NOT NULL,
    last_four TEXT NOT NULL
);

CREATE TABLE dns_wordlists (
    id TEXT PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL UNIQUE,
    entries INTEGER NOT NULL CHECK (entries > 0),
    contents TEXT NOT NULL
);
