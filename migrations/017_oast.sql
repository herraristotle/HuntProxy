-- Provider registry: Caido/QuickSSRF-style named providers the daemon can
-- register sessions with. Global (not project-scoped): providers are shared
-- daemon infrastructure; sessions snapshot what they need to keep polling.
CREATE TABLE oast_providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    server TEXT NOT NULL,
    domain TEXT,
    token TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    is_default INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE oast_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    provider_kind TEXT NOT NULL,
    correlation_id TEXT UNIQUE,
    secret TEXT,
    server TEXT NOT NULL,
    domain TEXT,
    rsa_private_key_pem TEXT,
    rsa_public_key_pem TEXT,
    provider_meta TEXT,
    provider_token TEXT,
    label TEXT,
    purpose TEXT,
    watch INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    last_polled_at TEXT
);

CREATE INDEX idx_oast_sessions_project ON oast_sessions(project_id, status);
CREATE INDEX idx_oast_sessions_watch ON oast_sessions(watch, status);

CREATE TABLE oast_interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES oast_sessions(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL DEFAULT '',
    unique_id TEXT NOT NULL DEFAULT '',
    full_id TEXT NOT NULL DEFAULT '',
    remote_address TEXT NOT NULL DEFAULT '',
    raw_request TEXT NOT NULL DEFAULT '',
    raw_response TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL,
    UNIQUE(session_id, full_id, timestamp, protocol)
);

CREATE INDEX idx_oast_interactions_session ON oast_interactions(session_id, id);

CREATE TABLE oast_labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES oast_sessions(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    case_index INTEGER,
    created_at TEXT NOT NULL,
    UNIQUE(session_id, label)
);

CREATE INDEX idx_oast_labels_session ON oast_labels(session_id, case_index);
