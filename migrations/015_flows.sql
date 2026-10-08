-- Flow definitions (graph workflows) and exchange row color (set-color parity).

CREATE TABLE flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL CHECK (kind IN ('passive', 'active', 'convert')),
    edition INTEGER NOT NULL,
    definition_json TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_flows_project_name ON flows(project_id, name);
CREATE INDEX idx_flows_project ON flows(project_id);

-- Row color rendered in history; written by the set-color flow node.
ALTER TABLE exchanges ADD COLUMN color TEXT;
