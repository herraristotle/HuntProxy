-- Passive scan alerts with severity, confidence, CWE, deduplication.
-- Extends findings table for automated vulnerability detection.

CREATE TABLE passive_scan_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    exchange_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    name TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical')),
    confidence INTEGER NOT NULL CHECK(confidence >= 0 AND confidence <= 100),
    cwe_id INTEGER,
    description TEXT NOT NULL,
    evidence TEXT NOT NULL,
    dedup_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (project_id, exchange_id)
        REFERENCES exchanges(project_id, exchange_id) ON DELETE CASCADE
);

CREATE INDEX idx_alerts_project ON passive_scan_alerts(project_id, id DESC);
CREATE INDEX idx_alerts_exchange ON passive_scan_alerts(project_id, exchange_id);
CREATE INDEX idx_alerts_severity ON passive_scan_alerts(project_id, severity);
CREATE UNIQUE INDEX idx_alerts_dedup ON passive_scan_alerts(project_id, dedup_key);
