CREATE TABLE crawl_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    host TEXT NOT NULL,
    state TEXT NOT NULL,
    depth INTEGER NOT NULL DEFAULT 0,
    discovered_urls INTEGER NOT NULL DEFAULT 0,
    crawled_urls INTEGER NOT NULL DEFAULT 0,
    failed_urls INTEGER NOT NULL DEFAULT 0,
    agent_count INTEGER NOT NULL DEFAULT 1,
    title TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    completed_at TEXT
);

CREATE INDEX idx_crawl_jobs_project ON crawl_jobs(project_id);
