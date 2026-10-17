//! Multi-level crawl engine: queue-driven fetching with scope, filter,
//! depth, rate, and robots checks; link discovery from HTML responses;
//! request persistence through `ReplyService`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::app::AppEvent;
use crate::codec::decode_content_encodings;
use crate::domain::*;
use crate::history::FilterNode;
use crate::policy::{url_is_in_scope, PresentationOptions};
use crate::reply::{ReplySendContext, ReplyService};
use crate::storage::Db;

use super::filter::{filter_matches_url, parse_crawl_filter};
use super::queue::CrawlQueue;
use super::rate_limit::RateLimiter;
use super::robots::RobotsTxt;
use super::stats::StatsTracker;
use super::types::{
    filter_links_by_strategy, CrawlRequest, CrawlStats, CrawlerOptions, LinkStrategy,
};
use super::{discover_links, is_html_mime};

const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;
const MAX_LINKS_PER_PAGE: usize = 64;
const STATS_FLUSH_EVERY: u64 = 25;
const ROBOTS_FETCH_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlEngineConfig {
    pub project_id: ProjectId,
    pub job_id: CrawlJobId,
    pub seed_url: String,
    #[serde(default)]
    pub options: CrawlerOptions,
    #[serde(default)]
    pub scope: ScopePolicy,
    #[serde(default = "default_strategy")]
    pub strategy: LinkStrategy,
}

fn default_strategy() -> LinkStrategy {
    LinkStrategy::SameDomain
}

pub struct CrawlEngine {
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    events: broadcast::Sender<AppEvent>,
    http: wreq::Client,
    robots_cache: DashMap<String, Arc<RobotsTxt>>,
}

impl CrawlEngine {
    pub fn new(db: Arc<Db>, reply: Arc<ReplyService>, events: broadcast::Sender<AppEvent>) -> Self {
        Self {
            db,
            reply,
            events,
            http: wreq::Client::builder()
                .timeout(std::time::Duration::from_secs(ROBOTS_FETCH_TIMEOUT_SECS))
                .build()
                .unwrap_or_default(),
            robots_cache: DashMap::new(),
        }
    }

    pub async fn run(
        &self,
        config: CrawlEngineConfig,
        cancel: CancellationToken,
    ) -> DomainResult<CrawlStats> {
        let options = config.options.clone();
        let filter = match &options.filter {
            Some(text) => parse_crawl_filter(text)?,
            None => None,
        };
        let limiter = RateLimiter::new(options.max_requests_per_minute);
        let stats = Arc::new(StatsTracker::new());
        let queue = Arc::new(Mutex::new(CrawlQueue::new()));
        let crawled = Arc::new(AtomicU64::new(0));

        queue.lock().await.add(CrawlRequest::new(
            config.seed_url.clone(),
            options.max_request_retries,
        ));

        self.db
            .set_crawl_job_state(
                config.project_id,
                config.job_id,
                CrawlJobState::Running,
                None,
            )
            .await?;

        let mut running = FuturesUnordered::new();
        let mut finished = false;

        loop {
            while !cancel.is_cancelled()
                && !finished
                && running.len() < options.max_concurrency.max(1)
            {
                if crawled.load(Ordering::Relaxed) >= options.max_requests_per_crawl {
                    finished = true;
                    break;
                }
                let Some(request) = queue.lock().await.fetch_next() else {
                    if running.is_empty() {
                        finished = true;
                    }
                    break;
                };

                if request.depth > options.max_depth {
                    queue.lock().await.mark_handled(&request);
                    continue;
                }
                if options.respect_robots_txt
                    && !self.robots_allowed(&request.url, &options.user_agent).await
                {
                    queue.lock().await.mark_handled(&request);
                    continue;
                }
                if !limiter.acquire().await {
                    return Err(DomainError::new(
                        ErrorCode::Internal,
                        "crawl rate limiter shut down",
                    ));
                }
                if request.retry_count > 0 {
                    let shift = u32::from(request.retry_count.min(8));
                    let delay = options
                        .retry_delay_ms
                        .saturating_mul(1u64 << shift)
                        .min(options.max_retry_delay_ms);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }

                let db = self.db.clone();
                let reply = self.reply.clone();
                let events = self.events.clone();
                let queue = queue.clone();
                let stats = stats.clone();
                let crawled = crawled.clone();
                let cancel = cancel.clone();
                let config = config.clone();
                let options = options.clone();
                let filter = filter.clone();
                running.push(tokio::spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = execute_request(
                            db, reply, events, queue, stats, crawled,
                            config, options, filter, request,
                        ) => {}
                    }
                }));
            }

            if running.is_empty() {
                break;
            }
            if let Some(Err(error)) = running.next().await {
                tracing::debug!(%error, "crawl task join failed");
            }

            if cancel.is_cancelled() {
                while running.next().await.is_some() {}
                let snapshot = stats.snapshot();
                let _ = self
                    .db
                    .set_crawl_job_state(
                        config.project_id,
                        config.job_id,
                        CrawlJobState::Interrupted,
                        None,
                    )
                    .await;
                return Ok(snapshot);
            }
        }

        let snapshot = stats.snapshot();
        self.db
            .update_crawl_job_stats(
                config.project_id,
                config.job_id,
                snapshot.crawler_runtime_ms.min(u32::MAX as u64) as u32,
                snapshot.requests_total,
                snapshot
                    .requests_finished
                    .saturating_sub(snapshot.requests_failed),
                snapshot.requests_failed,
            )
            .await?;
        self.db
            .set_crawl_job_state(
                config.project_id,
                config.job_id,
                CrawlJobState::Completed,
                None,
            )
            .await?;
        Ok(snapshot)
    }

    async fn robots_allowed(&self, url: &str, user_agent: &str) -> bool {
        let Ok(parsed) = Url::parse(url) else {
            return true;
        };
        let Some(host) = parsed.host_str().map(str::to_string) else {
            return true;
        };
        if !self.robots_cache.contains_key(&host) {
            let scheme = parsed.scheme();
            let robots_url = format!("{scheme}://{host}/robots.txt");
            let content = match self.http.get(&robots_url).send().await {
                Ok(response) if response.status().is_success() => response.text().await.ok(),
                _ => None,
            };
            let robots = content
                .map(|text| RobotsTxt::parse(&text))
                .unwrap_or_default();
            self.robots_cache.insert(host.clone(), Arc::new(robots));
        }
        self.robots_cache
            .get(&host)
            .map(|robots| robots.is_allowed(url, user_agent))
            .unwrap_or(true)
    }
}

async fn execute_request(
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    events: broadcast::Sender<AppEvent>,
    queue: Arc<Mutex<CrawlQueue>>,
    stats: Arc<StatsTracker>,
    crawled: Arc<AtomicU64>,
    config: CrawlEngineConfig,
    options: CrawlerOptions,
    filter: Option<FilterNode>,
    mut request: CrawlRequest,
) {
    let started = Instant::now();
    let draft = ReplyDraft {
        method: Some(request.method.clone()),
        url: Some(request.url.clone()),
        body_cleared: true,
        ..Default::default()
    };
    let context = ReplySendContext {
        source: ExchangeSource::Browser,
        lineage: ExchangeLineage::default(),
        plugin_target_host: None,
    };
    let result = reply
        .send_with_context(
            config.project_id,
            None,
            &draft,
            ProtocolPreference::Auto,
            0,
            context,
        )
        .await;

    match result {
        Ok(send_result) => {
            let duration_ms = started.elapsed().as_secs_f64() * 1000.0;
            let exchange_id = send_result.exchange_id;
            let status = match exchange_id {
                Some(id) => db
                    .get_exchange_summary(config.project_id, id)
                    .await
                    .ok()
                    .and_then(|summary| summary.status_code),
                None => None,
            };
            stats.record_request(duration_ms, status);
            let done = crawled.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = events.send(AppEvent {
                project_id: config.project_id.get(),
                kind: "crawl".into(),
                payload: serde_json::json!({
                    "job_id": config.job_id.get(),
                    "url": request.url.as_str(),
                    "exchange_id": exchange_id.map(|id| id.get()),
                    "status": status,
                }),
            });

            if let Some(exchange_id) = exchange_id {
                enqueue_discovered_links(
                    db.clone(),
                    queue.clone(),
                    &config,
                    &options,
                    filter.as_ref(),
                    &request,
                    exchange_id,
                )
                .await;
            }

            queue.lock().await.mark_handled(&request);

            if done % STATS_FLUSH_EVERY == 0 {
                let snapshot = stats.snapshot();
                let _ = db
                    .update_crawl_job_stats(
                        config.project_id,
                        config.job_id,
                        snapshot.crawler_runtime_ms.min(u32::MAX as u64) as u32,
                        snapshot.requests_total,
                        snapshot
                            .requests_finished
                            .saturating_sub(snapshot.requests_failed),
                        snapshot.requests_failed,
                    )
                    .await;
            }
        }
        Err(error) => {
            stats.record_failure(error_category(&error));
            queue
                .lock()
                .await
                .handle_failure(&mut request, &error.to_string());
        }
    }
}

fn error_category(error: &DomainError) -> &'static str {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("timeout") {
        "timeout"
    } else if text.contains("dns") || text.contains("resolve") {
        "dns"
    } else if text.contains("connect") || text.contains("refused") {
        "connect"
    } else {
        "other"
    }
}

async fn enqueue_discovered_links(
    db: Arc<Db>,
    queue: Arc<Mutex<CrawlQueue>>,
    config: &CrawlEngineConfig,
    options: &CrawlerOptions,
    filter: Option<&FilterNode>,
    parent: &CrawlRequest,
    exchange_id: ExchangeId,
) {
    let Ok(detail) = db
        .get_exchange_detail(
            config.project_id,
            exchange_id,
            PresentationOptions::default(),
        )
        .await
    else {
        return;
    };
    if !is_html_mime(detail.summary.mime.as_deref()) {
        return;
    }
    let Ok(Some(mut body)) = db
        .load_raw_body(config.project_id, exchange_id, MessageSide::Response)
        .await
    else {
        return;
    };
    if let Ok(headers) = db
        .load_raw_headers(config.project_id, exchange_id, MessageSide::Response)
        .await
    {
        if let Some(encoding) = headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("content-encoding"))
            .and_then(|header| std::str::from_utf8(&header.value).ok())
        {
            if let Ok(decoded) = decode_content_encodings(&body, encoding, MAX_HTML_BYTES) {
                body = decoded;
            }
        }
    }
    if body.len() > MAX_HTML_BYTES {
        body.truncate(MAX_HTML_BYTES);
    }
    let base = format!(
        "{}://{}{}",
        detail.summary.scheme, detail.summary.authority, detail.summary.path
    );
    let html = String::from_utf8_lossy(&body);
    let Ok(discovered) = discover_links(base.as_str(), &html) else {
        return;
    };
    let filtered: Vec<String> = discovered
        .into_iter()
        .filter(|url| {
            let Ok(parsed) = Url::parse(url) else {
                return false;
            };
            if !url_is_in_scope(url, &config.scope).unwrap_or(false) {
                return false;
            }
            if let Some(filter) = filter {
                if !filter_matches_url(filter, &parsed, "GET") {
                    return false;
                }
            }
            true
        })
        .take(MAX_LINKS_PER_PAGE)
        .collect();
    let filtered = filter_links_by_strategy(filtered, base.as_str(), config.strategy);

    let mut queue = queue.lock().await;
    for url in filtered {
        if parent.depth >= options.max_depth {
            break;
        }
        queue.add(CrawlRequest::child_of(
            parent,
            url,
            options.max_request_retries,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reply::PlaceholderKey;
    use crate::transport::SemanticTransport;

    struct RejectTransport;

    #[async_trait::async_trait]
    impl SemanticTransport for RejectTransport {
        async fn send(
            &self,
            _dial: &crate::domain::ValidatedDial,
            _req: crate::transport::OutboundRequest,
        ) -> DomainResult<crate::transport::OutboundResponse> {
            Err(DomainError::invalid("no transport in test"))
        }

        fn profile_name(&self) -> &str {
            "reject"
        }

        fn provenance(&self) -> crate::domain::TransportProvenance {
            crate::domain::TransportProvenance::GenericUnprofiled
        }
    }

    #[test]
    fn engine_config_defaults_strategy() {
        let config: CrawlEngineConfig = serde_json::from_value(serde_json::json!({
            "project_id": 1,
            "job_id": 1,
            "seed_url": "https://example.com",
        }))
        .unwrap();
        assert!(matches!(config.strategy, LinkStrategy::SameDomain));
        assert!(config.options.filter.is_none());
        assert!(!config.options.respect_robots_txt);
    }

    #[tokio::test]
    async fn robots_cache_stores_default_allow_when_fetch_fails() {
        let db = Arc::new(Db::open_in_memory().await.unwrap());
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: Arc::new(RejectTransport),
            placeholder_key: PlaceholderKey::from_bytes(vec![7; 32]),
            upstream_proxies: Default::default(),
        });
        let engine = CrawlEngine::new(db, reply, broadcast::channel(1).0);
        assert!(
            engine
                .robots_allowed("http://127.0.0.1:1/x", "HuntProxy")
                .await
        );
        assert!(engine.robots_cache.contains_key("127.0.0.1"));
    }
}
