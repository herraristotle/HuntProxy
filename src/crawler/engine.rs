//! Multi-level crawl engine: queue-driven fetching with scope, filter,
//! depth, rate, and robots checks; link discovery from HTML responses;
//! request persistence through `ReplyService`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures::stream::{FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, broadcast};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::app::AppEvent;
use crate::codec::decode_content_encodings;
use crate::domain::*;
use crate::history::FilterNode;
use crate::policy::{PresentationOptions, url_is_in_scope};
use crate::reply::{ReplySendContext, ReplyService};
use crate::storage::Db;

use super::filter::{filter_matches_url, parse_crawl_filter};
use super::queue::CrawlQueue;
use super::rate_limit::RateLimiter;
use super::robots::RobotsTxt;
use super::stats::StatsTracker;
use super::types::{
    CrawlRequest, CrawlRequestState, CrawlStats, CrawlerOptions, LinkStrategy,
    filter_links_by_strategy,
};
use super::{ajax, discover_links, forms, is_html_mime, sitemap};

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
        pause: Arc<AtomicBool>,
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
        let max_depth = Arc::new(AtomicU32::new(0));

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
        let _ = self.events.send(AppEvent {
            project_id: config.project_id.get(),
            kind: "crawl".into(),
            payload: serde_json::json!({
                "event": "crawl_started",
                "job_id": config.job_id.get(),
                "seed_url": config.seed_url,
            }),
        });

        let mut running = FuturesUnordered::new();
        let mut finished = false;
        let mut paused_db_state = false;

        loop {
            while !cancel.is_cancelled()
                && !finished
                && !pause.load(Ordering::Relaxed)
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
                max_depth.fetch_max(request.depth, Ordering::Relaxed);
                let acquired = tokio::select! {
                    _ = cancel.cancelled() => None,
                    acquired = limiter.acquire() => Some(acquired),
                };
                let Some(acquired) = acquired else {
                    finished = true;
                    break;
                };
                if !acquired {
                    return Err(DomainError::new(
                        ErrorCode::Internal,
                        "crawl rate limiter shut down",
                    ));
                }
                if request.retry_count > 0 {
                    let shift = request.retry_count.min(8);
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
                let max_depth = max_depth.clone();
                let cancel = cancel.clone();
                let config = config.clone();
                let options = options.clone();
                let filter = filter.clone();
                running.push(tokio::spawn(async move {
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = execute_request(
                            db, reply, events, queue, stats, crawled, max_depth,
                            config, options, filter, request,
                        ) => {}
                    }
                }));
            }

            let paused = pause.load(Ordering::Relaxed);
            if paused && !paused_db_state && !cancel.is_cancelled() {
                paused_db_state = true;
                let _ = self
                    .db
                    .set_crawl_job_state(
                        config.project_id,
                        config.job_id,
                        CrawlJobState::Paused,
                        None,
                    )
                    .await;
            } else if !paused && paused_db_state {
                paused_db_state = false;
                let _ = self
                    .db
                    .set_crawl_job_state(
                        config.project_id,
                        config.job_id,
                        CrawlJobState::Running,
                        None,
                    )
                    .await;
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
                let _ = self.events.send(AppEvent {
                    project_id: config.project_id.get(),
                    kind: "crawl".into(),
                    payload: serde_json::json!({
                        "event": "crawl_aborted",
                        "job_id": config.job_id.get(),
                        "stats": serde_json::to_value(&snapshot).ok(),
                    }),
                });
                return Ok(snapshot);
            }

            if running.is_empty() {
                if paused && !finished {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                } else {
                    break;
                }
            } else if let Some(Err(error)) = running.next().await {
                tracing::debug!(%error, "crawl task join failed");
            }
        }

        let snapshot = stats.snapshot();
        let discovered = queue.lock().await.stats().total as u64;
        self.db
            .update_crawl_job_stats(
                config.project_id,
                config.job_id,
                max_depth.load(Ordering::Relaxed),
                discovered,
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
        let _ = self.events.send(AppEvent {
            project_id: config.project_id.get(),
            kind: "crawl".into(),
            payload: serde_json::json!({
                "event": "crawl_finished",
                "job_id": config.job_id.get(),
                "stats": serde_json::to_value(&snapshot).ok(),
            }),
        });
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
            let robots = match content {
                Some(text) => RobotsTxt::parse(&text),
                None => RobotsTxt::default(),
            };
            self.robots_cache.insert(host.clone(), Arc::new(robots));
        }
        self.robots_cache
            .get(&host)
            .map(|robots| robots.is_allowed(url, user_agent))
            .unwrap_or(true)
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute_request(
    db: Arc<Db>,
    reply: Arc<ReplyService>,
    events: broadcast::Sender<AppEvent>,
    queue: Arc<Mutex<CrawlQueue>>,
    stats: Arc<StatsTracker>,
    crawled: Arc<AtomicU64>,
    max_depth: Arc<AtomicU32>,
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
    let _ = events.send(AppEvent {
        project_id: config.project_id.get(),
        kind: "crawl".into(),
        payload: serde_json::json!({
            "event": "request_started",
            "job_id": config.job_id.get(),
            "url": request.url,
            "depth": request.depth,
        }),
    });
    let send = reply.send_with_context(
        config.project_id,
        None,
        &draft,
        ProtocolPreference::Auto,
        0,
        context,
    );
    let result = match tokio::time::timeout(
        Duration::from_millis(options.navigation_timeout_ms.max(1)),
        send,
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(DomainError::new(
            ErrorCode::Timeout,
            format!(
                "crawl navigation timeout after {}ms: {}",
                options.navigation_timeout_ms, request.url
            ),
        )),
    };

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
                    "event": "request_completed",
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
                flush_job_stats(db, queue.clone(), max_depth, &stats, &config).await;
            }
        }
        Err(error) => {
            stats.record_failure(error_category(&error));
            let _ = events.send(AppEvent {
                project_id: config.project_id.get(),
                kind: "crawl".into(),
                payload: serde_json::json!({
                    "event": "request_failed",
                    "job_id": config.job_id.get(),
                    "url": request.url.as_str(),
                    "error": error.to_string(),
                }),
            });
            queue
                .lock()
                .await
                .handle_failure(&mut request, &error.to_string());
            if request.state == CrawlRequestState::Retrying {
                let _ = events.send(AppEvent {
                    project_id: config.project_id.get(),
                    kind: "crawl".into(),
                    payload: serde_json::json!({
                        "event": "request_retried",
                        "job_id": config.job_id.get(),
                        "url": request.url.as_str(),
                        "retry": request.retry_count,
                    }),
                });
            }
        }
    }
}

async fn flush_job_stats(
    db: Arc<Db>,
    queue: Arc<Mutex<CrawlQueue>>,
    max_depth: Arc<AtomicU32>,
    stats: &StatsTracker,
    config: &CrawlEngineConfig,
) {
    let snapshot = stats.snapshot();
    let discovered = queue.lock().await.stats().total as u64;
    let _ = db
        .update_crawl_job_stats(
            config.project_id,
            config.job_id,
            max_depth.load(Ordering::Relaxed),
            discovered,
            snapshot
                .requests_finished
                .saturating_sub(snapshot.requests_failed),
            snapshot.requests_failed,
        )
        .await;
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

    // Discover regular links
    let Ok(discovered_links) = discover_links(base.as_str(), &html) else {
        return;
    };

    // Discover AJAX endpoints if enabled
    let mut discovered = discovered_links;
    if options.discover_ajax {
        let ajax_endpoints = ajax::extract_ajax_endpoints(base.as_str(), &html);
        discovered.extend(ajax_endpoints.into_iter().map(|e| e.url));
    }

    // Discover forms if enabled
    if options.submit_forms {
        let discovered_forms = forms::extract_forms(base.as_str(), &html);
        for form in discovered_forms {
            // Generate form submission URL
            let form_url = if form.method == "GET" {
                // For GET forms, append query params
                let values = forms::generate_form_values(&form);
                let query: Vec<String> = values
                    .into_iter()
                    .map(|(k, v)| {
                        format!("{}={}", urlencoding::encode(&k), urlencoding::encode(&v))
                    })
                    .collect();
                if query.is_empty() {
                    form.action.clone()
                } else {
                    format!("{}?{}", form.action, query.join("&"))
                }
            } else {
                // For POST forms, just queue the action URL
                // Actual form submission would need request body support
                form.action.clone()
            };
            discovered.push(form_url);
        }
    }

    // Sitemap parsing: curated URLs are not subject to the per-page scrape
    // cap, but still go through scope + filter checks.
    let mut sitemap_urls: Vec<String> = Vec::new();
    if options.parse_sitemap
        && (base.ends_with(".xml") || html.contains("<urlset") || html.contains("<sitemapindex"))
    {
        sitemap_urls = if sitemap::is_sitemap_index(&html) {
            sitemap::parse_sitemap_index(base.as_str(), &html)
        } else {
            sitemap::parse_sitemap(base.as_str(), &html)
                .into_iter()
                .map(|u| u.loc)
                .collect()
        };
    }

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
    let mut filtered = filter_links_by_strategy(filtered, base.as_str(), config.strategy);

    let sitemap_filtered: Vec<String> = sitemap_urls
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
        .collect();
    filtered.extend(filter_links_by_strategy(
        sitemap_filtered,
        base.as_str(),
        config.strategy,
    ));

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
