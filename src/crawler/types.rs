//! Crawler engine types: options, requests, stats, and link strategies.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrawlRequestState {
    Pending,
    Processing,
    Completed,
    Retrying,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlRequest {
    pub id: String,
    pub url: String,
    pub method: String,
    pub depth: u32,
    pub priority: i32,
    pub max_retries: u32,
    pub retry_count: u32,
    pub state: CrawlRequestState,
    pub unique_key: String,
    pub parent_id: Option<String>,
    pub error: Option<String>,
}

impl CrawlRequest {
    pub fn new(url: impl Into<String>, max_retries: u32) -> Self {
        let url = url.into();
        let unique_key = compute_unique_key(&url, "GET");
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            url,
            method: "GET".into(),
            depth: 0,
            priority: 0,
            max_retries,
            retry_count: 0,
            state: CrawlRequestState::Pending,
            unique_key,
            parent_id: None,
            error: None,
        }
    }

    pub fn child_of(parent: &Self, url: impl Into<String>, max_retries: u32) -> Self {
        let mut child = Self::new(url, max_retries);
        child.depth = parent.depth + 1;
        child.parent_id = Some(parent.id.clone());
        child
    }

    pub fn can_retry(&self) -> bool {
        self.retry_count < self.max_retries
    }
}

pub fn compute_unique_key(url: &str, method: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut parsed) => {
            let mut pairs: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            pairs.sort();
            let query = pairs
                .iter()
                .map(|(k, v)| {
                    format!(
                        "{}={}",
                        percent_encoding::utf8_percent_encode(
                            k,
                            percent_encoding::NON_ALPHANUMERIC
                        ),
                        percent_encoding::utf8_percent_encode(
                            v,
                            percent_encoding::NON_ALPHANUMERIC
                        )
                    )
                })
                .collect::<Vec<_>>()
                .join("&");
            if query.is_empty() {
                parsed.set_query(None);
            } else {
                parsed.set_query(Some(&query));
            }
            parsed.set_fragment(None);
            format!("{}:{}", method.to_ascii_uppercase(), parsed.as_str())
        }
        Err(_) => format!("{}:{}", method.to_ascii_uppercase(), url),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkStrategy {
    All,
    #[default]
    SameDomain,
    SameHostname,
    SameOrigin,
}

pub fn get_root_domain(hostname: &str) -> String {
    let parts: Vec<&str> = hostname.split('.').collect();
    if parts.len() <= 2 {
        return hostname.to_string();
    }
    parts[parts.len() - 2..].join(".")
}

pub fn filter_links_by_strategy(
    links: Vec<String>,
    base_url: &str,
    strategy: LinkStrategy,
) -> Vec<String> {
    let Ok(base) = url::Url::parse(base_url) else {
        return links;
    };
    let base_host = base.host_str().unwrap_or_default().to_ascii_lowercase();
    let base_root = get_root_domain(&base_host);
    let base_origin = base.origin().ascii_serialization();

    links
        .into_iter()
        .filter(|link| {
            let Ok(link_url) = url::Url::parse(link) else {
                return false;
            };
            let link_host = link_url.host_str().unwrap_or_default().to_ascii_lowercase();
            match strategy {
                LinkStrategy::All => true,
                LinkStrategy::SameDomain => get_root_domain(&link_host) == base_root,
                LinkStrategy::SameHostname => link_host == base_host,
                LinkStrategy::SameOrigin => link_url.origin().ascii_serialization() == base_origin,
            }
        })
        .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrawlStats {
    pub requests_finished: u64,
    pub requests_failed: u64,
    pub requests_retried: u64,
    pub requests_total: u64,
    pub avg_response_time_ms: f64,
    pub max_response_time_ms: f64,
    pub min_response_time_ms: f64,
    pub total_response_time_ms: f64,
    pub crawler_runtime_ms: u64,
    pub requests_with_status_code: BTreeMap<u16, u64>,
    pub errors_per_type: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerOptions {
    pub max_requests_per_crawl: u64,
    pub max_requests_per_minute: u64,
    pub max_concurrency: usize,
    pub max_request_retries: u32,
    pub retry_delay_ms: u64,
    pub max_retry_delay_ms: u64,
    pub max_depth: u32,
    pub same_domain_only: bool,
    pub respect_robots_txt: bool,
    pub user_agent: String,
    /// HuntProxy native query language (same grammar as History search).
    pub filter: Option<String>,
    pub navigation_timeout_ms: u64,
    /// Discover and crawl AJAX/fetch endpoints from JavaScript
    #[serde(default)]
    pub discover_ajax: bool,
    /// Auto-submit discovered forms with default values
    #[serde(default)]
    pub submit_forms: bool,
    /// Parse and crawl URLs from sitemap.xml
    #[serde(default)]
    pub parse_sitemap: bool,
}

impl Default for CrawlerOptions {
    fn default() -> Self {
        Self {
            max_requests_per_crawl: u64::MAX,
            max_requests_per_minute: 120,
            max_concurrency: 5,
            max_request_retries: 3,
            retry_delay_ms: 1_000,
            max_retry_delay_ms: 30_000,
            max_depth: 10,
            same_domain_only: true,
            respect_robots_txt: false,
            user_agent: "HuntProxy-Crawler".into(),
            filter: None,
            navigation_timeout_ms: 30_000,
            discover_ajax: false,
            submit_forms: false,
            parse_sitemap: false,
        }
    }
}
