//! Sitemap.xml parsing for spider enhancement.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitemapUrl {
    pub loc: String,
    pub lastmod: Option<String>,
    pub changefreq: Option<String>,
    pub priority: Option<f32>,
}

/// Parse sitemap.xml and extract URLs.
pub fn parse_sitemap(base_url: &str, xml_content: &str) -> Vec<SitemapUrl> {
    let Ok(base) = Url::parse(base_url) else {
        return Vec::new();
    };

    let mut urls = Vec::new();
    let mut seen = HashSet::new();

    // Simple regex-based XML parsing (good enough for sitemap.xml structure)
    let url_pattern = regex::Regex::new(r"(?s)<url>(.*?)</url>").unwrap();
    let loc_pattern = regex::Regex::new(r"<loc>(.*?)</loc>").unwrap();
    let lastmod_pattern = regex::Regex::new(r"<lastmod>(.*?)</lastmod>").unwrap();
    let changefreq_pattern = regex::Regex::new(r"<changefreq>(.*?)</changefreq>").unwrap();
    let priority_pattern = regex::Regex::new(r"<priority>(.*?)</priority>").unwrap();

    for url_block in url_pattern.captures_iter(xml_content) {
        let block = url_block.get(1).map(|m| m.as_str()).unwrap_or("");

        // Extract loc (required)
        let Some(loc_cap) = loc_pattern.captures(block) else {
            continue;
        };
        let loc = loc_cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");

        if loc.is_empty() {
            continue;
        }

        // Resolve URL
        let resolved = if loc.starts_with("http://") || loc.starts_with("https://") {
            loc.to_string()
        } else {
            base.join(loc)
                .ok()
                .map(|u| u.to_string())
                .unwrap_or_else(|| loc.to_string())
        };

        // Deduplicate
        if seen.contains(&resolved) {
            continue;
        }
        seen.insert(resolved.clone());

        // Extract optional fields
        let lastmod = lastmod_pattern
            .captures(block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());

        let changefreq = changefreq_pattern
            .captures(block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());

        let priority = priority_pattern
            .captures(block)
            .and_then(|c| c.get(1))
            .and_then(|m| m.as_str().trim().parse::<f32>().ok());

        urls.push(SitemapUrl {
            loc: resolved,
            lastmod,
            changefreq,
            priority,
        });
    }

    urls
}

/// Parse sitemap index and extract sitemap URLs.
pub fn parse_sitemap_index(base_url: &str, xml_content: &str) -> Vec<String> {
    let Ok(base) = Url::parse(base_url) else {
        return Vec::new();
    };

    let mut sitemaps = Vec::new();
    let sitemap_pattern = regex::Regex::new(r"(?s)<sitemap>(.*?)</sitemap>").unwrap();
    let loc_pattern = regex::Regex::new(r"<loc>(.*?)</loc>").unwrap();

    for sitemap_block in sitemap_pattern.captures_iter(xml_content) {
        let block = sitemap_block.get(1).map(|m| m.as_str()).unwrap_or("");

        if let Some(loc_cap) = loc_pattern.captures(block) {
            let loc = loc_cap.get(1).map(|m| m.as_str().trim()).unwrap_or("");

            if !loc.is_empty() {
                let resolved = if loc.starts_with("http://") || loc.starts_with("https://") {
                    loc.to_string()
                } else {
                    base.join(loc)
                        .ok()
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| loc.to_string())
                };
                sitemaps.push(resolved);
            }
        }
    }

    sitemaps
}

/// Detect if XML content is a sitemap index vs regular sitemap.
pub fn is_sitemap_index(xml_content: &str) -> bool {
    xml_content.contains("<sitemapindex") || xml_content.contains("<sitemap>")
}

/// Extract sitemap URLs from robots.txt content.
pub fn extract_sitemaps_from_robots(robots_content: &str, base_url: &str) -> Vec<String> {
    let Ok(base) = Url::parse(base_url) else {
        return Vec::new();
    };

    let mut sitemaps = Vec::new();
    let sitemap_pattern = regex::Regex::new(r"(?i)^\s*Sitemap:\s*(.+)$").unwrap();

    for line in robots_content.lines() {
        if let Some(cap) = sitemap_pattern.captures(line) {
            if let Some(url) = cap.get(1) {
                let url_str = url.as_str().trim();

                let resolved = if url_str.starts_with("http://") || url_str.starts_with("https://")
                {
                    url_str.to_string()
                } else {
                    base.join(url_str)
                        .ok()
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| url_str.to_string())
                };

                sitemaps.push(resolved);
            }
        }
    }

    sitemaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_sitemap() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/page1</loc>
    <lastmod>2024-01-01</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>https://example.com/page2</loc>
  </url>
</urlset>"#;

        let urls = parse_sitemap("https://example.com", xml);
        assert_eq!(urls.len(), 2);

        let page1 = &urls[0];
        assert_eq!(page1.loc, "https://example.com/page1");
        assert_eq!(page1.lastmod.as_deref(), Some("2024-01-01"));
        assert_eq!(page1.changefreq.as_deref(), Some("daily"));
        assert_eq!(page1.priority, Some(0.8));

        let page2 = &urls[1];
        assert_eq!(page2.loc, "https://example.com/page2");
        assert!(page2.lastmod.is_none());
    }

    #[test]
    fn parses_sitemap_index() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap>
    <loc>https://example.com/sitemap1.xml</loc>
  </sitemap>
  <sitemap>
    <loc>https://example.com/sitemap2.xml</loc>
  </sitemap>
</sitemapindex>"#;

        let sitemaps = parse_sitemap_index("https://example.com", xml);
        assert_eq!(sitemaps.len(), 2);
        assert!(sitemaps.contains(&"https://example.com/sitemap1.xml".to_string()));
        assert!(sitemaps.contains(&"https://example.com/sitemap2.xml".to_string()));
    }

    #[test]
    fn detect_sitemap_index() {
        let index_xml = r#"<sitemapindex><sitemap><loc>test</loc></sitemap></sitemapindex>"#;
        let regular_xml = r#"<urlset><url><loc>test</loc></url></urlset>"#;

        assert!(is_sitemap_index(index_xml));
        assert!(!is_sitemap_index(regular_xml));
    }

    #[test]
    fn extract_from_robots() {
        let robots = r#"
User-agent: *
Disallow: /admin

Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap2.xml
"#;

        let sitemaps = extract_sitemaps_from_robots(robots, "https://example.com");
        assert_eq!(sitemaps.len(), 2);
        assert!(sitemaps.contains(&"https://example.com/sitemap.xml".to_string()));
        assert!(sitemaps.contains(&"https://example.com/sitemap2.xml".to_string()));
    }

    #[test]
    fn resolve_relative_urls() {
        let xml = r#"<urlset><url><loc>/page1</loc></url></urlset>"#;

        let urls = parse_sitemap("https://example.com", xml);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].loc, "https://example.com/page1");
    }

    #[test]
    fn deduplicate_urls() {
        let xml = r#"<urlset>
            <url><loc>https://example.com/page1</loc></url>
            <url><loc>https://example.com/page1</loc></url>
        </urlset>"#;

        let urls = parse_sitemap("https://example.com", xml);
        assert_eq!(urls.len(), 1);
    }
}
