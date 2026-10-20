//! robots.txt parsing and per-domain compliance checking.

use regex::Regex;
use std::collections::HashMap;

#[derive(Debug, Clone)]
struct RobotsGroup {
    user_agents: Vec<String>,
    allow: Vec<String>,
    disallow: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RobotsTxt {
    groups: Vec<RobotsGroup>,
    sitemaps: Vec<String>,
    crawl_delay: Option<f64>,
}

impl RobotsTxt {
    pub fn parse(content: &str) -> Self {
        let mut robots = Self::default();
        let mut current_agents: Vec<String> = Vec::new();
        let mut current_allow: Vec<String> = Vec::new();
        let mut current_disallow: Vec<String> = Vec::new();

        for raw_line in content.lines() {
            let line = raw_line.trim();
            let clean = match line.find('#') {
                Some(index) => line[..index].trim(),
                None => line,
            };
            if clean.is_empty() {
                continue;
            }
            let Some((directive, value)) = clean.split_once(':') else {
                continue;
            };
            let directive = directive.trim().to_ascii_lowercase();
            let value = value.trim();
            match directive.as_str() {
                "user-agent" => {
                    if !current_agents.is_empty()
                        && (!current_allow.is_empty() || !current_disallow.is_empty())
                    {
                        robots.groups.push(RobotsGroup {
                            user_agents: std::mem::take(&mut current_agents),
                            allow: std::mem::take(&mut current_allow),
                            disallow: std::mem::take(&mut current_disallow),
                        });
                    }
                    if !current_allow.is_empty() || !current_disallow.is_empty() {
                        current_agents = vec![value.to_string()];
                        current_allow.clear();
                        current_disallow.clear();
                    } else {
                        current_agents.push(value.to_string());
                    }
                }
                "allow" if !value.is_empty() => current_allow.push(normalize_pattern(value)),
                "disallow" if !value.is_empty() => current_disallow.push(normalize_pattern(value)),
                "sitemap" if !value.is_empty() => robots.sitemaps.push(value.to_string()),
                "crawl-delay" => {
                    if let Ok(delay) = value.parse::<f64>() {
                        if delay >= 0.0 && matches_user_agent(&current_agents, "*") {
                            robots.crawl_delay = Some(delay);
                        }
                    }
                }
                _ => {}
            }
        }
        if !current_agents.is_empty() && (!current_allow.is_empty() || !current_disallow.is_empty())
        {
            robots.groups.push(RobotsGroup {
                user_agents: current_agents,
                allow: current_allow,
                disallow: current_disallow,
            });
        }
        robots
    }

    pub fn is_allowed(&self, url: &str, user_agent: &str) -> bool {
        let Some(groups) = self.select_groups(user_agent) else {
            return true;
        };
        let path = url::Url::parse(url)
            .ok()
            .map(|parsed| parsed.path().to_string())
            .unwrap_or_else(|| "/".into());

        let mut best_allow: Option<(usize, usize)> = None;
        let mut best_disallow: Option<(usize, usize)> = None;
        for group in groups {
            for pattern in &group.allow {
                if let Some(len) = match_pattern(pattern, &path) {
                    let candidate = (len, 1);
                    if best_allow.is_none_or(|best| candidate.0 > best.0) {
                        best_allow = Some(candidate);
                    }
                }
            }
            for pattern in &group.disallow {
                if let Some(len) = match_pattern(pattern, &path) {
                    let candidate = (len, 0);
                    if best_disallow.is_none_or(|best| candidate.0 > best.0) {
                        best_disallow = Some(candidate);
                    }
                }
            }
        }
        match (best_allow, best_disallow) {
            (Some(allow), Some(disallow)) => allow.0 >= disallow.0,
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => true,
        }
    }

    pub fn sitemaps(&self) -> &[String] {
        &self.sitemaps
    }

    pub fn crawl_delay(&self) -> Option<f64> {
        self.crawl_delay
    }

    fn select_groups(&self, user_agent: &str) -> Option<Vec<&RobotsGroup>> {
        let ua_lower = user_agent.to_ascii_lowercase();
        let matching: Vec<&RobotsGroup> = self
            .groups
            .iter()
            .filter(|group| {
                group
                    .user_agents
                    .iter()
                    .any(|agent| agent == "*" || ua_lower.contains(&agent.to_ascii_lowercase()))
            })
            .collect();
        if matching.is_empty() {
            return None;
        }
        Some(matching)
    }
}

fn matches_user_agent(agents: &[String], target: &str) -> bool {
    agents.iter().any(|agent| agent == target)
}

fn normalize_pattern(pattern: &str) -> String {
    if pattern.starts_with('/') {
        pattern.to_string()
    } else {
        format!("/{pattern}")
    }
}

fn match_pattern(pattern: &str, path: &str) -> Option<usize> {
    let anchored_end = pattern.ends_with('$');
    let core = if anchored_end {
        &pattern[..pattern.len() - 1]
    } else {
        pattern
    };
    if core.is_empty() {
        return None;
    }
    let regex_src = format!(
        "^{}{}",
        regex::escape(core).replace("\\*", ".*"),
        if anchored_end { "$" } else { "" }
    );
    let re = Regex::new(&regex_src).ok()?;
    if re.is_match(path) {
        Some(core.len())
    } else {
        None
    }
}

pub struct RobotsHandler {
    parsers: HashMap<String, RobotsTxt>,
    user_agent: String,
}

impl RobotsHandler {
    pub fn new(user_agent: impl Into<String>) -> Self {
        Self {
            parsers: HashMap::new(),
            user_agent: user_agent.into(),
        }
    }

    pub fn is_allowed(
        &mut self,
        url: &str,
        fetch_content: impl FnOnce(&str) -> Option<String>,
    ) -> bool {
        let domain = url::Url::parse(url)
            .ok()
            .and_then(|parsed| parsed.host_str().map(str::to_string))
            .unwrap_or_default();
        if !self.parsers.contains_key(&domain) {
            let content = fetch_content(&domain);
            let robots = content
                .map(|text| RobotsTxt::parse(&text))
                .unwrap_or_default();
            self.parsers.insert(domain.clone(), robots);
        }
        self.parsers
            .get(&domain)
            .map(|robots| robots.is_allowed(url, &self.user_agent))
            .unwrap_or(true)
    }

    pub fn sitemaps(&self, domain: &str) -> &[String] {
        self.parsers
            .get(domain)
            .map(RobotsTxt::sitemaps)
            .unwrap_or(&[])
    }

    pub fn reset(&mut self) {
        self.parsers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# Example robots.txt
User-agent: *
Disallow: /private/
Allow: /private/public.html
Disallow: /admin

User-agent: BadBot
Disallow: /

Sitemap: https://example.com/sitemap.xml
"#;

    #[test]
    fn allows_by_default_without_rules() {
        let robots = RobotsTxt::parse("");
        assert!(robots.is_allowed("https://example.com/anything", "HuntProxy"));
    }

    #[test]
    fn disallowed_paths_blocked() {
        let robots = RobotsTxt::parse(SAMPLE);
        assert!(!robots.is_allowed("https://example.com/private/secret", "HuntProxy"));
        assert!(!robots.is_allowed("https://example.com/admin", "HuntProxy"));
    }

    #[test]
    fn allow_overrides_disallow_on_longer_match() {
        let robots = RobotsTxt::parse(SAMPLE);
        assert!(robots.is_allowed("https://example.com/private/public.html", "HuntProxy"));
    }

    #[test]
    fn user_agent_specific_group_wins() {
        let robots = RobotsTxt::parse(SAMPLE);
        assert!(!robots.is_allowed("https://example.com/anything", "BadBot/1.0"));
        assert!(robots.is_allowed("https://example.com/anything", "GoodBot"));
    }

    #[test]
    fn sitemaps_collected() {
        let robots = RobotsTxt::parse(SAMPLE);
        assert_eq!(
            robots.sitemaps(),
            &["https://example.com/sitemap.xml".to_string()]
        );
    }

    #[test]
    fn handler_caches_per_domain() {
        let mut handler = RobotsHandler::new("HuntProxy");
        let mut calls = 0;
        let allowed = handler.is_allowed("https://example.com/a", |_| {
            calls += 1;
            Some("User-agent: *\nDisallow: /a".into())
        });
        assert!(!allowed);
        let allowed = handler.is_allowed("https://example.com/b", |_| {
            calls += 1;
            None
        });
        assert!(allowed);
        assert_eq!(calls, 1);
    }
}
