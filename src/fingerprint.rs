//! Technology stack fingerprinting for web applications.
//! Detects frameworks, libraries, servers from headers, HTML, and JavaScript.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Technology {
    pub name: String,
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub confidence: u8, // 0-100
}

#[derive(Debug, Clone, Serialize)]
pub struct Fingerprint {
    pub technologies: Vec<Technology>,
    pub server: Option<String>,
    pub powered_by: Vec<String>,
}

struct Pattern {
    name: &'static str,
    category: &'static str,
    header_checks: Vec<(&'static str, &'static str)>, // (header_name, regex)
    html_patterns: Vec<&'static str>,
    js_patterns: Vec<&'static str>,
    version_pattern: Option<&'static str>,
}

static PATTERNS: Lazy<Vec<Pattern>> = Lazy::new(|| {
    vec![
        // Frameworks
        Pattern {
            name: "React",
            category: "JavaScript framework",
            header_checks: vec![],
            html_patterns: vec![r"data-reactroot", r"data-react-", r"__REACT_"],
            js_patterns: vec![r"React\.version", r"react-dom", r"_reactRootContainer"],
            version_pattern: Some(r#"React\.version\s*=\s*["']([0-9.]+)["']"#),
        },
        Pattern {
            name: "Vue.js",
            category: "JavaScript framework",
            header_checks: vec![],
            html_patterns: vec![r"v-cloak", r"v-if=", r"v-for=", r"data-v-"],
            js_patterns: vec![r"Vue\.version", r"__VUE__"],
            version_pattern: Some(r#"Vue\.version\s*=\s*["']([0-9.]+)["']"#),
        },
        Pattern {
            name: "Angular",
            category: "JavaScript framework",
            header_checks: vec![],
            html_patterns: vec![r"ng-app", r"ng-controller", r"ng-version"],
            js_patterns: vec![r"angular\.version", r"@angular/core"],
            version_pattern: Some(r#"ng-version="([0-9.]+)"#),
        },
        Pattern {
            name: "Next.js",
            category: "JavaScript framework",
            header_checks: vec![("x-powered-by", r"Next\.js")],
            html_patterns: vec![r"__NEXT_DATA__", r"/_next/static/"],
            js_patterns: vec![r"__NEXT_DATA__", r"next/dist"],
            version_pattern: None,
        },
        Pattern {
            name: "Nuxt.js",
            category: "JavaScript framework",
            header_checks: vec![],
            html_patterns: vec![r"__NUXT__"],
            js_patterns: vec![r"__NUXT__", r"nuxt\."],
            version_pattern: None,
        },
        // Backend frameworks
        Pattern {
            name: "Express",
            category: "Web framework",
            header_checks: vec![("x-powered-by", r"Express")],
            html_patterns: vec![],
            js_patterns: vec![],
            version_pattern: None,
        },
        Pattern {
            name: "Laravel",
            category: "Web framework",
            header_checks: vec![("set-cookie", r"laravel_session")],
            html_patterns: vec![r"Laravel", r"_token"],
            js_patterns: vec![],
            version_pattern: None,
        },
        Pattern {
            name: "Django",
            category: "Web framework",
            header_checks: vec![("set-cookie", r"csrftoken"), ("set-cookie", r"sessionid")],
            html_patterns: vec![r"csrfmiddlewaretoken"],
            js_patterns: vec![],
            version_pattern: None,
        },
        Pattern {
            name: "Ruby on Rails",
            category: "Web framework",
            header_checks: vec![("set-cookie", r"_.*_session")],
            html_patterns: vec![r"csrf-param", r"csrf-token"],
            js_patterns: vec![],
            version_pattern: None,
        },
        Pattern {
            name: "Spring Boot",
            category: "Web framework",
            header_checks: vec![("set-cookie", r"JSESSIONID")],
            html_patterns: vec![],
            js_patterns: vec![],
            version_pattern: None,
        },
        Pattern {
            name: "ASP.NET",
            category: "Web framework",
            header_checks: vec![("x-aspnet-version", r".*"), ("x-powered-by", r"ASP\.NET")],
            html_patterns: vec![r"__VIEWSTATE", r"asp\.net"],
            js_patterns: vec![],
            version_pattern: Some(r"X-AspNet-Version:\s*([0-9.]+)"),
        },
        // CMS
        Pattern {
            name: "WordPress",
            category: "CMS",
            header_checks: vec![],
            html_patterns: vec![r"wp-content/", r"wp-includes/", r"wordpress", r"wp-json/"],
            js_patterns: vec![],
            version_pattern: Some(r#"ver=([0-9.]+)"#),
        },
        Pattern {
            name: "Drupal",
            category: "CMS",
            header_checks: vec![("x-drupal-cache", r".*"), ("x-generator", r"Drupal")],
            html_patterns: vec![r"Drupal\.settings", r"/sites/default/files/"],
            js_patterns: vec![r"Drupal\."],
            version_pattern: None,
        },
        Pattern {
            name: "Joomla",
            category: "CMS",
            header_checks: vec![],
            html_patterns: vec![r"/media/jui/", r"joomla", r"option=com_"],
            js_patterns: vec![],
            version_pattern: None,
        },
        // Libraries
        Pattern {
            name: "jQuery",
            category: "JavaScript library",
            header_checks: vec![],
            html_patterns: vec![],
            js_patterns: vec![r"jquery", r"jQuery\.fn\.jquery"],
            version_pattern: Some(r#"jQuery\.fn\.jquery\s*=\s*["']([0-9.]+)["']"#),
        },
        Pattern {
            name: "Bootstrap",
            category: "CSS framework",
            header_checks: vec![],
            html_patterns: vec![r"bootstrap", r#"class=["'][^"']*\bbs-"#],
            js_patterns: vec![r"bootstrap"],
            version_pattern: Some(r"bootstrap[/\\]([0-9.]+)"),
        },
        Pattern {
            name: "Tailwind CSS",
            category: "CSS framework",
            header_checks: vec![],
            html_patterns: vec![
                r"tailwind",
                r#"class=["'][^"']*\b(?:flex|grid|p-|m-|w-|h-)"#,
            ],
            js_patterns: vec![],
            version_pattern: None,
        },
        // Servers
        Pattern {
            name: "nginx",
            category: "Web server",
            header_checks: vec![("server", r"nginx")],
            html_patterns: vec![],
            js_patterns: vec![],
            version_pattern: Some(r"nginx/([0-9.]+)"),
        },
        Pattern {
            name: "Apache",
            category: "Web server",
            header_checks: vec![("server", r"Apache")],
            html_patterns: vec![],
            js_patterns: vec![],
            version_pattern: Some(r"Apache/([0-9.]+)"),
        },
        Pattern {
            name: "Cloudflare",
            category: "CDN",
            header_checks: vec![("server", r"cloudflare"), ("cf-ray", r".*")],
            html_patterns: vec![],
            js_patterns: vec![],
            version_pattern: None,
        },
        // Analytics
        Pattern {
            name: "Google Analytics",
            category: "Analytics",
            header_checks: vec![],
            html_patterns: vec![r"google-analytics\.com", r"gtag\(", r"ga\("],
            js_patterns: vec![r"google-analytics\.com/analytics\.js", r"gtag\("],
            version_pattern: None,
        },
    ]
});

pub fn fingerprint_from_response(headers: &[(String, String)], body: Option<&str>) -> Fingerprint {
    let mut detected = HashMap::<&'static str, Technology>::new();
    let mut server = None;
    let mut powered_by = Vec::new();

    // Normalize headers
    let headers_map: HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    // Extract server/powered-by directly
    if let Some(s) = headers_map.get("server") {
        server = Some(s.clone());
    }
    if let Some(pb) = headers_map.get("x-powered-by") {
        powered_by.push(pb.clone());
    }

    for pattern in PATTERNS.iter() {
        let mut matched = false;
        let mut confidence = 0u8;
        let mut version = None;

        // Check headers
        for (header_name, header_regex) in &pattern.header_checks {
            if let Some(header_value) = headers_map.get(&header_name.to_lowercase()) {
                if let Ok(re) = Regex::new(header_regex) {
                    if re.is_match(header_value) {
                        matched = true;
                        confidence = confidence.saturating_add(40);

                        // Try to extract version
                        if let Some(version_pat) = pattern.version_pattern {
                            if let Ok(ver_re) = Regex::new(version_pat) {
                                if let Some(caps) = ver_re.captures(header_value) {
                                    version = caps.get(1).map(|m| m.as_str().to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check body patterns
        if let Some(body_text) = body {
            // HTML patterns
            for html_pat in &pattern.html_patterns {
                if let Ok(re) = Regex::new(html_pat) {
                    if re.is_match(body_text) {
                        matched = true;
                        confidence = confidence.saturating_add(30);

                        // Try to extract version
                        if version.is_none() {
                            if let Some(version_pat) = pattern.version_pattern {
                                if let Ok(ver_re) = Regex::new(version_pat) {
                                    if let Some(caps) = ver_re.captures(body_text) {
                                        version = caps.get(1).map(|m| m.as_str().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // JS patterns
            for js_pat in &pattern.js_patterns {
                if let Ok(re) = Regex::new(js_pat) {
                    if re.is_match(body_text) {
                        matched = true;
                        confidence = confidence.saturating_add(25);

                        if version.is_none() {
                            if let Some(version_pat) = pattern.version_pattern {
                                if let Ok(ver_re) = Regex::new(version_pat) {
                                    if let Some(caps) = ver_re.captures(body_text) {
                                        version = caps.get(1).map(|m| m.as_str().to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if matched {
            // Cap confidence at 100
            confidence = confidence.min(100);

            detected.insert(
                pattern.name,
                Technology {
                    name: pattern.name.to_string(),
                    category: pattern.category.to_string(),
                    version,
                    confidence,
                },
            );
        }
    }

    let mut technologies: Vec<Technology> = detected.into_values().collect();
    technologies.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.name.cmp(&b.name))
    });

    Fingerprint {
        technologies,
        server,
        powered_by,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_react_detection() {
        let headers = vec![];
        let body = r#"<div id="root" data-reactroot="">React app</div>"#;
        let fp = fingerprint_from_response(&headers, Some(body));
        assert!(fp.technologies.iter().any(|t| t.name == "React"));
    }

    #[test]
    fn test_nginx_detection() {
        let headers = vec![("server".to_string(), "nginx/1.21.0".to_string())];
        let fp = fingerprint_from_response(&headers, None);
        assert!(fp.technologies.iter().any(|t| t.name == "nginx"));
        assert_eq!(fp.server, Some("nginx/1.21.0".to_string()));
    }

    #[test]
    fn test_wordpress_detection() {
        let headers = vec![];
        let body =
            r#"<link rel="stylesheet" href="/wp-content/themes/twentytwenty/style.css?ver=6.4">"#;
        let fp = fingerprint_from_response(&headers, Some(body));
        assert!(fp.technologies.iter().any(|t| t.name == "WordPress"));
    }
}
