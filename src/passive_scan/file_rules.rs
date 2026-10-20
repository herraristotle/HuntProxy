//! Sensitive file and directory detection rules.

use super::{PassiveRule, PassiveRuleResult, PassiveScanExchange, RuleSeverity};
use async_trait::async_trait;

struct SensitiveFile {
    path: &'static str,
    name: &'static str,
    severity: RuleSeverity,
    description: &'static str,
}

static SENSITIVE_FILES: &[SensitiveFile] = &[
    // Version control
    SensitiveFile {
        path: ".git/config",
        name: "Git Config Exposed",
        severity: RuleSeverity::High,
        description: "Git configuration file exposed. May contain repository URLs, usernames, and internal paths.",
    },
    SensitiveFile {
        path: ".git/HEAD",
        name: "Git Repository Exposed",
        severity: RuleSeverity::High,
        description: "Git repository metadata exposed. Entire repository history may be downloadable.",
    },
    SensitiveFile {
        path: ".svn/entries",
        name: "SVN Repository Exposed",
        severity: RuleSeverity::High,
        description: "Subversion repository metadata exposed.",
    },
    SensitiveFile {
        path: ".hg/",
        name: "Mercurial Repository Exposed",
        severity: RuleSeverity::High,
        description: "Mercurial repository exposed.",
    },
    // Environment files
    SensitiveFile {
        path: ".env",
        name: "Environment File Exposed",
        severity: RuleSeverity::Critical,
        description: "Environment configuration file exposed. Typically contains database credentials, API keys, and secrets.",
    },
    SensitiveFile {
        path: ".env.local",
        name: "Local Environment File Exposed",
        severity: RuleSeverity::Critical,
        description: "Local environment configuration exposed.",
    },
    SensitiveFile {
        path: ".env.production",
        name: "Production Environment File Exposed",
        severity: RuleSeverity::Critical,
        description: "Production environment configuration exposed.",
    },
    // Configuration files
    SensitiveFile {
        path: "web.config",
        name: "IIS Web Config Exposed",
        severity: RuleSeverity::High,
        description: "IIS web.config file exposed. May contain database connection strings and authentication settings.",
    },
    SensitiveFile {
        path: "Web.config",
        name: "IIS Web Config Exposed",
        severity: RuleSeverity::High,
        description: "IIS web.config file exposed (capitalized).",
    },
    SensitiveFile {
        path: "phpinfo.php",
        name: "PHP Info Page",
        severity: RuleSeverity::Medium,
        description: "PHP info page exposed. Reveals server configuration, loaded modules, and environment variables.",
    },
    SensitiveFile {
        path: "info.php",
        name: "PHP Info Page",
        severity: RuleSeverity::Medium,
        description: "PHP info page exposed.",
    },
    // macOS files
    SensitiveFile {
        path: ".DS_Store",
        name: "macOS .DS_Store File",
        severity: RuleSeverity::Low,
        description: "macOS .DS_Store file exposed. May reveal directory structure and file names.",
    },
    // Backup files
    SensitiveFile {
        path: ".bak",
        name: "Backup File Exposed",
        severity: RuleSeverity::Medium,
        description: "Backup file exposed. May contain old source code or configuration.",
    },
    SensitiveFile {
        path: ".old",
        name: "Old File Exposed",
        severity: RuleSeverity::Medium,
        description: "Old/archived file exposed.",
    },
    SensitiveFile {
        path: ".orig",
        name: "Original File Exposed",
        severity: RuleSeverity::Medium,
        description: "Original file exposed.",
    },
    SensitiveFile {
        path: ".backup",
        name: "Backup File Exposed",
        severity: RuleSeverity::Medium,
        description: "Backup file exposed.",
    },
    // Archives
    SensitiveFile {
        path: ".zip",
        name: "ZIP Archive Exposed",
        severity: RuleSeverity::Medium,
        description: "ZIP archive exposed. May contain source code or sensitive files.",
    },
    SensitiveFile {
        path: ".tar.gz",
        name: "Tar Archive Exposed",
        severity: RuleSeverity::Medium,
        description: "Tar archive exposed.",
    },
    SensitiveFile {
        path: ".sql",
        name: "SQL Dump File Exposed",
        severity: RuleSeverity::Critical,
        description: "SQL database dump exposed. May contain entire database with user credentials.",
    },
    // Source maps
    SensitiveFile {
        path: ".map",
        name: "Source Map Exposed",
        severity: RuleSeverity::Low,
        description: "JavaScript source map exposed. Reveals original unminified source code.",
    },
    // Logs
    SensitiveFile {
        path: "error.log",
        name: "Error Log Exposed",
        severity: RuleSeverity::Medium,
        description: "Error log file exposed. May contain stack traces and internal paths.",
    },
    SensitiveFile {
        path: "access.log",
        name: "Access Log Exposed",
        severity: RuleSeverity::Medium,
        description: "Access log exposed. May contain user activity and IP addresses.",
    },
    SensitiveFile {
        path: "debug.log",
        name: "Debug Log Exposed",
        severity: RuleSeverity::Medium,
        description: "Debug log exposed.",
    },
    // Config files
    SensitiveFile {
        path: "config.json",
        name: "Configuration File Exposed",
        severity: RuleSeverity::High,
        description: "Configuration file exposed.",
    },
    SensitiveFile {
        path: "config.yml",
        name: "YAML Config Exposed",
        severity: RuleSeverity::High,
        description: "YAML configuration file exposed.",
    },
    SensitiveFile {
        path: "settings.py",
        name: "Django Settings Exposed",
        severity: RuleSeverity::Critical,
        description: "Django settings file exposed. Contains SECRET_KEY and database credentials.",
    },
    // Documentation
    SensitiveFile {
        path: "robots.txt",
        name: "Robots.txt",
        severity: RuleSeverity::Info,
        description: "Robots.txt may reveal admin paths and hidden directories.",
    },
    SensitiveFile {
        path: "sitemap.xml",
        name: "Sitemap",
        severity: RuleSeverity::Info,
        description: "Sitemap may reveal internal URL structure.",
    },
];

pub struct SensitiveFileDetection;

#[async_trait]
impl PassiveRule for SensitiveFileDetection {
    fn id(&self) -> &str {
        "sensitive-file-exposed"
    }

    fn name(&self) -> &str {
        "Sensitive File Exposed"
    }

    fn enabled(&self) -> bool {
        true
    }

    async fn scan(&self, exchange: &PassiveScanExchange) -> Option<PassiveRuleResult> {
        let url_lower = exchange.url.to_lowercase();
        let status = exchange.status?;

        // Only check successful responses
        if !(200..300).contains(&status) {
            return None;
        }

        for file in SENSITIVE_FILES {
            if url_lower.ends_with(file.path) || url_lower.contains(&format!("/{}", file.path)) {
                return Some(PassiveRuleResult {
                    rule_id: format!("{}-{}", self.id(), file.path.replace(['/', '.'], "-")),
                    name: file.name.to_string(),
                    severity: file.severity,
                    confidence: 95,
                    cwe_id: Some(538), // CWE-538: Insertion of Sensitive Information into Externally-Accessible File
                    description: file.description.to_string(),
                    evidence: format!("Accessible at: {}", exchange.url),
                    references: vec![
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information".to_string(),
                    ],
                });
            }
        }

        None
    }
}

pub fn load_file_rules() -> Vec<Box<dyn PassiveRule + Send + Sync>> {
    vec![Box::new(SensitiveFileDetection)]
}
