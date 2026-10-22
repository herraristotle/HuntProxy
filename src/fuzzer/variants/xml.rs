//! XML node extraction and injection.

use super::{InjectionPoint, VariantType};
use once_cell::sync::Lazy;
use regex::Regex;

static XML_TAG: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"<([a-zA-Z0-9_-]+)[^>]*>([^<]*)</[a-zA-Z0-9_-]+>").expect("valid XML regex")
});

pub struct XmlVariant;

impl XmlVariant {
    /// Extract injectable text nodes from XML.
    pub fn extract(body: &[u8]) -> Vec<InjectionPoint> {
        let Ok(text) = std::str::from_utf8(body) else {
            return Vec::new();
        };

        let mut points = Vec::new();

        for caps in XML_TAG.captures_iter(text) {
            let tag_name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            let content = caps.get(2).map(|m| m.as_str()).unwrap_or("");

            if !content.trim().is_empty() && !content.contains('<') {
                points.push(InjectionPoint {
                    name: tag_name.to_string(),
                    variant_type: VariantType::Xml,
                    location: format!("xml:{tag_name}"),
                    original_value: content.to_string(),
                    content_type: Some("application/xml".to_string()),
                });
            }
        }

        points
    }

    /// Apply payload to XML node.
    pub fn apply(body: &[u8], location: &str, payload: &str) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(body) else {
            return body.to_vec();
        };

        let tag_name = location.strip_prefix("xml:").unwrap_or(location);
        let Ok(tag_regex) = Regex::new(&format!(r"(<{tag_name}[^>]*>)([^<]*)(</{tag_name}>)"))
        else {
            return body.to_vec();
        };

        // Substitute via closure: a string replacement would interpret `$1`/`$3`
        // in the *payload* as capture references and corrupt the payload.
        let result = tag_regex.replace(text, |caps: &regex::Captures<'_>| {
            format!("{}{}{}", &caps[1], payload, &caps[3])
        });
        result.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_xml_nodes() {
        let body = b"<user>admin</user><role>viewer</role>";
        let points = XmlVariant::extract(body);

        assert_eq!(points.len(), 2);
        assert!(points
            .iter()
            .any(|p| p.name == "user" && p.original_value == "admin"));
        assert!(points
            .iter()
            .any(|p| p.name == "role" && p.original_value == "viewer"));
    }

    #[test]
    fn apply_payload_to_xml() {
        let body = b"<user>admin</user>";
        let result = XmlVariant::apply(body, "xml:user", "attacker");
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains("<user>attacker</user>"));
    }
}
