//! Form discovery and auto-submission for spider enhancement.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormField {
    pub name: String,
    pub field_type: String,
    pub value: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredForm {
    pub action: String,
    pub method: String,
    pub fields: Vec<FormField>,
    pub enctype: String,
}

/// Extract forms from HTML for auto-submission during crawling.
pub fn extract_forms(base_url: &str, html: &str) -> Vec<DiscoveredForm> {
    let Ok(base) = Url::parse(base_url) else {
        return Vec::new();
    };

    let mut forms = Vec::new();
    let form_regex = regex::Regex::new(r#"(?is)<form\b([^>]*)>(.*?)</form>"#).unwrap();

    for form_cap in form_regex.captures_iter(html) {
        let attrs = form_cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = form_cap.get(2).map(|m| m.as_str()).unwrap_or("");

        let action = extract_attribute(attrs, "action")
            .and_then(|a| base.join(&a).ok())
            .map(|u| u.to_string())
            .unwrap_or_else(|| base.to_string());

        let method = extract_attribute(attrs, "method")
            .unwrap_or_else(|| "GET".to_string())
            .to_uppercase();

        let enctype = extract_attribute(attrs, "enctype")
            .unwrap_or_else(|| "application/x-www-form-urlencoded".to_string());

        let fields = extract_form_fields(body);

        forms.push(DiscoveredForm {
            action,
            method,
            fields,
            enctype,
        });
    }

    forms
}

fn extract_form_fields(body: &str) -> Vec<FormField> {
    let mut fields = Vec::new();

    // Input fields
    let input_regex = regex::Regex::new(r#"(?is)<input\b([^>]*)>"#).unwrap();
    for cap in input_regex.captures_iter(body) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");

        if let Some(name) = extract_attribute(attrs, "name") {
            let field_type = extract_attribute(attrs, "type")
                .unwrap_or_else(|| "text".to_string())
                .to_lowercase();

            // Skip submit/reset/button
            if matches!(field_type.as_str(), "submit" | "reset" | "button" | "image") {
                continue;
            }

            let value = extract_attribute(attrs, "value");
            let required = attrs.contains("required");

            fields.push(FormField {
                name,
                field_type,
                value,
                required,
            });
        }
    }

    // Textarea fields
    let textarea_regex =
        regex::Regex::new(r#"(?is)<textarea\b([^>]*)>([^<]*)</textarea>"#).unwrap();
    for cap in textarea_regex.captures_iter(body) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");

        if let Some(name) = extract_attribute(attrs, "name") {
            let value = cap.get(2).map(|m| m.as_str().trim().to_string());
            let required = attrs.contains("required");

            fields.push(FormField {
                name,
                field_type: "textarea".to_string(),
                value,
                required,
            });
        }
    }

    // Select fields
    let select_regex = regex::Regex::new(r#"(?is)<select\b([^>]*)>(.*?)</select>"#).unwrap();
    for cap in select_regex.captures_iter(body) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let options_body = cap.get(2).map(|m| m.as_str()).unwrap_or("");

        if let Some(name) = extract_attribute(attrs, "name") {
            let required = attrs.contains("required");

            // Extract first option value as default
            let value = extract_first_option_value(options_body);

            fields.push(FormField {
                name,
                field_type: "select".to_string(),
                value,
                required,
            });
        }
    }

    fields
}

fn extract_attribute(attrs: &str, name: &str) -> Option<String> {
    let pattern = format!(r#"(?i)\b{}\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#, name);
    let regex = regex::Regex::new(&pattern).ok()?;

    regex.captures(attrs).and_then(|cap| {
        cap.get(1)
            .or_else(|| cap.get(2))
            .or_else(|| cap.get(3))
            .map(|m| m.as_str().to_string())
    })
}

fn extract_first_option_value(options_body: &str) -> Option<String> {
    let option_regex = regex::Regex::new(r#"(?is)<option\b([^>]*)>([^<]*)</option>"#).ok()?;

    for cap in option_regex.captures_iter(options_body) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");

        // Prefer explicit value attribute
        if let Some(value) = extract_attribute(attrs, "value") {
            return Some(value);
        }

        // Fall back to option text content
        if let Some(text) = cap.get(2) {
            let text = text.as_str().trim();
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
    }

    None
}

/// Generate default form values for auto-submission.
pub fn generate_form_values(form: &DiscoveredForm) -> HashMap<String, String> {
    let mut values = HashMap::new();

    for field in &form.fields {
        let default_value = match field.field_type.as_str() {
            "text" | "search" | "url" | "tel" => "test",
            "email" => "test@example.com",
            "password" => "password123",
            "number" => "0",
            "date" => "2024-01-01",
            "time" => "12:00",
            "datetime-local" => "2024-01-01T12:00",
            "month" => "2024-01",
            "week" => "2024-W01",
            "color" => "#000000",
            "checkbox" => "on",
            "radio" => "on",
            "hidden" => field.value.as_deref().unwrap_or(""),
            "textarea" => "test content",
            "select" => field.value.as_deref().unwrap_or(""),
            _ => "",
        };

        values.insert(
            field.name.clone(),
            field
                .value
                .clone()
                .unwrap_or_else(|| default_value.to_string()),
        );
    }

    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_simple_form() {
        let html = r#"
            <form action="/login" method="POST">
                <input type="text" name="username" required>
                <input type="password" name="password" required>
                <input type="submit" value="Login">
            </form>
        "#;

        let forms = extract_forms("https://example.com", html);
        assert_eq!(forms.len(), 1);

        let form = &forms[0];
        assert_eq!(form.action, "https://example.com/login");
        assert_eq!(form.method, "POST");
        assert_eq!(form.fields.len(), 2);
        assert!(form.fields.iter().any(|f| f.name == "username"));
        assert!(form.fields.iter().any(|f| f.name == "password"));
    }

    #[test]
    fn extract_form_with_select() {
        let html = r#"
            <form action="/search">
                <select name="category">
                    <option value="all">All</option>
                    <option value="books">Books</option>
                </select>
                <input type="text" name="query">
            </form>
        "#;

        let forms = extract_forms("https://example.com", html);
        assert_eq!(forms.len(), 1);

        let form = &forms[0];
        assert_eq!(form.fields.len(), 2);

        let select_field = form.fields.iter().find(|f| f.name == "category").unwrap();
        assert_eq!(select_field.field_type, "select");
        assert_eq!(select_field.value.as_deref(), Some("all"));
    }

    #[test]
    fn generate_default_values() {
        let form = DiscoveredForm {
            action: "https://example.com/submit".to_string(),
            method: "POST".to_string(),
            enctype: "application/x-www-form-urlencoded".to_string(),
            fields: vec![
                FormField {
                    name: "email".to_string(),
                    field_type: "email".to_string(),
                    value: None,
                    required: true,
                },
                FormField {
                    name: "age".to_string(),
                    field_type: "number".to_string(),
                    value: None,
                    required: false,
                },
            ],
        };

        let values = generate_form_values(&form);
        assert_eq!(values.get("email").unwrap(), "test@example.com");
        assert_eq!(values.get("age").unwrap(), "0");
    }
}
