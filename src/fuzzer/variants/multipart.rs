//! Multipart form field extraction.

use super::{InjectionPoint, VariantType};

pub struct MultipartVariant;

impl MultipartVariant {
    /// Extract form fields from multipart body.
    pub fn extract(body: &[u8], boundary: &str) -> Vec<InjectionPoint> {
        let Ok(text) = std::str::from_utf8(body) else {
            return Vec::new();
        };

        let mut points = Vec::new();
        let boundary_str = format!("--{boundary}");
        let parts = text.split(&boundary_str);

        for part in parts.skip(1) {
            if let Some(field_name) = extract_field_name(part) {
                if let Some(value) = extract_field_value(part) {
                    points.push(InjectionPoint {
                        name: field_name.clone(),
                        variant_type: VariantType::Multipart,
                        location: format!("multipart:{field_name}"),
                        original_value: value,
                        content_type: Some("multipart/form-data".to_string()),
                    });
                }
            }
        }

        points
    }
}

fn extract_field_name(part: &str) -> Option<String> {
    part.lines()
        .find(|line| line.contains("Content-Disposition"))
        .and_then(|line| {
            line.split("name=\"")
                .nth(1)?
                .split('"')
                .next()
                .map(String::from)
        })
}

fn extract_field_value(part: &str) -> Option<String> {
    let lines: Vec<&str> = part.lines().collect();
    let mut in_body = false;
    let mut value_lines = Vec::new();

    for line in lines {
        if in_body {
            value_lines.push(line);
        } else if line.is_empty() {
            in_body = true;
        }
    }

    if value_lines.is_empty() {
        None
    } else {
        Some(value_lines.join("\n").trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_multipart_fields() {
        let body = b"--boundary\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nadmin\r\n--boundary--";
        let points = MultipartVariant::extract(body, "boundary");

        assert_eq!(points.len(), 1);
        assert_eq!(points[0].name, "user");
        assert_eq!(points[0].original_value, "admin");
    }
}
