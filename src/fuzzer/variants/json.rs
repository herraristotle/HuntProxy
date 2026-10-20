//! JSON body field extraction and injection.

use super::{InjectionPoint, VariantType};
use serde_json::Value;

pub struct JsonVariant;

impl JsonVariant {
    /// Extract all injectable fields from JSON body.
    pub fn extract(body: &[u8]) -> Vec<InjectionPoint> {
        let Ok(text) = std::str::from_utf8(body) else {
            return Vec::new();
        };

        let Ok(json): Result<Value, _> = serde_json::from_str(text) else {
            return Vec::new();
        };

        let mut points = Vec::new();
        extract_fields(&json, "", &mut points);
        points
    }

    /// Apply payload to specific JSON field path.
    pub fn apply(body: &[u8], location: &str, payload: &str) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(body) else {
            return body.to_vec();
        };

        let Ok(mut json): Result<Value, _> = serde_json::from_str(text) else {
            return body.to_vec();
        };

        // location format: "json:user.name" or "json:items[0].id"
        let path = location.strip_prefix("json:").unwrap_or(location);
        set_value_at_path(&mut json, path, payload);

        serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
    }
}

/// Recursively extract all string/number fields from JSON.
fn extract_fields(value: &Value, prefix: &str, points: &mut Vec<InjectionPoint>) {
    match value {
        Value::Object(map) => {
            for (key, val) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };

                match val {
                    Value::String(s) => {
                        points.push(InjectionPoint {
                            name: path.clone(),
                            variant_type: VariantType::Json,
                            location: format!("json:{}", path),
                            original_value: s.clone(),
                            content_type: Some("application/json".to_string()),
                        });
                    }
                    Value::Number(n) => {
                        points.push(InjectionPoint {
                            name: path.clone(),
                            variant_type: VariantType::Json,
                            location: format!("json:{}", path),
                            original_value: n.to_string(),
                            content_type: Some("application/json".to_string()),
                        });
                    }
                    Value::Bool(b) => {
                        points.push(InjectionPoint {
                            name: path.clone(),
                            variant_type: VariantType::Json,
                            location: format!("json:{}", path),
                            original_value: b.to_string(),
                            content_type: Some("application/json".to_string()),
                        });
                    }
                    Value::Object(_) => extract_fields(val, &path, points),
                    Value::Array(arr) => {
                        for (index, item) in arr.iter().enumerate() {
                            extract_fields(item, &format!("{}[{}]", path, index), points);
                        }
                    }
                    Value::Null => {}
                }
            }
        }
        Value::Array(arr) => {
            for (index, item) in arr.iter().enumerate() {
                let path = format!("{}[{}]", prefix, index);
                extract_fields(item, &path, points);
            }
        }
        _ => {}
    }
}

/// Set value at JSON path (supports nested objects and arrays).
fn set_value_at_path(json: &mut Value, path: &str, new_value: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = json;

    for (i, part) in parts.iter().enumerate() {
        let is_last = i == parts.len() - 1;

        // Handle array index: "items[0]"
        if let Some((key, index_str)) = part.split_once('[') {
            let index: usize = index_str.trim_end_matches(']').parse().unwrap_or(0);

            if !key.is_empty() {
                current = current.get_mut(key)?;
            }

            if let Some(arr) = current.as_array_mut() {
                if let Some(element) = arr.get_mut(index) {
                    if is_last {
                        *element = Value::String(new_value.to_string());
                        return;
                    }
                    current = element;
                }
            }
        } else if is_last {
            // Set final value
            if let Some(obj) = current.as_object_mut() {
                // Try to preserve type
                let typed_value = if new_value.parse::<i64>().is_ok() {
                    Value::Number(new_value.parse().unwrap())
                } else if new_value == "true" || new_value == "false" {
                    Value::Bool(new_value == "true")
                } else {
                    Value::String(new_value.to_string())
                };
                obj.insert(part.to_string(), typed_value);
            }
        } else {
            // Navigate deeper
            current = current.get_mut(*part)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_nested_json() {
        let body = br#"{"user": "admin", "profile": {"email": "test@example.com", "age": 30}}"#;
        let points = JsonVariant::extract(body);

        assert_eq!(points.len(), 3);
        assert!(points.iter().any(|p| p.name == "user" && p.original_value == "admin"));
        assert!(points.iter().any(|p| p.name == "profile.email"));
        assert!(points.iter().any(|p| p.name == "profile.age" && p.original_value == "30"));
    }

    #[test]
    fn apply_payload_to_nested_field() {
        let body = br#"{"user": "admin", "role": "viewer"}"#;
        let result = JsonVariant::apply(body, "json:role", "admin");
        let result_str = String::from_utf8(result).unwrap();

        assert!(result_str.contains(r#""role":"admin""#));
    }
}
