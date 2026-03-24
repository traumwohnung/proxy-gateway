//! Affinity parameters — the validated `meta` object from the proxy
//! authorization username.
//!
//! Values are restricted to strings and numbers (no booleans, nulls, arrays,
//! or nested objects).

use std::ops::Deref;

/// Validated affinity parameters.
///
/// A thin wrapper around `serde_json::Map<String, serde_json::Value>` that
/// guarantees all values are either strings or numbers.  Construct via
/// [`AffinityParams::parse`] (validates) or [`AffinityParams::new`] (empty).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(transparent)]
pub struct AffinityParams(serde_json::Map<String, serde_json::Value>);

impl AffinityParams {
    /// Create an empty set of affinity parameters.
    pub fn new() -> Self {
        Self(serde_json::Map::new())
    }

    /// Parse and validate a raw JSON map.
    ///
    /// Every value must be a string or number.  Returns a human-readable
    /// error message on the first invalid value.
    pub fn parse(map: serde_json::Map<String, serde_json::Value>) -> Result<Self, String> {
        for (key, val) in &map {
            match val {
                serde_json::Value::String(_) | serde_json::Value::Number(_) => {}
                serde_json::Value::Bool(_) => {
                    return Err(format!(
                        "'meta.{}' has a boolean value. Only string and number values are allowed.",
                        key
                    ));
                }
                serde_json::Value::Null => {
                    return Err(format!(
                        "'meta.{}' has a null value. Only string and number values are allowed.",
                        key
                    ));
                }
                serde_json::Value::Array(_) => {
                    return Err(format!(
                        "'meta.{}' has an array value. Only string and number values are allowed.",
                        key
                    ));
                }
                serde_json::Value::Object(_) => {
                    return Err(format!(
                        "'meta.{}' has a nested object value. Only string and number values are allowed.",
                        key
                    ));
                }
            }
        }
        Ok(Self(map))
    }

    /// Consume the wrapper and return the inner map.
    pub fn into_inner(self) -> serde_json::Map<String, serde_json::Value> {
        self.0
    }
}

impl Default for AffinityParams {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for AffinityParams {
    type Target = serde_json::Map<String, serde_json::Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let params = AffinityParams::new();
        assert!(params.is_empty());
    }

    #[test]
    fn test_valid_string_and_number() {
        let mut map = serde_json::Map::new();
        map.insert("app".into(), serde_json::Value::String("myapp".into()));
        map.insert("count".into(), serde_json::Value::Number(42.into()));
        let params = AffinityParams::parse(map).unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params["app"], "myapp");
    }

    #[test]
    fn test_rejects_boolean() {
        let mut map = serde_json::Map::new();
        map.insert("flag".into(), serde_json::Value::Bool(true));
        let err = AffinityParams::parse(map).unwrap_err();
        assert!(err.contains("meta.flag"));
        assert!(err.contains("boolean"));
    }

    #[test]
    fn test_rejects_null() {
        let mut map = serde_json::Map::new();
        map.insert("x".into(), serde_json::Value::Null);
        let err = AffinityParams::parse(map).unwrap_err();
        assert!(err.contains("meta.x"));
        assert!(err.contains("null"));
    }

    #[test]
    fn test_rejects_array() {
        let mut map = serde_json::Map::new();
        map.insert("list".into(), serde_json::Value::Array(vec![]));
        let err = AffinityParams::parse(map).unwrap_err();
        assert!(err.contains("meta.list"));
        assert!(err.contains("array"));
    }

    #[test]
    fn test_rejects_nested_object() {
        let mut map = serde_json::Map::new();
        map.insert("nested".into(), serde_json::Value::Object(serde_json::Map::new()));
        let err = AffinityParams::parse(map).unwrap_err();
        assert!(err.contains("meta.nested"));
        assert!(err.contains("nested object"));
    }

    #[test]
    fn test_serialize_is_transparent() {
        let mut map = serde_json::Map::new();
        map.insert("key".into(), serde_json::Value::String("val".into()));
        let params = AffinityParams::parse(map).unwrap();
        let json = serde_json::to_string(&params).unwrap();
        assert_eq!(json, r#"{"key":"val"}"#);
    }
}
