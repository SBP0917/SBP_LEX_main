use std::collections::HashSet;

use serde_json::Value;

use crate::{digest::is_sha512, BoundaryError};

pub(crate) fn exact_keys(
    value: &Value,
    expected: &[&str],
    label: &'static str,
) -> Result<(), BoundaryError> {
    let object = value.as_object().ok_or(BoundaryError::Malformed(label))?;
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(BoundaryError::Malformed(label));
    }
    Ok(())
}

pub(crate) fn nonempty_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, BoundaryError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(BoundaryError::Malformed(key))
}

pub(crate) fn sha512_field<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<&'a str, BoundaryError> {
    nonempty_text(object, key).and_then(|value| {
        if is_sha512(value) {
            Ok(value)
        } else {
            Err(BoundaryError::Malformed(key))
        }
    })
}

pub(crate) fn evidence_references(value: &Value) -> Result<(), BoundaryError> {
    let references = value
        .as_array()
        .filter(|value| !value.is_empty())
        .ok_or(BoundaryError::Missing("evidence_references"))?;
    let mut identifiers = HashSet::new();
    for reference in references {
        exact_keys(
            reference,
            &["evidence_id", "source", "digest"],
            "evidence_reference",
        )?;
        let object = reference
            .as_object()
            .ok_or(BoundaryError::Malformed("evidence_reference"))?;
        let identifier = nonempty_text(object, "evidence_id")?;
        if !identifiers.insert(identifier) {
            return Err(BoundaryError::Duplicate("evidence_id"));
        }
        nonempty_text(object, "source")?;
        sha512_field(object, "digest")?;
    }
    Ok(())
}
