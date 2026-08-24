use std::cmp::Ordering;

use serde_json::{Map, Value};
use unicode_normalization::UnicodeNormalization;

use crate::BoundaryError;

fn key_order(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn normal_decimal(input: &str) -> Result<String, BoundaryError> {
    let (negative, body) = input
        .strip_prefix('-')
        .map_or((false, input), |rest| (true, rest));
    let (mantissa, exponent) = match body.split_once(['e', 'E']) {
        Some((m, e)) => (
            m,
            e.parse::<i64>()
                .map_err(|_| BoundaryError::Malformed("number"))?,
        ),
        None => (body, 0),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BoundaryError::Malformed("number"));
    }
    let digits = format!("{whole}{fraction}");
    let decimal_index =
        i64::try_from(whole.len()).map_err(|_| BoundaryError::Malformed("number"))? + exponent;
    let mut rendered = if decimal_index <= 0 {
        let zero_count = usize::try_from(decimal_index.unsigned_abs())
            .map_err(|_| BoundaryError::Malformed("number"))?;
        format!("0.{}{}", "0".repeat(zero_count), digits)
    } else if usize::try_from(decimal_index).unwrap_or(usize::MAX) >= digits.len() {
        let padding = usize::try_from(decimal_index)
            .map_err(|_| BoundaryError::Malformed("number"))?
            - digits.len();
        format!("{digits}{}", "0".repeat(padding))
    } else {
        let index =
            usize::try_from(decimal_index).map_err(|_| BoundaryError::Malformed("number"))?;
        format!("{}.{}", &digits[..index], &digits[index..])
    };
    if let Some((integer, fraction)) = rendered.split_once('.') {
        let fraction = fraction.trim_end_matches('0');
        rendered = if fraction.is_empty() {
            integer.to_owned()
        } else {
            format!("{integer}.{fraction}")
        };
    }
    let trimmed = rendered.trim_start_matches('0');
    rendered = if rendered.starts_with("0.") {
        rendered
    } else if trimmed.is_empty() {
        "0".to_owned()
    } else {
        trimmed.to_owned()
    };
    if negative && rendered != "0" {
        rendered.insert(0, '-');
    }
    Ok(rendered)
}

fn integrity_value(value: &Value) -> Result<Value, BoundaryError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(value.clone()),
        Value::Number(number) if number.is_i64() || number.is_u64() => Ok(value.clone()),
        Value::Number(number) => {
            let mut object = Map::new();
            object.insert(
                "exact_decimal".to_owned(),
                Value::String(normal_decimal(&number.to_string())?),
            );
            Ok(Value::Object(object))
        }
        Value::Array(values) => values
            .iter()
            .map(integrity_value)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Value::Object(object) => object
            .iter()
            .map(|(key, value)| Ok((key.clone(), integrity_value(value)?)))
            .collect::<Result<Map<_, _>, _>>()
            .map(Value::Object),
    }
}

fn write_string(output: &mut String, text: &str) -> Result<(), BoundaryError> {
    let normalised: String = text.nfc().collect();
    output.push_str(
        &serde_json::to_string(&normalised)
            .map_err(|_| BoundaryError::Malformed("canonical_string"))?,
    );
    Ok(())
}

fn write_value(
    value: &Value,
    output: &mut String,
    allow_decimal: bool,
) -> Result<(), BoundaryError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(boolean) => output.push_str(if *boolean { "true" } else { "false" }),
        Value::Number(number) => {
            if !allow_decimal && !number.is_i64() && !number.is_u64() {
                return Err(BoundaryError::Malformed("floating_point_forbidden"));
            }
            output.push_str(&number.to_string());
        }
        Value::String(text) => write_string(output, text)?,
        Value::Array(values) => {
            output.push('[');
            for (index, child) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_value(child, output, allow_decimal)?;
            }
            output.push(']');
        }
        Value::Object(object) => {
            let mut normalised = Vec::with_capacity(object.len());
            for (key, child) in object {
                let key: String = key.nfc().collect();
                if normalised
                    .iter()
                    .any(|(existing, _): &(String, &Value)| existing == &key)
                {
                    return Err(BoundaryError::Duplicate("normalised_object_key"));
                }
                normalised.push((key, child));
            }
            normalised.sort_by(|(left, _), (right, _)| key_order(left, right));
            output.push('{');
            for (index, (key, child)) in normalised.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_string(output, key)?;
                output.push(':');
                write_value(child, output, allow_decimal)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

/// Exact restricted V2 assurance JSON: NFC, UTF-16 key ordering, no floats.
pub fn canonical_assurance_bytes(value: &Value) -> Result<Vec<u8>, BoundaryError> {
    let mut output = String::new();
    write_value(value, &mut output, false)?;
    Ok(output.into_bytes())
}

/// V2 integrity representation: finite decimal numbers become `exact_decimal` objects.
pub fn canonical_integrity_bytes(value: &Value) -> Result<Vec<u8>, BoundaryError> {
    canonical_assurance_bytes(&integrity_value(value)?)
}
