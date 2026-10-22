// SPDX-FileCopyrightText: 2026 The weft authors
// SPDX-License-Identifier: MIT

//! Configuration as JSON for the adopter's services (CBOR on the wire, JSON on disk).

use serde_json::{Map, Number, Value as Json};
use weft_verifier::cbor::Value;

use crate::hex;

/// CBOR value to JSON, for display. Byte strings become `"h'…'"`, non-text map keys their
/// display form.
pub fn to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(i) => Json::Number(Number::from(*i)),
        Value::Text(s) => Json::String(s.clone()),
        Value::Bytes(b) => Json::String(format!("h'{}'", hex(b))),
        Value::Array(items) => Json::Array(items.iter().map(to_json).collect()),
        Value::Map(entries) => {
            let mut map = Map::new();
            for (k, v) in entries {
                let key = match k {
                    Value::Text(s) => s.clone(),
                    other => to_json(other).to_string(),
                };
                map.insert(key, to_json(v));
            }
            Json::Object(map)
        }
    }
}
