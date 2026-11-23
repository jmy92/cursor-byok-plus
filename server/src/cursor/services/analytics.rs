//! Implements Cursor analytics endpoints and event handling.
use axum::{
    body::{Body, Bytes},
    extract::Extension,
    http::{header, HeaderValue, Request, Response, StatusCode},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::{BufMut, BytesMut};
use prost::Message;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::{api::cursor::proxy, Error, Result};

pub const BOOTSTRAP_STATSIG_PATH: &str = "/aiserver.v1.AnalyticsService/BootstrapStatsig";
const AGENT_RETRIES_GATE: &str = "nal_agent_retries";
const AGENT_WEBSOCKET_GATE: &str = "nal_websocket_client";
const AGENT_LOCAL_LOOP_GATE: &str = "agent_host_local_loop";
const BIDI_BINARY_ENCODING_GATE: &str = "bidi_append_binary_encoding_disabled";
const LOCAL_RULE: &str = "local_enabled";

/// Forces gates into every bootstrap response so Cursor keeps using the
/// RunSSE/BidiAppend transport this server implements:
/// - retries on, letting the client retry transient stream failures;
/// - Agent Run WebSocket transport off (Cursor 3.29+ dials wss://api2.cursor.sh
///   otherwise, bypassing the local proxy entirely);
/// - client-side agent loop off (Cursor 3.31+ would call
///   InferenceService/RunInferenceSSE, which the server does not implement);
/// - hex BidiAppend encoding kept (Cursor 3.31+ would otherwise send raw
///   protobuf bytes in data_binary).
const GATE_OVERRIDES: [(&str, bool); 4] = [
    (AGENT_RETRIES_GATE, true),
    (AGENT_WEBSOCKET_GATE, false),
    (AGENT_LOCAL_LOOP_GATE, false),
    (BIDI_BINARY_ENCODING_GATE, true),
];

#[derive(Clone, PartialEq, Message)]
struct BootstrapStatsigResponse {
    #[prost(string, tag = "1")]
    config: String,
    #[prost(uint64, tag = "2")]
    generated_at_ms: u64,
}

pub async fn bootstrap_statsig(
    Extension(upstream): Extension<proxy::CursorProxy>,
    request: Request<Body>,
) -> Result<Response<Body>> {
    match proxy::forward_buffered(&upstream, request).await {
        Ok(response) if response.status.is_success() => match patch_upstream(response) {
            Ok(response) => Ok(response),
            Err(error) => {
                tracing::warn!(%error, "Cursor Statsig bootstrap was invalid; using local bootstrap");
                local_response()
            }
        },
        Ok(response) => {
            tracing::warn!(status = %response.status, "Cursor Statsig bootstrap was rejected; using local bootstrap");
            local_response()
        }
        Err(error) => {
            tracing::warn!(%error, "Cursor Statsig bootstrap was unavailable; using local bootstrap");
            local_response()
        }
    }
}

fn patch_upstream(response: proxy::BufferedResponse) -> Result<Response<Body>> {
    let (framed, payload) = unary_payload(&response.body)?;
    let mut message = BootstrapStatsigResponse::decode(payload)?;
    let mut config = serde_json::from_str::<Value>(&message.config)?;
    apply_gate_overrides(&mut config)?;
    message.config = serde_json::to_string(&config)?;
    Ok(response.with_body(encode_unary(&message, framed)))
}

fn local_response() -> Result<Response<Body>> {
    let generated_at_ms = chrono::Utc::now().timestamp_millis() as u64;
    let mut config = json!({
        "feature_gates": {},
        "dynamic_configs": {},
        "layer_configs": {},
        "user": {
            "userID": "local_ultra",
            "customIDs": { "localUserID": "local_ultra" }
        },
        "has_updates": true,
        "hash_used": "none",
        "sdkParams": {
            "stableID": "local_ultra",
            "disableDiagnosticsLogging": true
        },
        "time": generated_at_ms
    });
    apply_gate_overrides(&mut config)?;
    let message = BootstrapStatsigResponse {
        config: serde_json::to_string(&config)?,
        generated_at_ms,
    };
    let body = message.encode_to_vec();
    let mut response = Response::new(Body::from(body.clone()));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/proto"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        body.len()
            .to_string()
            .parse()
            .expect("body length is a valid header value"),
    );
    Ok(response)
}

fn apply_gate_overrides(config: &mut Value) -> Result<()> {
    let hash_used = config
        .get("hash_used")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let overrides = GATE_OVERRIDES
        .iter()
        .map(|(name, value)| {
            let key = statsig_key(&hash_used, name);
            (key.clone(), local_gate(&key, *value))
        })
        .collect::<Vec<_>>();
    let root = config
        .as_object_mut()
        .ok_or_else(|| Error::Protocol("Statsig bootstrap config must be an object".into()))?;
    let gates = root
        .entry("feature_gates")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| Error::Protocol("Statsig feature_gates must be an object".into()))?;
    for (key, gate) in overrides {
        gates.insert(key, gate);
    }
    Ok(())
}

fn statsig_key(hash_used: &str, name: &str) -> String {
    match hash_used {
        "djb2" => djb2(name),
        "sha256" => STANDARD.encode(Sha256::digest(name.as_bytes())),
        _ => name.to_owned(),
    }
}

fn djb2(value: &str) -> String {
    value
        .encode_utf16()
        .fold(0_u32, |hash, character| {
            hash.wrapping_mul(31).wrapping_add(u32::from(character))
        })
        .to_string()
}

fn local_gate(name: &str, value: bool) -> Value {
    json!({
        "name": name,
        "value": value,
        "rule_id": LOCAL_RULE,
        "ruleID": LOCAL_RULE,
        "group_name": LOCAL_RULE,
        "groupName": LOCAL_RULE,
        "secondary_exposures": [],
        "secondaryExposures": [],
        "undelegated_secondary_exposures": [],
        "undelegatedSecondaryExposures": [],
        "is_device_based": false,
        "isDeviceBased": false,
        "id_type": "userID",
        "idType": "userID"
    })
}

fn unary_payload(body: &Bytes) -> Result<(bool, &[u8])> {
    if body.len() < 5 {
        return Ok((false, body));
    }
    let flags = body[0];
    let length = u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize;
    if length != body.len() - 5 {
        return Ok((false, body));
    }
    if flags != 0 {
        return Err(Error::Protocol(format!(
            "cannot patch compressed or terminal Statsig frame: flags={flags}"
        )));
    }
    Ok((true, &body[5..]))
}

fn encode_unary(message: &impl Message, framed: bool) -> Bytes {
    let payload = message.encode_to_vec();
    if !framed {
        return Bytes::from(payload);
    }
    let mut output = BytesMut::with_capacity(5 + payload.len());
    output.put_u8(0);
    output.put_u32(payload.len() as u32);
    output.extend_from_slice(&payload);
    output.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_force_backend_transport_for_every_statsig_hash_format() {
        for hash_used in ["none", "djb2", "sha256"] {
            let mut config = json!({
                "feature_gates": {},
                "hash_used": hash_used,
            });
            apply_gate_overrides(&mut config).unwrap();
            let gates = config
                .get("feature_gates")
                .and_then(Value::as_object)
                .expect("feature_gates object exists");
            for (name, expected) in GATE_OVERRIDES {
                let key = statsig_key(hash_used, name);
                let gate = gates
                    .get(&key)
                    .unwrap_or_else(|| panic!("gate {name} missing under hash {hash_used}"));
                assert_eq!(
                    gate.get("value").and_then(Value::as_bool),
                    Some(expected),
                    "gate {name} has the wrong value under hash {hash_used}"
                );
            }
        }
    }

    #[test]
    fn overrides_replace_planted_gate_values() {
        let mut config = json!({
            "feature_gates": {
                "nal_websocket_client": { "value": true },
                "agent_host_local_loop": { "value": true },
            },
            "hash_used": "none",
        });
        apply_gate_overrides(&mut config).unwrap();
        let gates = config.get("feature_gates").unwrap();
        assert_eq!(gates["nal_websocket_client"]["value"], json!(false));
        assert_eq!(gates["agent_host_local_loop"]["value"], json!(false));
    }

    #[test]
    fn overrides_create_feature_gates_when_missing() {
        let mut config = json!({ "hash_used": "djb2" });
        apply_gate_overrides(&mut config).unwrap();
        let gates = config
            .get("feature_gates")
            .and_then(Value::as_object)
            .expect("feature_gates object was created");
        assert_eq!(gates.len(), GATE_OVERRIDES.len());
    }
}
