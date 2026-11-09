//! MCP server (Streamable HTTP, JSON responses) at `POST /mcp`.
//!
//! Agents authenticate with an OAuth 2.1 access token from airlift's own
//! authorization server (see api/oauth.rs); a missing/invalid token gets a
//! 401 pointing at the protected-resource metadata, which is how MCP clients
//! discover where to log in. Every tool calls the same handlers the REST API
//! uses, so each acts with exactly the user's permissions (RBAC ∩ token
//! scope ∩ cap, branch protection, IP allowlists…).

use axum::body::to_bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use serde_json::{json, Value};

use crate::api::{apps, observability, publish};
use crate::auth::ApiUser;
use crate::db;
use crate::error::Error;
use crate::state::AppState;

const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

pub async fn get_mcp() -> Response {
    // No server-initiated stream: we only answer requests.
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")]).into_response()
}

pub async fn post_mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    caller: Result<ApiUser, Error>,
    body: Option<Json<Value>>,
) -> Response {
    // DNS-rebinding defence: a browser Origin must be our own.
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let ours = crate::auth::base_url(&state, &headers);
        if origin.trim_end_matches('/') != ours {
            return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
        }
    }
    // Bearer tokens only (no ambient cookie auth on an agent endpoint).
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("Bearer "));
    let caller = match (bearer, caller) {
        (true, Ok(c)) => c,
        _ => {
            let md = crate::api::oauth_server::resource_metadata_url(&state, &headers);
            return (
                StatusCode::UNAUTHORIZED,
                [(
                    header::WWW_AUTHENTICATE,
                    format!("Bearer resource_metadata=\"{md}\""),
                )],
                Json(json!({ "error": "invalid_token" })),
            )
                .into_response();
        }
    };
    let Some(Json(body)) = body else {
        return Json(rpc_error(Value::Null, -32700, "parse error")).into_response();
    };
    let (messages, batch) = match body {
        Value::Array(a) => (a, true),
        one => (vec![one], false),
    };
    let mut out = Vec::new();
    for m in messages {
        if let Some(resp) = handle(&state, &caller, m).await {
            out.push(resp);
        }
    }
    match (out.len(), batch) {
        (0, _) => StatusCode::ACCEPTED.into_response(),
        (_, true) => Json(Value::Array(out)).into_response(),
        _ => Json(out.remove(0)).into_response(),
    }
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// One JSON-RPC message → its response (None for notifications).
async fn handle(state: &AppState, caller: &ApiUser, m: Value) -> Option<Value> {
    let id = m.get("id").cloned();
    let method = m["method"].as_str().unwrap_or("").to_string();
    let id = match id {
        Some(id) if !id.is_null() => id,
        _ => return None, // notification (e.g. notifications/initialized)
    };
    let result = match method.as_str() {
        "initialize" => {
            let asked = m["params"]["protocolVersion"].as_str().unwrap_or("");
            let version = PROTOCOL_VERSIONS
                .iter()
                .find(|v| **v == asked)
                .copied()
                .unwrap_or(PROTOCOL_VERSIONS[0]);
            json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "airlift", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "airlift is a self-hosted Expo OTA update server. Apps live in orgs; \
                    publishes go to branches; devices follow channels. Use list_apps first, then \
                    get_app to see channels, releases and rollouts.",
            })
        }
        "ping" => json!({}),
        "tools/list" => json!({ "tools": tools() }),
        "tools/call" => {
            let name = m["params"]["name"].as_str().unwrap_or("");
            let args = m["params"]["arguments"].clone();
            match call_tool(state, caller, name, &args).await {
                Ok(v) => json!({
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&v).unwrap_or_default() }],
                    "structuredContent": v,
                    "isError": false,
                }),
                Err(msg) => json!({
                    "content": [{ "type": "text", "text": msg }],
                    "isError": true,
                }),
            }
        }
        _ => return Some(rpc_error(id, -32601, "method not found")),
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn s(props: &[(&str, &str)], required: &[&str]) -> Value {
    let mut p = serde_json::Map::new();
    for (k, desc) in props {
        let ty = if k.ends_with("percent") || *k == "limit" {
            "number"
        } else {
            "string"
        };
        p.insert((*k).into(), json!({ "type": ty, "description": desc }));
    }
    json!({ "type": "object", "properties": p, "required": required })
}

const ORG: (&str, &str) = ("org", "organization slug");
const APP: (&str, &str) = ("app", "app slug");

fn tools() -> Vec<Value> {
    vec![
        json!({ "name": "list_apps", "description": "List the orgs and apps you can access.",
            "inputSchema": s(&[], &[]) }),
        json!({ "name": "get_app", "description": "An app's branches, channels, releases (with rollout % and health) and A/B splits.",
            "inputSchema": s(&[ORG, APP], &["org", "app"]) }),
        json!({ "name": "list_updates", "description": "Recent update groups (newest first) with platforms and crash health.",
            "inputSchema": s(&[ORG, APP, ("branch", "only this branch"), ("runtime", "only this runtime version"), ("limit", "max results (default 30)")], &["org", "app"]) }),
        json!({ "name": "publish", "description": "Publish a zipped `expo export` output directory (base64) to a branch. Auto-release channels go live (or start a rollout with rollout_percent).",
            "inputSchema": s(&[ORG, APP, ("branch", "target branch"), ("runtime_version", "runtime version the update targets"),
                ("archive_base64", "base64 of the zipped export directory (metadata.json at the root)"),
                ("message", "release message"), ("rollout_percent", "start a progressive rollout at this share (0-100]")],
                &["org", "app", "branch", "runtime_version", "archive_base64"]) }),
        json!({ "name": "promote", "description": "Release an update group to every device on a channel.",
            "inputSchema": s(&[ORG, APP, ("channel", "channel name"), ("group_id", "update group id")], &["org", "app", "channel", "group_id"]) }),
        json!({ "name": "start_rollout", "description": "Release an update group to only a share of a channel's devices (stable per device).",
            "inputSchema": s(&[ORG, APP, ("channel", "channel name"), ("group_id", "update group id"), ("percent", "share of devices (0-100]")], &["org", "app", "channel", "group_id", "percent"]) }),
        json!({ "name": "set_rollout", "description": "Grow/shrink a running rollout; 100 completes it.",
            "inputSchema": s(&[ORG, APP, ("channel", "channel name"), ("runtime_version", "runtime of the rollout"), ("percent", "new share (0-100]")], &["org", "app", "channel", "runtime_version", "percent"]) }),
        json!({ "name": "rollback", "description": "Roll a channel back to the previous release it shipped for a runtime (devices switch back).",
            "inputSchema": s(&[ORG, APP, ("channel", "channel name"), ("runtime_version", "runtime version")], &["org", "app", "channel", "runtime_version"]) }),
        json!({ "name": "republish", "description": "Re-ship an existing update group as a brand-new update (optionally straight to a channel).",
            "inputSchema": s(&[ORG, APP, ("group_id", "update group to republish"), ("channel", "release the copy to this channel")], &["org", "app", "group_id"]) }),
        json!({ "name": "list_errors", "description": "Device JS error groups (symbolicated), newest first.",
            "inputSchema": s(&[ORG, APP, ("window", "1h | 24h | 7d | 14d (default 24h)"), ("update", "only errors from this update id")], &["org", "app"]) }),
        json!({ "name": "app_stats", "description": "Adoption: which update active devices run, and daily check-ins.",
            "inputSchema": s(&[ORG, APP], &["org", "app"]) }),
    ]
}

/// Turn a handler result into the tool result (JSON body or the API error).
async fn body(res: crate::error::Result<Response>) -> Result<Value, String> {
    let resp = res.map_err(|e| e.to_string())?;
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 32 * 1024 * 1024)
        .await
        .map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if status.is_success() {
        Ok(v)
    } else {
        Err(v["error"]["message"]
            .as_str()
            .unwrap_or("request failed")
            .to_string())
    }
}

fn arg(args: &Value, k: &str) -> Result<String, String> {
    match &args[k] {
        Value::String(s) if !s.is_empty() => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(format!("missing argument: {k}")),
    }
}

fn from<T: serde::de::DeserializeOwned>(v: Value) -> Result<T, String> {
    serde_json::from_value(v).map_err(|e| format!("invalid arguments: {e}"))
}

async fn call_tool(
    state: &AppState,
    caller: &ApiUser,
    name: &str,
    a: &Value,
) -> Result<Value, String> {
    let st = || State(state.clone());
    let c = || caller.clone();
    let oa = || -> Result<(String, String), String> { Ok((arg(a, "org")?, arg(a, "app")?)) };
    let num = |k: &str| -> Result<f64, String> {
        a[k].as_f64()
            .or_else(|| a[k].as_str().and_then(|s| s.parse().ok()))
            .ok_or_else(|| format!("missing argument: {k}"))
    };
    match name {
        "list_apps" => {
            let mut out = Vec::new();
            for (org, _role) in db::orgs::orgs_for_user(state.db(), &caller.user.id)
                .await
                .map_err(|e| e.to_string())?
            {
                if let Ok(v) = body(apps::list_apps(st(), c(), Path(org.slug.clone())).await).await
                {
                    let apps: Vec<Value> = v["apps"]
                        .as_array()
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|a| json!({ "slug": a["slug"], "name": a["name"], "id": a["id"] }))
                        .collect();
                    out.push(json!({ "org": org.slug, "name": org.name, "apps": apps }));
                }
            }
            Ok(json!({ "orgs": out }))
        }
        "get_app" => body(apps::get_app(st(), c(), Path(oa()?)).await).await,
        "list_updates" => {
            let q = from(
                json!({ "branch": a["branch"], "runtime": a["runtime"], "limit": a["limit"].as_i64() }),
            )?;
            body(apps::list_updates(st(), c(), Path(oa()?), Query(q)).await).await
        }
        "app_stats" => body(apps::app_stats(st(), c(), Path(oa()?)).await).await,
        "list_errors" => {
            let q = from(json!({ "window": a["window"], "update": a["update"] }))?;
            body(observability::list_errors(st(), c(), Path(oa()?), Query(q)).await).await
        }
        "promote" => {
            let (o, ap) = oa()?;
            let req = from(json!({ "group_id": arg(a, "group_id")? }))?;
            body(apps::promote(st(), c(), Path((o, ap, arg(a, "channel")?)), Json(req)).await).await
        }
        "start_rollout" => {
            let (o, ap) = oa()?;
            let req = from(json!({ "group_id": arg(a, "group_id")?, "percent": num("percent")? }))?;
            body(apps::start_rollout(st(), c(), Path((o, ap, arg(a, "channel")?)), Json(req)).await)
                .await
        }
        "set_rollout" => {
            let (o, ap) = oa()?;
            let req = from(
                json!({ "runtime_version": arg(a, "runtime_version")?, "percent": num("percent")? }),
            )?;
            body(apps::set_rollout(st(), c(), Path((o, ap, arg(a, "channel")?)), Json(req)).await)
                .await
        }
        "rollback" => {
            let (o, ap) = oa()?;
            let req = from(json!({ "runtime_version": arg(a, "runtime_version")? }))?;
            body(apps::rollback(st(), c(), Path((o, ap, arg(a, "channel")?)), Json(req)).await)
                .await
        }
        "republish" => {
            let (o, ap) = oa()?;
            let req = from(json!({ "channel": a["channel"].as_str() }))?;
            body(
                apps::republish(
                    st(),
                    c(),
                    Path((o, ap, arg(a, "group_id")?)),
                    Some(Json(req)),
                )
                .await,
            )
            .await
        }
        "publish" => {
            let (o, ap) = oa()?;
            let org = db::orgs::find_org_by_slug(state.db(), &o)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("not found")?;
            let app = db::apps::find_by_slug(state.db(), &org.id, &ap)
                .await
                .map_err(|e| e.to_string())?
                .ok_or("not found")?;
            let archive = base64::engine::general_purpose::STANDARD
                .decode(arg(a, "archive_base64")?.replace(['\n', '\r', ' '], ""))
                .map_err(|_| "archive_base64 is not valid base64".to_string())?;
            if archive.len() > state.config().server.max_body_bytes {
                return Err("archive exceeds server.max_body_bytes".into());
            }
            let opt = |k: &str| {
                a[k].as_str()
                    .map(String::from)
                    .or_else(|| a[k].as_f64().map(|n| n.to_string()))
            };
            publish::publish_archive(
                state,
                caller,
                &app.id,
                publish::PublishInput {
                    branch: Some(arg(a, "branch")?),
                    runtime_version: Some(arg(a, "runtime_version")?),
                    message: opt("message"),
                    git_branch: None,
                    git_commit: None,
                    expo_config: None,
                    rollout_percent: opt("rollout_percent"),
                    archive: Some(archive),
                },
            )
            .await
            .map_err(|e| e.to_string())
        }
        _ => Err(format!("unknown tool {name}")),
    }
}
