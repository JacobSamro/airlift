//! OTLP/HTTP JSON ingestion (logs + metrics). The JS OpenTelemetry exporters
//! (`@opentelemetry/exporter-logs-otlp-http`, `…-metrics-otlp-http`) send
//! this encoding by default, so React Native apps can point them at
//! `/u/<app>/otlp/v1/{logs,metrics}`. Protobuf is not accepted.
//!
//! Correlation attributes (record or resource): `airlift.update_id` /
//! `expo.update_id`, `airlift.client_id` / `eas.client_id` / `device.id`,
//! `airlift.platform` / `os.type`, `airlift.runtime_version`,
//! `airlift.channel`. Log records carrying `exception.*` attributes also
//! become error reports (symbolicated and grouped like reporter errors).

use serde_json::{Map, Value};

use crate::db;
use crate::error::Result;

use super::ErrorReport;

/// Flatten an OTLP AnyValue into plain JSON.
fn any_value(v: &Value) -> Value {
    let Some(obj) = v.as_object() else {
        return Value::Null;
    };
    if let Some(s) = obj.get("stringValue") {
        return s.clone();
    }
    if let Some(b) = obj.get("boolValue") {
        return b.clone();
    }
    if let Some(i) = obj.get("intValue") {
        // int64 is a JSON string in OTLP/JSON.
        return match i {
            Value::String(s) => s.parse::<i64>().map(Value::from).unwrap_or(i.clone()),
            other => other.clone(),
        };
    }
    if let Some(d) = obj.get("doubleValue") {
        return d.clone();
    }
    if let Some(a) = obj.get("arrayValue").and_then(|a| a.get("values")) {
        return Value::Array(
            a.as_array()
                .map(|vs| vs.iter().map(any_value).collect())
                .unwrap_or_default(),
        );
    }
    if let Some(kv) = obj.get("kvlistValue").and_then(|a| a.get("values")) {
        return Value::Object(attributes(kv));
    }
    if let Some(b) = obj.get("bytesValue") {
        return b.clone();
    }
    Value::Null
}

/// `[{key, value: AnyValue}]` → `{key: value}`.
fn attributes(list: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    for kv in list.as_array().into_iter().flatten() {
        if let (Some(k), Some(v)) = (kv.get("key").and_then(Value::as_str), kv.get("value")) {
            out.insert(k.to_string(), any_value(v));
        }
    }
    out
}

fn nanos_to_rfc3339(v: Option<&Value>) -> Option<String> {
    let n: i128 = match v? {
        Value::String(s) => s.parse().ok()?,
        Value::Number(n) => n.as_i64()? as i128,
        _ => return None,
    };
    if n <= 0 {
        return None;
    }
    let t = time::OffsetDateTime::from_unix_timestamp_nanos(n).ok()?;
    let s = t
        .format(&time::format_description::well_known::Rfc3339)
        .ok()?;
    Some(crate::util::normalize_rfc3339(&s))
}

fn first_str(attrs: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| attrs.get(*k).and_then(Value::as_str))
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// The correlation fields we index on.
struct Correlation {
    update_id: Option<String>,
    client_id: Option<String>,
    platform: Option<String>,
    runtime_version: Option<String>,
    channel: Option<String>,
}

fn correlation(attrs: &Map<String, Value>) -> Correlation {
    let platform = first_str(attrs, &["airlift.platform", "os.type", "os.name"])
        .map(|p| p.to_ascii_lowercase())
        .and_then(|p| match p.as_str() {
            "ios" | "iphone os" | "darwin" => Some("ios".to_string()),
            "android" | "linux" => Some("android".to_string()),
            _ => None,
        });
    Correlation {
        update_id: first_str(
            attrs,
            &[
                "airlift.update_id",
                "expo.update_id",
                "expo.updates.update_id",
            ],
        )
        .map(|s| s.to_ascii_lowercase()),
        client_id: first_str(attrs, &["airlift.client_id", "eas.client_id", "device.id"]),
        platform,
        runtime_version: first_str(attrs, &["airlift.runtime_version", "expo.runtime_version"]),
        channel: first_str(attrs, &["airlift.channel", "expo.channel"]),
    }
}

/// Parse an OTLP logs request: (log rows, exception reports).
pub fn parse_logs(
    body: &Value,
    app_id: &str,
    org_id: &str,
) -> (Vec<db::observability::NewLog>, Vec<ErrorReport>) {
    let now = crate::util::now_rfc3339();
    let mut logs = Vec::new();
    let mut errors = Vec::new();
    for rl in body["resourceLogs"].as_array().into_iter().flatten() {
        let resource = attributes(&rl["resource"]["attributes"]);
        for sl in rl["scopeLogs"].as_array().into_iter().flatten() {
            for r in sl["logRecords"].as_array().into_iter().flatten() {
                let mut attrs = resource.clone();
                attrs.extend(attributes(&r["attributes"]));
                let c = correlation(&attrs);
                let ts = nanos_to_rfc3339(r.get("timeUnixNano"))
                    .or_else(|| nanos_to_rfc3339(r.get("observedTimeUnixNano")))
                    .unwrap_or_else(|| now.clone());
                let body = match any_value(&r["body"]) {
                    Value::String(s) => s,
                    Value::Null => String::new(),
                    other => other.to_string(),
                };
                if let Some(ex_type) = first_str(&attrs, &["exception.type"]) {
                    errors.push(ErrorReport {
                        app_id: app_id.to_string(),
                        org_id: org_id.to_string(),
                        ts: ts.clone(),
                        name: ex_type,
                        message: first_str(&attrs, &["exception.message"])
                            .unwrap_or_else(|| body.clone()),
                        stack: first_str(&attrs, &["exception.stacktrace"]),
                        fatal: attrs
                            .get("airlift.fatal")
                            .or_else(|| attrs.get("exception.escaped"))
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        update_id: c.update_id.clone(),
                        platform: c.platform.clone(),
                        runtime_version: c.runtime_version.clone(),
                        channel: c.channel.clone(),
                        client_id: c.client_id.clone(),
                        source: "otlp",
                    });
                }
                logs.push(db::observability::NewLog {
                    ts,
                    severity: r["severityNumber"].as_i64().unwrap_or(0),
                    severity_text: r["severityText"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                    body,
                    attributes: (!attrs.is_empty())
                        .then(|| Value::Object(attrs.clone()).to_string()),
                    update_id: c.update_id,
                    platform: c.platform,
                    client_id: c.client_id,
                    trace_id: r["traceId"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                });
            }
        }
    }
    (logs, errors)
}

/// One data point, pre-bucketed to its minute.
#[derive(Debug, Clone)]
pub struct MetricPoint {
    pub name: String,
    pub unit: Option<String>,
    pub kind: &'static str,
    pub minute: String,
    pub attributes: String,
    pub count: i64,
    pub sum: f64,
    pub min: Option<f64>,
    pub max: Option<f64>,
}

fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Parse an OTLP metrics request. Sums with CUMULATIVE temporality are
/// stored like gauges (one observation per point) since deltas would need
/// per-series state; DELTA sums and histograms aggregate naturally.
pub fn parse_metrics(body: &Value) -> Vec<MetricPoint> {
    let now = crate::util::now_rfc3339();
    let mut out = Vec::new();
    for rm in body["resourceMetrics"].as_array().into_iter().flatten() {
        let resource = attributes(&rm["resource"]["attributes"]);
        let platform = correlation(&resource).platform;
        for sm in rm["scopeMetrics"].as_array().into_iter().flatten() {
            for m in sm["metrics"].as_array().into_iter().flatten() {
                let Some(name) = m["name"].as_str().filter(|n| !n.is_empty()) else {
                    continue;
                };
                let unit = m["unit"]
                    .as_str()
                    .filter(|u| !u.is_empty())
                    .map(String::from);
                let (kind, data) = if m.get("sum").is_some() {
                    let cumulative = m["sum"]["aggregationTemporality"].as_i64() == Some(2);
                    (if cumulative { "gauge" } else { "sum" }, &m["sum"])
                } else if m.get("gauge").is_some() {
                    ("gauge", &m["gauge"])
                } else if m.get("histogram").is_some() {
                    ("histogram", &m["histogram"])
                } else {
                    continue;
                };
                for dp in data["dataPoints"].as_array().into_iter().flatten() {
                    let mut attrs = attributes(&dp["attributes"]);
                    if let Some(p) = &platform {
                        attrs.insert("platform".into(), Value::String(p.clone()));
                    }
                    let ts =
                        nanos_to_rfc3339(dp.get("timeUnixNano")).unwrap_or_else(|| now.clone());
                    let minute: String = ts.chars().take(16).collect();
                    let point = if kind == "histogram" {
                        let count = number(&dp["count"]).unwrap_or(0.0) as i64;
                        MetricPoint {
                            name: name.to_string(),
                            unit: unit.clone(),
                            kind,
                            minute,
                            attributes: Value::Object(attrs).to_string(),
                            count,
                            sum: number(&dp["sum"]).unwrap_or(0.0),
                            min: number(&dp["min"]),
                            max: number(&dp["max"]),
                        }
                    } else {
                        let Some(v) = number(&dp["asDouble"]).or_else(|| number(&dp["asInt"]))
                        else {
                            continue;
                        };
                        MetricPoint {
                            name: name.to_string(),
                            unit: unit.clone(),
                            kind,
                            minute,
                            attributes: Value::Object(attrs).to_string(),
                            count: 1,
                            sum: v,
                            min: Some(v),
                            max: Some(v),
                        }
                    };
                    out.push(point);
                }
            }
        }
    }
    out
}

pub async fn store_metrics(db: &db::Db, app_id: &str, points: &[MetricPoint]) -> Result<()> {
    let obs: Vec<_> = points
        .iter()
        .map(|p| db::observability::MetricObs {
            name: &p.name,
            minute: &p.minute,
            attributes: &p.attributes,
            kind: p.kind,
            unit: p.unit.as_deref(),
            count: p.count,
            sum: p.sum,
            min: p.min,
            max: p.max,
        })
        .collect();
    db::observability::add_metric_points(db, app_id, &obs).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_logs_with_exceptions() {
        let body = json!({ "resourceLogs": [{
            "resource": { "attributes": [
                { "key": "airlift.update_id", "value": { "stringValue": "ABC" } },
                { "key": "os.type", "value": { "stringValue": "android" } }
            ]},
            "scopeLogs": [{ "logRecords": [
                { "timeUnixNano": "1700000000000000000", "severityNumber": 9,
                  "severityText": "INFO", "body": { "stringValue": "hello" } },
                { "severityNumber": 17, "body": { "stringValue": "boom" },
                  "attributes": [
                    { "key": "exception.type", "value": { "stringValue": "TypeError" } },
                    { "key": "exception.message", "value": { "stringValue": "x is undefined" } },
                    { "key": "exception.stacktrace", "value": { "stringValue": "at f (index.android.bundle:1:5)" } }
                  ] }
            ]}]
        }]});
        let (logs, errors) = parse_logs(&body, "app", "org");
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].ts, "2023-11-14T22:13:20.000Z");
        assert_eq!(logs[0].update_id.as_deref(), Some("abc"));
        assert_eq!(logs[0].platform.as_deref(), Some("android"));
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].name, "TypeError");
        assert_eq!(errors[0].message, "x is undefined");
    }

    #[test]
    fn parses_sum_gauge_and_histogram() {
        let body = json!({ "resourceMetrics": [{ "scopeMetrics": [{ "metrics": [
            { "name": "taps", "sum": { "aggregationTemporality": 1,
                "dataPoints": [{ "asInt": "3", "timeUnixNano": "1700000000000000000" }] } },
            { "name": "mem", "unit": "By", "gauge": { "dataPoints": [{ "asDouble": 1.5 }] } },
            { "name": "lat", "histogram": { "dataPoints": [{ "count": "4", "sum": 10.0, "min": 1.0, "max": 5.0 }] } }
        ]}]}]});
        let p = parse_metrics(&body);
        assert_eq!(p.len(), 3);
        assert_eq!(
            (p[0].kind, p[0].sum, p[0].minute.as_str()),
            ("sum", 3.0, "2023-11-14T22:13")
        );
        assert_eq!((p[1].kind, p[1].unit.as_deref()), ("gauge", Some("By")));
        assert_eq!(
            (p[2].kind, p[2].count, p[2].max),
            ("histogram", 4, Some(5.0))
        );
    }
}
