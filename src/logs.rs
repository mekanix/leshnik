use std::{net::IpAddr, sync::OnceLock};

use chrono::{DateTime, FixedOffset, Utc};
use regex::Regex;
use serde_json::{json, Value};
use thiserror::Error;

use crate::config::LogFormat;

#[derive(Debug, Clone)]
pub struct ParsedLine {
    pub timestamp_ns: String,
    pub line: String,
    pub remote_addr: Option<IpAddr>,
    pub request_path: Option<String>,
    pub status: Option<u16>,
}

impl ParsedLine {
    pub fn set_geoip(
        &mut self,
        country_code: &str,
        country_iso3: &str,
        city_name: Option<&str>,
        latitude: Option<f64>,
        longitude: Option<f64>,
    ) {
        let Ok(mut value) = serde_json::from_str::<Value>(&self.line) else {
            return;
        };
        let Some(object) = value.as_object_mut() else {
            return;
        };
        object.insert("geoip_country_code".to_owned(), json!(country_code));
        object.insert("geoip_country_iso3".to_owned(), json!(country_iso3));
        if let Some(city_name) = city_name {
            object.insert("geoip_city_name".to_owned(), json!(city_name));
        }
        if let Some(latitude) = latitude {
            object.insert("geoip_latitude".to_owned(), json!(latitude));
        }
        if let Some(longitude) = longitude {
            object.insert("geoip_longitude".to_owned(), json!(longitude));
        }
        self.line = value.to_string();
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("line is not nginx combined format")]
    Combined,
    #[error("invalid nginx timestamp: {0}")]
    Timestamp(String),
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn parse_line(format: LogFormat, line: &str) -> Result<ParsedLine, ParseError> {
    match format {
        LogFormat::Combined => parse_combined(line),
        LogFormat::Json => parse_json(line),
    }
}

fn parse_combined(line: &str) -> Result<ParsedLine, ParseError> {
    static COMBINED: OnceLock<Regex> = OnceLock::new();
    let regex = COMBINED.get_or_init(|| {
        Regex::new(
            r#"^(?P<remote_addr>\S+) \S+ (?P<remote_user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>[^"]*) (?P<protocol>[^"]+)" (?P<status>\d{3}) (?P<body_bytes_sent>\d+|-) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)""#,
        )
        .expect("combined regex must compile")
    });
    let captures = regex.captures(line).ok_or(ParseError::Combined)?;
    let time = captures
        .name("time")
        .map(|m| m.as_str())
        .ok_or(ParseError::Combined)?;
    let status = capture(&captures, "status")?;
    let body_bytes_sent = capture(&captures, "body_bytes_sent")?;
    let remote_user = capture(&captures, "remote_user")?;
    let referer = capture(&captures, "referer")?;
    let method = capture(&captures, "method")?;
    let request_uri = capture(&captures, "path")?;
    let protocol = capture(&captures, "protocol")?;
    let remote_addr = capture(&captures, "remote_addr")?;
    let parsed_time = parse_nginx_time(time)?;

    let body_bytes_sent = if body_bytes_sent == "-" {
        Value::Null
    } else {
        json!(body_bytes_sent
            .parse::<u64>()
            .map_err(|_| ParseError::Combined)?)
    };
    let remote_user = dash_to_empty(remote_user);
    let referer = dash_to_empty(referer);
    let user_agent = capture(&captures, "user_agent")?;
    let status = status.parse::<u16>().map_err(|_| ParseError::Combined)?;
    let structured = json!({
        "remote_addr": capture(&captures, "remote_addr")?,
        "remote_user": remote_user,
        "time_local": time,
        "time_iso8601": parsed_time.to_rfc3339(),
        "method": method,
        "request_method": method,
        "path": request_uri,
        "request": format!("{method} {request_uri} {protocol}"),
        "request_uri": request_uri,
        "args": query_string(request_uri),
        "protocol": protocol,
        "server_protocol": protocol,
        "status": status,
        "body_bytes_sent": body_bytes_sent,
        "referer": referer,
        "http_referer": referer,
        "user_agent": user_agent,
        "http_user_agent": user_agent,
        "request_time": 0.0,
        "geoip_country_code": "",
        "geoip_country_iso3": "",
        "geoip_city_name": "",
        "geoip_latitude": null,
        "geoip_longitude": null,
        "message": line,
    });
    Ok(ParsedLine {
        timestamp_ns: to_ns(parsed_time),
        line: structured.to_string(),
        remote_addr: remote_addr.parse().ok(),
        request_path: Some(url_path(request_uri).to_owned()),
        status: Some(status),
    })
}

fn capture<'a>(
    captures: &'a regex::Captures<'a>,
    name: &'static str,
) -> Result<&'a str, ParseError> {
    captures
        .name(name)
        .map(|m| m.as_str())
        .ok_or(ParseError::Combined)
}

fn dash_to_empty(value: &str) -> Value {
    if value == "-" {
        json!("")
    } else {
        json!(value)
    }
}

fn query_string(request_uri: &str) -> &str {
    request_uri
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap_or("")
}

fn url_path(request_uri: &str) -> &str {
    request_uri
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(request_uri)
}

fn parse_json(line: &str) -> Result<ParsedLine, ParseError> {
    let value: Value = serde_json::from_str(line)?;
    let timestamp_ns = json_timestamp(&value)
        .transpose()?
        .unwrap_or_else(|| now_ns().to_string());
    Ok(ParsedLine {
        timestamp_ns,
        request_path: json_request_path(&value),
        line: line.to_owned(),
        remote_addr: json_remote_addr(&value),
        status: json_status(&value),
    })
}

fn json_status(value: &Value) -> Option<u16> {
    value
        .get("status")
        .and_then(|status| {
            status
                .as_u64()
                .and_then(|status| u16::try_from(status).ok())
        })
        .or_else(|| {
            value
                .get("status")
                .and_then(Value::as_str)
                .and_then(|status| status.parse().ok())
        })
}

fn json_request_path(value: &Value) -> Option<String> {
    for key in ["request_uri", "path", "uri"] {
        if let Some(raw) = value.get(key).and_then(Value::as_str) {
            return Some(url_path(raw).to_owned());
        }
    }
    value
        .get("request")
        .and_then(Value::as_str)
        .and_then(|request| request.split_whitespace().nth(1))
        .map(url_path)
        .map(str::to_owned)
}

fn json_remote_addr(value: &Value) -> Option<IpAddr> {
    for key in ["remote_addr", "remote_ip", "client_ip"] {
        if let Some(raw) = value.get(key).and_then(Value::as_str) {
            if let Ok(addr) = raw.parse() {
                return Some(addr);
            }
        }
    }
    None
}

fn json_timestamp(value: &Value) -> Option<Result<String, ParseError>> {
    for key in ["time", "time_local", "timestamp", "@timestamp"] {
        if let Some(raw) = value.get(key).and_then(Value::as_str) {
            return Some(parse_timestamp(raw));
        }
    }
    None
}

fn parse_timestamp(raw: &str) -> Result<String, ParseError> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(to_ns(dt));
    }
    nginx_time_to_ns(raw)
}

fn nginx_time_to_ns(raw: &str) -> Result<String, ParseError> {
    parse_nginx_time(raw).map(to_ns)
}

fn parse_nginx_time(raw: &str) -> Result<DateTime<FixedOffset>, ParseError> {
    DateTime::parse_from_str(raw, "%d/%b/%Y:%H:%M:%S %z")
        .map_err(|_| ParseError::Timestamp(raw.to_owned()))
}

fn now_ns() -> i64 {
    Utc::now()
        .timestamp_nanos_opt()
        .expect("current timestamp must fit in nanoseconds")
}

fn to_ns(dt: DateTime<FixedOffset>) -> String {
    dt.timestamp_nanos_opt()
        .expect("log timestamp must fit in nanoseconds")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_combined_timestamp() {
        let line = r#"217.198.191.213 - - [31/Jul/2026:15:33:55 +0000] "GET / HTTP/1.1" 200 832 "-" "Mozilla/5.0""#;
        let parsed = parse_line(LogFormat::Combined, line).unwrap();
        assert_eq!(parsed.timestamp_ns, "1785512035000000000");
        assert_eq!(parsed.remote_addr, Some("217.198.191.213".parse().unwrap()));
        assert_eq!(parsed.request_path.as_deref(), Some("/"));
        assert_eq!(parsed.status, Some(200));
        let value: Value = serde_json::from_str(&parsed.line).unwrap();
        assert_eq!(value["remote_addr"], "217.198.191.213");
        assert_eq!(value["remote_user"], "");
        assert_eq!(value["time_iso8601"], "2026-07-31T15:33:55+00:00");
        assert_eq!(value["method"], "GET");
        assert_eq!(value["request_method"], "GET");
        assert_eq!(value["path"], "/");
        assert_eq!(value["request"], "GET / HTTP/1.1");
        assert_eq!(value["request_uri"], "/");
        assert_eq!(value["args"], "");
        assert_eq!(value["protocol"], "HTTP/1.1");
        assert_eq!(value["server_protocol"], "HTTP/1.1");
        assert_eq!(value["status"], 200);
        assert_eq!(value["body_bytes_sent"], 832);
        assert_eq!(value["referer"], "");
        assert_eq!(value["http_referer"], "");
        assert_eq!(value["user_agent"], "Mozilla/5.0");
        assert_eq!(value["http_user_agent"], "Mozilla/5.0");
        assert_eq!(value["request_time"], 0.0);
        assert_eq!(value["geoip_country_code"], "");
        assert_eq!(value["geoip_country_iso3"], "");
        assert_eq!(value["geoip_city_name"], "");
        assert_eq!(value["geoip_latitude"], Value::Null);
        assert_eq!(value["geoip_longitude"], Value::Null);
        assert_eq!(value["message"], line);
    }

    #[test]
    fn parses_query_string_for_dashboard_request_uri() {
        let line = r#"192.168.111.186 - meka [31/Jul/2026:15:33:55 +0000] "GET /api/search?q=test HTTP/2.0" 200 53 "https://grafana.sys.it.com/" "Firefox""#;
        let parsed = parse_line(LogFormat::Combined, line).unwrap();
        assert_eq!(parsed.request_path.as_deref(), Some("/api/search"));
        let value: Value = serde_json::from_str(&parsed.line).unwrap();
        assert_eq!(value["request_uri"], "/api/search?q=test");
        assert_eq!(value["args"], "q=test");
        assert_eq!(value["http_referer"], "https://grafana.sys.it.com/");
        assert_eq!(value["remote_user"], "meka");
    }

    #[test]
    fn parses_json_rfc3339_timestamp() {
        let parsed = parse_line(
            LogFormat::Json,
            r#"{"time":"2026-07-31T15:33:55Z","status":200}"#,
        )
        .unwrap();
        assert_eq!(parsed.timestamp_ns, "1785512035000000000");
        assert_eq!(parsed.remote_addr, None);
        assert_eq!(parsed.status, Some(200));
    }

    #[test]
    fn parses_json_string_status() {
        let parsed = parse_line(
            LogFormat::Json,
            r#"{"time":"2026-07-31T15:33:55Z","status":"302"}"#,
        )
        .unwrap();
        assert_eq!(parsed.status, Some(302));
    }

    #[test]
    fn parses_json_remote_addr() {
        let parsed = parse_line(
            LogFormat::Json,
            r#"{"time":"2026-07-31T15:33:55Z","remote_addr":"2001:db8::1"}"#,
        )
        .unwrap();
        assert_eq!(parsed.remote_addr, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn parses_json_request_path() {
        let parsed = parse_line(
            LogFormat::Json,
            r#"{"time":"2026-07-31T15:33:55Z","request_uri":"/status?full=1"}"#,
        )
        .unwrap();
        assert_eq!(parsed.request_path.as_deref(), Some("/status"));

        let parsed = parse_line(
            LogFormat::Json,
            r#"{"time":"2026-07-31T15:33:55Z","request":"GET /api/ping?x=1 HTTP/2.0"}"#,
        )
        .unwrap();
        assert_eq!(parsed.request_path.as_deref(), Some("/api/ping"));
    }

    #[test]
    fn enriches_geoip() {
        let mut parsed = parse_line(
            LogFormat::Json,
            r#"{"time":"2026-07-31T15:33:55Z","remote_addr":"8.8.8.8"}"#,
        )
        .unwrap();
        parsed.set_geoip(
            "US",
            "USA",
            Some("Mountain View"),
            Some(37.386),
            Some(-122.0838),
        );
        let value: Value = serde_json::from_str(&parsed.line).unwrap();
        assert_eq!(value["geoip_country_code"], "US");
        assert_eq!(value["geoip_country_iso3"], "USA");
        assert_eq!(value["geoip_city_name"], "Mountain View");
        assert_eq!(value["geoip_latitude"], 37.386);
        assert_eq!(value["geoip_longitude"], -122.0838);
    }

    #[test]
    fn rejects_invalid_combined() {
        assert!(parse_line(LogFormat::Combined, "not nginx").is_err());
    }
}
