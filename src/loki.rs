use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use anyhow::Context;
use reqwest::blocking::Client;
use serde::Serialize;
use tracing::info;

use crate::{config::LokiConfig, logs::ParsedLine};

#[derive(Debug, Clone)]
pub struct LokiClient {
    client: Client,
    url: String,
    tenant_id: Option<String>,
    batch_size: usize,
    batch_timeout: Duration,
}

#[derive(Debug)]
pub struct LokiBatch {
    entries: Vec<LokiEntry>,
    max_size: usize,
    last_flush: Instant,
    flush_after: Duration,
}

#[derive(Debug)]
struct LokiEntry {
    labels: BTreeMap<String, String>,
    line: ParsedLine,
}

#[derive(Debug, Serialize)]
struct PushRequest {
    streams: Vec<PushStream>,
}

#[derive(Debug, Serialize)]
struct PushStream {
    stream: BTreeMap<String, String>,
    values: Vec<[String; 2]>,
}

impl LokiClient {
    pub fn new(config: &LokiConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(config.timeout_secs))
                .build()
                .context("failed to build HTTP client")?,
            url: config.url.clone(),
            tenant_id: config
                .tenant_id
                .as_ref()
                .filter(|tenant| !tenant.is_empty())
                .cloned(),
            batch_size: config.batch_size,
            batch_timeout: Duration::from_millis(config.batch_timeout_ms),
        })
    }

    pub fn batch(&self) -> LokiBatch {
        LokiBatch {
            entries: Vec::with_capacity(self.batch_size),
            max_size: self.batch_size,
            last_flush: Instant::now(),
            flush_after: self.batch_timeout,
        }
    }

    pub fn push(&self, entries: Vec<(BTreeMap<String, String>, ParsedLine)>) -> anyhow::Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let line_count = entries.len();

        let mut streams: BTreeMap<BTreeMap<String, String>, Vec<[String; 2]>> = BTreeMap::new();
        for (labels, line) in entries {
            streams
                .entry(labels)
                .or_default()
                .push([line.timestamp_ns, line.line]);
        }

        let request = PushRequest {
            streams: streams
                .into_iter()
                .map(|(stream, values)| PushStream { stream, values })
                .collect(),
        };

        let mut builder = self.client.post(&self.url).json(&request);
        if let Some(tenant_id) = &self.tenant_id {
            builder = builder.header("X-Scope-OrgID", tenant_id);
        }

        let response = builder.send().context("failed to send batch to loki")?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().unwrap_or_default();
            anyhow::bail!("loki rejected batch with HTTP {status}: {body}");
        }
        info!(
            lines = line_count,
            streams = request.streams.len(),
            "pushed log batch to loki"
        );
        Ok(())
    }
}

impl LokiBatch {
    pub fn push(
        &mut self,
        client: &LokiClient,
        labels: BTreeMap<String, String>,
        line: ParsedLine,
    ) -> anyhow::Result<()> {
        self.entries.push(LokiEntry { labels, line });
        if self.entries.len() >= self.max_size {
            self.flush(client)?;
        }
        Ok(())
    }

    pub fn flush_if_due(&mut self, client: &LokiClient) -> anyhow::Result<()> {
        if !self.entries.is_empty() && self.last_flush.elapsed() >= self.flush_after {
            self.flush(client)?;
        }
        Ok(())
    }

    pub fn flush(&mut self, client: &LokiClient) -> anyhow::Result<()> {
        let entries = self
            .entries
            .drain(..)
            .map(|entry| (entry.labels, entry.line))
            .collect();
        client.push(entries)?;
        self.last_flush = Instant::now();
        Ok(())
    }
}
