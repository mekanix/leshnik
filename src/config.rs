use std::{collections::BTreeMap, fs, path::Path};

use anyhow::Context;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub geoip: Option<GeoIpConfig>,
    pub loki: LokiConfig,
    pub watch: Vec<WatchConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeoIpConfig {
    pub database: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LokiConfig {
    pub url: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WatchConfig {
    pub glob: String,
    #[serde(default)]
    pub ignore: Vec<String>,
    #[serde(default)]
    pub ignore_ips: Vec<String>,
    #[serde(default)]
    pub ignore_paths: Vec<String>,
    #[serde(default)]
    pub ignore_status: Vec<u16>,
    pub format: LogFormat,
    #[serde(default)]
    pub from_beginning: bool,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Combined,
    Json,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read config {}", path.display()))?;
        let config: Self = toml::from_str(&contents)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        if config.watch.is_empty() {
            anyhow::bail!("config must contain at least one [[watch]] entry");
        }
        if config.loki.batch_size == 0 {
            anyhow::bail!("loki.batch_size must be greater than zero");
        }
        Ok(config)
    }
}

fn default_batch_size() -> usize {
    100
}

fn default_batch_timeout_ms() -> u64 {
    1_000
}

fn default_timeout_secs() -> u64 {
    10
}
