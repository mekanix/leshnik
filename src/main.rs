mod config;
mod geoip;
mod ip_filter;
mod logs;
mod loki;
mod tailer;

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use tracing_subscriber::filter::LevelFilter;

use crate::config::Config;

#[derive(Debug, Parser)]
#[command(version, about = "Watch nginx access logs and ship them to Loki")]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warning => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::from(args.log_level))
        .init();

    let config = Config::load(args.config)?;
    tailer::run(config)
}
