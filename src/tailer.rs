use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufRead, BufReader, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::Context;
use glob::{glob, Pattern};
use inotify::{Inotify, WatchDescriptor, WatchMask};
use tracing::{debug, error, info, warn};

use crate::{
    config::{Config, LogFormat, WatchConfig},
    geoip::{self, GeoIp},
    ip_filter::IpMatcher,
    logs::parse_line,
    loki::LokiClient,
};

#[derive(Debug, Clone)]
pub struct WatchSpec {
    pub glob: String,
    pub ignore: Vec<Pattern>,
    pub ignore_ips: Vec<IpMatcher>,
    pub ignore_paths: Vec<Pattern>,
    pub ignore_status: Vec<u16>,
    pub format: LogFormat,
    pub from_beginning: bool,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug)]
struct WatchedFile {
    path: PathBuf,
    format: LogFormat,
    labels: BTreeMap<String, String>,
    ignore_ips: Vec<IpMatcher>,
    ignore_paths: Vec<Pattern>,
    ignore_status: Vec<u16>,
    reader: BufReader<File>,
    dev: u64,
    ino: u64,
    offset: u64,
    watch: WatchDescriptor,
}

pub fn run(config: Config) -> anyhow::Result<()> {
    let loki = LokiClient::new(&config.loki)?;
    let geoip = geoip::open(config.geoip.as_ref());
    let specs = config
        .watch
        .iter()
        .map(|watch| to_spec(&config.loki.labels, watch))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut inotify = Inotify::init().context("failed to initialize inotify")?;
    let mut directories = HashMap::<PathBuf, WatchDescriptor>::new();
    let mut files = HashMap::<PathBuf, WatchedFile>::new();

    info!("starting inotify log tailer");
    reconcile_dirs(&mut inotify, &specs, &mut directories)?;
    reconcile_files(&mut inotify, &specs, &mut files)?;

    let mut batch = loki.batch();
    let mut buffer = [0_u8; 16 * 1024];
    let mut should_read = true;

    loop {
        let mut should_reconcile = false;
        if should_read {
            read_all_files(&loki, geoip.as_ref(), &mut batch, &mut files);
            should_read = false;
        }
        flush_if_due(&loki, &mut batch);

        match inotify.read_events(&mut buffer) {
            Ok(events) => {
                for event in events {
                    debug!(mask = ?event.mask, name = ?event.name, "inotify event");
                    should_read = true;
                    should_reconcile = true;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(err) => warn!(error = %err, "inotify read failed"),
        }

        if should_reconcile {
            read_all_files(&loki, geoip.as_ref(), &mut batch, &mut files);
            if let Err(err) = reconcile_dirs(&mut inotify, &specs, &mut directories) {
                warn!(error = %err, "failed to reconcile watched directories");
            }
            if let Err(err) = reconcile_files(&mut inotify, &specs, &mut files) {
                warn!(error = %err, "failed to reconcile watched log files");
            }
            read_all_files(&loki, geoip.as_ref(), &mut batch, &mut files);
            should_read = false;
            flush_if_due(&loki, &mut batch);
        }

        thread::sleep(Duration::from_millis(250));
    }
}

fn to_spec(
    global_labels: &BTreeMap<String, String>,
    watch: &WatchConfig,
) -> anyhow::Result<WatchSpec> {
    let mut labels = global_labels.clone();
    labels.extend(watch.labels.clone());
    let ignore = watch
        .ignore
        .iter()
        .map(|pattern| {
            Pattern::new(pattern).with_context(|| {
                format!(
                    "invalid ignore glob pattern {pattern:?} for watch {}",
                    watch.glob
                )
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let ignore_ips = watch
        .ignore_ips
        .iter()
        .map(|matcher| {
            IpMatcher::parse(matcher).with_context(|| {
                format!(
                    "invalid ignore IP matcher {matcher:?} for watch {}",
                    watch.glob
                )
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let ignore_paths = watch
        .ignore_paths
        .iter()
        .map(|pattern| {
            Pattern::new(pattern).with_context(|| {
                format!(
                    "invalid ignore path glob pattern {pattern:?} for watch {}",
                    watch.glob
                )
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(WatchSpec {
        glob: watch.glob.clone(),
        ignore,
        ignore_ips,
        ignore_paths,
        ignore_status: watch.ignore_status.clone(),
        format: watch.format,
        from_beginning: watch.from_beginning,
        labels,
    })
}

fn read_all_files(
    loki: &LokiClient,
    geoip: Option<&GeoIp>,
    batch: &mut crate::loki::LokiBatch,
    files: &mut HashMap<PathBuf, WatchedFile>,
) {
    for file in files.values_mut() {
        match file.read_new_lines(loki, geoip, batch) {
            Ok(lines) if lines > 0 => {
                info!(path = %file.path.display(), lines, "queued log lines");
            }
            Ok(_) => {}
            Err(err) => {
                warn!(path = %file.path.display(), error = %err, "failed to read log file");
            }
        }
    }
}

fn flush_if_due(loki: &LokiClient, batch: &mut crate::loki::LokiBatch) {
    if let Err(err) = batch.flush_if_due(loki) {
        error!(error = %err, "failed to flush loki batch");
    }
}

fn reconcile_dirs(
    inotify: &mut Inotify,
    specs: &[WatchSpec],
    directories: &mut HashMap<PathBuf, WatchDescriptor>,
) -> anyhow::Result<()> {
    for spec in specs {
        let parent = glob_parent(&spec.glob);
        if directories.contains_key(&parent) {
            continue;
        }
        let watch = inotify
            .watches()
            .add(
                &parent,
                WatchMask::CREATE
                    | WatchMask::MOVED_TO
                    | WatchMask::MOVED_FROM
                    | WatchMask::DELETE
                    | WatchMask::DELETE_SELF
                    | WatchMask::MOVE_SELF
                    | WatchMask::ATTRIB,
            )
            .with_context(|| format!("failed to watch directory {}", parent.display()))?;
        info!(path = %parent.display(), "watching directory");
        directories.insert(parent, watch);
    }
    Ok(())
}

fn reconcile_files(
    inotify: &mut Inotify,
    specs: &[WatchSpec],
    files: &mut HashMap<PathBuf, WatchedFile>,
) -> anyhow::Result<()> {
    for spec in specs {
        for entry in glob(&spec.glob).with_context(|| format!("invalid glob {}", spec.glob))? {
            let path = match entry {
                Ok(path) => path,
                Err(err) => {
                    warn!(error = %err, "glob entry failed");
                    continue;
                }
            };
            if !path.is_file() {
                continue;
            }
            if spec.is_ignored(&path) {
                debug!(path = %path.display(), glob = %spec.glob, "ignoring matched log file");
                continue;
            }
            let should_replace = match files.get(&path) {
                Some(existing) => existing.replaced_on_disk().unwrap_or(true),
                None => true,
            };
            if should_replace {
                if let Some(old) = files.remove(&path) {
                    remove_watch(inotify, &path, old.watch);
                }
                match WatchedFile::open(inotify, path.clone(), spec) {
                    Ok(file) => {
                        info!(path = %path.display(), "watching log file");
                        files.insert(path, file);
                    }
                    Err(err) => {
                        warn!(path = %path.display(), error = %err, "failed to open log file")
                    }
                }
            }
        }
    }
    Ok(())
}

impl WatchSpec {
    fn is_ignored(&self, path: &Path) -> bool {
        self.ignore.iter().any(|pattern| pattern.matches_path(path))
    }
}

fn remove_watch(inotify: &mut Inotify, path: &Path, watch: WatchDescriptor) {
    if let Err(err) = inotify.watches().remove(watch) {
        debug!(path = %path.display(), error = %err, "failed to remove stale watch");
    }
}

fn glob_parent(pattern: &str) -> PathBuf {
    let magic = pattern.find(['*', '?', '[', '{']).unwrap_or(pattern.len());
    let prefix = &pattern[..magic];
    let path = Path::new(prefix);
    if prefix.ends_with('/') {
        return path.to_path_buf();
    }
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

impl WatchedFile {
    fn open(inotify: &mut Inotify, path: PathBuf, spec: &WatchSpec) -> anyhow::Result<Self> {
        let mut file = File::open(&path)
            .with_context(|| format!("failed to open log file {}", path.display()))?;
        let metadata = file.metadata()?;
        let mut labels = spec.labels.clone();
        labels.insert("filename".to_owned(), path.display().to_string());
        let offset = if spec.from_beginning {
            0
        } else {
            metadata.len()
        };
        let watch = inotify
            .watches()
            .add(
                &path,
                WatchMask::MODIFY
                    | WatchMask::CLOSE_WRITE
                    | WatchMask::ATTRIB
                    | WatchMask::DELETE_SELF
                    | WatchMask::MOVE_SELF,
            )
            .with_context(|| format!("failed to watch log file {}", path.display()))?;
        file.seek(SeekFrom::Start(offset))?;
        Ok(Self {
            path,
            format: spec.format,
            labels,
            ignore_ips: spec.ignore_ips.clone(),
            ignore_paths: spec.ignore_paths.clone(),
            ignore_status: spec.ignore_status.clone(),
            reader: BufReader::new(file),
            dev: metadata.dev(),
            ino: metadata.ino(),
            offset,
            watch,
        })
    }

    fn replaced_on_disk(&self) -> anyhow::Result<bool> {
        let metadata = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        Ok(metadata.dev() != self.dev || metadata.ino() != self.ino)
    }

    fn truncated_on_disk(&self) -> anyhow::Result<bool> {
        let metadata = match std::fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(err) => return Err(err.into()),
        };
        Ok(
            metadata.dev() == self.dev
                && metadata.ino() == self.ino
                && metadata.len() < self.offset,
        )
    }

    fn rewind_if_truncated(&mut self) -> anyhow::Result<bool> {
        if !self.truncated_on_disk()? {
            return Ok(false);
        }
        self.reader.seek(SeekFrom::Start(0))?;
        self.offset = 0;
        info!(path = %self.path.display(), "rewound truncated log file");
        Ok(true)
    }

    fn read_new_lines(
        &mut self,
        loki: &LokiClient,
        geoip: Option<&GeoIp>,
        batch: &mut crate::loki::LokiBatch,
    ) -> anyhow::Result<usize> {
        let mut lines = self.drain_current(loki, geoip, batch)?;
        if self.rewind_if_truncated()? {
            lines += self.drain_current(loki, geoip, batch)?;
        }
        Ok(lines)
    }

    fn drain_current(
        &mut self,
        loki: &LokiClient,
        geoip: Option<&GeoIp>,
        batch: &mut crate::loki::LokiBatch,
    ) -> anyhow::Result<usize> {
        let mut lines = 0;
        loop {
            let mut line = String::new();
            let bytes = self.reader.read_line(&mut line)?;
            if bytes == 0 {
                break;
            }
            self.offset += bytes as u64;
            while line.ends_with(['\n', '\r']) {
                line.pop();
            }
            if line.is_empty() {
                continue;
            }
            match parse_line(self.format, &line) {
                Ok(mut parsed) => {
                    if parsed
                        .status
                        .is_some_and(|status| self.ignore_status.contains(&status))
                    {
                        debug!(path = %self.path.display(), status = ?parsed.status, "skipping ignored HTTP status");
                        continue;
                    }
                    if let Some(request_path) = parsed.request_path.as_deref() {
                        if self
                            .ignore_paths
                            .iter()
                            .any(|pattern| pattern.matches(request_path))
                        {
                            debug!(path = %self.path.display(), request_path, "skipping ignored URL path");
                            continue;
                        }
                    }
                    if let Some(remote_addr) = parsed.remote_addr {
                        if self
                            .ignore_ips
                            .iter()
                            .any(|matcher| matcher.matches(remote_addr))
                        {
                            debug!(path = %self.path.display(), %remote_addr, "skipping ignored remote address");
                            continue;
                        }
                        if let Some(record) = geoip.and_then(|geoip| geoip.lookup(remote_addr)) {
                            parsed.set_geoip(
                                &record.iso2,
                                &record.iso3,
                                record.city_name.as_deref(),
                                record.latitude,
                                record.longitude,
                            );
                        }
                    }
                    batch.push(loki, self.labels.clone(), parsed)?;
                    lines += 1;
                }
                Err(err) => {
                    warn!(path = %self.path.display(), error = %err, line, "skipping unparsable log line")
                }
            }
        }
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_parent_before_glob_magic() {
        assert_eq!(
            glob_parent("/var/log/nginx/*.log"),
            PathBuf::from("/var/log/nginx")
        );
        assert_eq!(glob_parent("logs/**/*.log"), PathBuf::from("logs"));
        assert_eq!(glob_parent("*.log"), PathBuf::from("."));
    }

    #[test]
    fn watch_spec_ignores_matching_paths() {
        let spec = WatchSpec {
            glob: "/var/log/nginx/*.log".to_owned(),
            ignore: vec![
                Pattern::new("/var/log/nginx/error.log").unwrap(),
                Pattern::new("/var/log/nginx/*.old.log").unwrap(),
            ],
            ignore_ips: Vec::new(),
            ignore_paths: vec![Pattern::new("/stub_status").unwrap()],
            ignore_status: vec![301, 302],
            format: LogFormat::Combined,
            from_beginning: false,
            labels: BTreeMap::new(),
        };

        assert!(spec.is_ignored(Path::new("/var/log/nginx/error.log")));
        assert!(spec.is_ignored(Path::new("/var/log/nginx/access.old.log")));
        assert!(!spec.is_ignored(Path::new("/var/log/nginx/access.log")));
    }

    #[test]
    fn url_path_ignore_patterns_use_globs() {
        let patterns = [Pattern::new("/api/*").unwrap()];

        assert!(patterns.iter().any(|pattern| pattern.matches("/api/ping")));
        assert!(patterns
            .iter()
            .any(|pattern| pattern.matches("/api/v1/users")));
        assert!(!patterns
            .iter()
            .any(|pattern| pattern.matches("/assets/app.css")));
    }
}
