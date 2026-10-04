use crate::{
    detection::severity_for_filesystem_path,
    event::{EventKind, SecurityEvent},
};
use anyhow::{Context, Result};
use notify::{
    Config, Event, EventKind as NotifyEventKind, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver},
};

pub struct FilesystemMonitor {
    _watcher: RecommendedWatcher,
    receiver: Receiver<notify::Result<Event>>,
}

impl FilesystemMonitor {
    pub fn new(paths: &[String], recursive: bool) -> Result<Self> {
        let (sender, receiver) = mpsc::channel();
        let mut watcher = RecommendedWatcher::new(sender, Config::default())
            .context("failed to create filesystem watcher")?;

        let mode = if recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        for path in paths {
            watcher
                .watch(Path::new(path), mode)
                .with_context(|| format!("failed to watch filesystem path {path}"))?;
        }

        Ok(Self {
            _watcher: watcher,
            receiver,
        })
    }

    pub fn drain_events(&self) -> Vec<SecurityEvent> {
        let mut events = Vec::new();
        while let Ok(result) = self.receiver.try_recv() {
            match result {
                Ok(event) => events.extend(event_to_security_events(event)),
                Err(error) => events.push(SecurityEvent::new(
                    EventKind::MonitorStatus,
                    crate::event::Severity::Low,
                    "filesystem",
                    format!("filesystem watcher error: {error}"),
                )),
            }
        }
        events
    }
}

pub fn event_to_security_events(event: Event) -> Vec<SecurityEvent> {
    let kind = match event.kind {
        NotifyEventKind::Create(_) => EventKind::FileCreated,
        NotifyEventKind::Modify(_) => EventKind::FileModified,
        NotifyEventKind::Remove(_) => EventKind::FileRemoved,
        _ => EventKind::FileOther,
    };

    event
        .paths
        .into_iter()
        .map(|path| event_for_path(kind.clone(), path))
        .collect()
}

fn event_for_path(kind: EventKind, path: PathBuf) -> SecurityEvent {
    SecurityEvent::new(
        kind,
        severity_for_filesystem_path(&path),
        "filesystem",
        format!("filesystem event for {}", path.display()),
    )
    .with_detail("path", path.to_string_lossy().to_string())
}
