use crate::event::{EventKind, SecurityEvent, Severity};
use chrono::{DateTime, Duration, Utc};
use serde_json::Value;
use std::{
    collections::{hash_map::DefaultHasher, HashSet, VecDeque},
    hash::{Hash, Hasher},
    time::Duration as StdDuration,
};

#[derive(Debug)]
pub struct CorrelationState {
    window: Duration,
    recent: VecDeque<SecurityEvent>,
    emitted: HashSet<String>,
}

impl CorrelationState {
    pub fn new(window: StdDuration) -> Self {
        let window = Duration::from_std(window).unwrap_or_else(|_| Duration::seconds(300));
        Self {
            window,
            recent: VecDeque::new(),
            emitted: HashSet::new(),
        }
    }

    pub fn observe(&mut self, events: &[SecurityEvent]) -> Vec<SecurityEvent> {
        let mut correlated = Vec::new();
        for event in events {
            self.expire(event.timestamp);
            self.recent.push_back(event.clone());
            if let Some(correlation) = self.correlate(event) {
                correlated.push(correlation);
            }
        }
        correlated
    }

    fn expire(&mut self, now: DateTime<Utc>) {
        while self
            .recent
            .front()
            .is_some_and(|event| now - event.timestamp > self.window)
        {
            self.recent.pop_front();
        }
    }

    fn correlate(&mut self, current: &SecurityEvent) -> Option<SecurityEvent> {
        let executable =
            detail_string(current, "process_exe").or_else(|| detail_string(current, "exe"))?;

        let file_event = self.recent.iter().find(|event| {
            matches!(event.kind, EventKind::FileCreated | EventKind::FileModified)
                && detail_string(event, "path").as_deref() == Some(executable.as_str())
        })?;
        let process_event = self.recent.iter().find(|event| {
            matches!(
                event.kind,
                EventKind::ProcessStart | EventKind::FirstSeenProcess
            ) && detail_string(event, "exe").as_deref() == Some(executable.as_str())
        })?;
        let network_event = self.recent.iter().find(|event| {
            matches!(
                event.kind,
                EventKind::ListeningSocket
                    | EventKind::FirstSeenListener
                    | EventKind::FirstSeenConnection
                    | EventKind::ProcessNetworkBehaviorChanged
            ) && detail_string(event, "process_exe").as_deref() == Some(executable.as_str())
        })?;

        let key = format!(
            "{}:{}:{}",
            executable,
            file_event.kind_as_key(),
            network_event.kind_as_key()
        );
        if !self.emitted.insert(key.clone()) {
            return None;
        }

        let mut event = SecurityEvent::new(
            EventKind::CorrelatedActivity,
            Severity::High,
            "correlation",
            format!("correlated filesystem, process, and network activity for {executable}"),
        )
        .with_detail("correlation_id", correlation_id(&key))
        .with_detail("executable", &executable)
        .with_detail("file_event", file_event.kind_as_key())
        .with_detail("process_event", process_event.kind_as_key())
        .with_detail("network_event", network_event.kind_as_key());

        if let Some(path) = detail_string(file_event, "path") {
            event = event.with_detail("path", path);
        }
        if let Some(remote_address) = detail_string(network_event, "remote_address") {
            event = event.with_detail("remote_address", remote_address);
        }
        if let Some(remote_port) = network_event.details.get("remote_port") {
            event = event.with_detail("remote_port", remote_port);
        }
        Some(event)
    }
}

fn detail_string(event: &SecurityEvent, key: &str) -> Option<String> {
    event
        .details
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn correlation_id(key: &str) -> String {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    format!("corr-{:016x}", hasher.finish())
}

trait EventKindKey {
    fn kind_as_key(&self) -> &'static str;
}

impl EventKindKey for SecurityEvent {
    fn kind_as_key(&self) -> &'static str {
        match self.kind {
            EventKind::FileCreated => "file_created",
            EventKind::FileModified => "file_modified",
            EventKind::ProcessStart => "process_start",
            EventKind::FirstSeenProcess => "first_seen_process",
            EventKind::ListeningSocket => "listening_socket",
            EventKind::FirstSeenListener => "first_seen_listener",
            EventKind::FirstSeenConnection => "first_seen_connection",
            EventKind::ProcessNetworkBehaviorChanged => "process_network_behavior_changed",
            _ => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CorrelationState;
    use crate::event::{EventKind, SecurityEvent, Severity};
    use std::time::Duration;

    fn file(path: &str) -> SecurityEvent {
        SecurityEvent::new(
            EventKind::FileCreated,
            Severity::Low,
            "filesystem",
            "created",
        )
        .with_detail("path", path)
    }

    fn process(exe: &str) -> SecurityEvent {
        SecurityEvent::new(EventKind::ProcessStart, Severity::Low, "process", "started")
            .with_detail("exe", exe)
    }

    fn network(exe: &str) -> SecurityEvent {
        SecurityEvent::new(
            EventKind::FirstSeenConnection,
            Severity::Medium,
            "behavior",
            "connection",
        )
        .with_detail("process_exe", exe)
        .with_detail("remote_address", "203.0.113.10")
        .with_detail("remote_port", 4444)
    }

    #[test]
    fn correlates_file_process_and_network_sequence() {
        let mut state = CorrelationState::new(Duration::from_secs(300));
        let events = [
            file("/tmp/payload"),
            process("/tmp/payload"),
            network("/tmp/payload"),
        ];
        let correlated = state.observe(&events);

        assert_eq!(correlated.len(), 1);
        assert_eq!(correlated[0].kind, EventKind::CorrelatedActivity);
        assert_eq!(correlated[0].severity, Severity::High);
        assert_eq!(correlated[0].details["remote_port"], 4444);
    }

    #[test]
    fn deduplicates_repeated_sequences() {
        let mut state = CorrelationState::new(Duration::from_secs(300));
        let events = [
            file("/tmp/payload"),
            process("/tmp/payload"),
            network("/tmp/payload"),
        ];

        assert_eq!(state.observe(&events).len(), 1);
        assert!(state.observe(&events).is_empty());
    }
}
