use crate::{
    baseline::{BaselineAllowlistConfig, BaselineStore},
    detection::{severity_for_process, severity_for_socket},
    event::{EventKind, SecurityEvent, Severity},
    network::SocketInfo,
    process::ProcessInfo,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketOwner {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub executable: Option<String>,
    pub uid: Option<u32>,
}

impl From<&ProcessInfo> for SocketOwner {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: Some(process.pid),
            name: process.name.clone(),
            executable: process.exe.clone(),
            uid: process.uid,
        }
    }
}

impl From<Option<&ProcessInfo>> for SocketOwner {
    fn from(process: Option<&ProcessInfo>) -> Self {
        match process {
            Some(process) => process.into(),
            None => Self {
                pid: None,
                name: None,
                executable: None,
                uid: None,
            },
        }
    }
}

pub enum Anomaly {
    FirstSeenProcess {
        process: ProcessInfo,
    },

    FirstSeenListener {
        socket: SocketInfo,
    },

    ListenerOwnerChanged {
        previous: SocketOwner,
        current: SocketOwner,
    },
}

pub fn detect_new_processes(
    processes: &[ProcessInfo],
    baseline: &BaselineStore,
    allowlist: &BaselineAllowlistConfig,
) -> Vec<ProcessInfo> {
    processes
        .iter()
        .filter(|process| !allowlisted_process(process, allowlist))
        .filter(|process| !baseline.contains_process(process))
        .cloned()
        .collect()
}

pub fn detect_new_listeners(
    sockets: &[SocketInfo],
    baseline: &BaselineStore,
    allowlist: &BaselineAllowlistConfig,
) -> Vec<SocketInfo> {
    sockets
        .iter()
        .filter(|socket| !allowlisted_listener(socket, allowlist))
        .filter(|socket| !baseline.contains_listener(socket))
        .cloned()
        .collect()
}

pub fn event_for_first_seen_process(process: &ProcessInfo) -> SecurityEvent {
    let severity = default_process_severity(process);
    let mut event = SecurityEvent::new(
        EventKind::FirstSeenProcess,
        severity,
        "baseline",
        format!(
            "new process observed: {}",
            process.name.as_deref().unwrap_or("unknown")
        ),
    )
    .with_detail("pid", process.pid)
    .with_detail("name", &process.name)
    .with_detail("exe", &process.exe)
    .with_detail("uid", process.uid);

    if let Some(cmdline) = &process.cmdline {
        event = event.with_detail("cmdline", cmdline);
    }

    event
}

pub fn event_for_first_seen_listener(socket: &SocketInfo) -> SecurityEvent {
    let severity = default_listener_severity(socket);
    let mut event = SecurityEvent::new(
        EventKind::FirstSeenListener,
        severity,
        "baseline",
        format!(
            "new listener observed: {} {}:{}",
            socket.protocol, socket.local_address, socket.local_port
        ),
    )
    .with_detail("protocol", &socket.protocol)
    .with_detail("local_address", &socket.local_address)
    .with_detail("local_port", socket.local_port)
    .with_detail("inode", socket.inode);

    if let Some(process) = &socket.process {
        event = event
            .with_detail("pid", process.pid)
            .with_detail("process_name", &process.name)
            .with_detail("process_exe", &process.exe)
            .with_detail("process_uid", process.uid);

        if let Some(cmdline) = &process.cmdline {
            event = event.with_detail("process_cmdline", cmdline);
        }
    }

    event
}

pub fn event_for_listener_owner_change(
    change: &crate::network::SocketOwnerChange,
) -> SecurityEvent {
    let previous = SocketOwner::from(change.previous.as_ref());
    let current = SocketOwner::from(change.current.as_ref());

    SecurityEvent::new(
        EventKind::ListenerOwnerChanged,
        Severity::High,
        "baseline",
        format!(
            "listener owner changed on {} {}:{}",
            change.socket.protocol, change.socket.local_address, change.socket.local_port
        ),
    )
    .with_detail("protocol", &change.socket.protocol)
    .with_detail("local_address", &change.socket.local_address)
    .with_detail("local_port", change.socket.local_port)
    .with_detail("inode", change.socket.inode)
    .with_detail("previous_pid", previous.pid)
    .with_detail("previous_name", &previous.name)
    .with_detail("previous_exe", &previous.executable)
    .with_detail("previous_uid", previous.uid)
    .with_detail("current_pid", current.pid)
    .with_detail("current_name", &current.name)
    .with_detail("current_exe", &current.executable)
    .with_detail("current_uid", current.uid)
}

pub fn event_for_baseline_initialized(
    process_count: usize,
    listener_count: usize,
) -> SecurityEvent {
    SecurityEvent::new(
        EventKind::BaselineInitialized,
        Severity::Info,
        "baseline",
        "baseline initialized",
    )
    .with_detail("process_count", process_count)
    .with_detail("listener_count", listener_count)
}

pub fn allowlisted_process(process: &ProcessInfo, allowlist: &BaselineAllowlistConfig) -> bool {
    process.exe.as_deref().is_some_and(|exe| {
        allowlist
            .process_executables
            .iter()
            .any(|entry| entry == exe)
    })
}

pub fn allowlisted_listener(socket: &SocketInfo, allowlist: &BaselineAllowlistConfig) -> bool {
    let exe_match = socket
        .process
        .as_ref()
        .and_then(|process| process.exe.as_deref())
        .is_some_and(|exe| {
            allowlist
                .listener_executables
                .iter()
                .any(|entry| entry == exe)
        });

    exe_match || allowlist.listener_ports.contains(&socket.local_port)
}

fn default_process_severity(process: &ProcessInfo) -> Severity {
    match severity_for_process(process) {
        Severity::Info => Severity::Low,
        Severity::Low | Severity::Medium | Severity::High => severity_for_process(process),
    }
}

fn default_listener_severity(socket: &SocketInfo) -> Severity {
    match severity_for_socket(socket) {
        Severity::Info | Severity::Low => Severity::Medium,
        Severity::Medium | Severity::High => severity_for_socket(socket),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        detect_new_listeners, detect_new_processes, event_for_first_seen_listener,
        event_for_first_seen_process, event_for_listener_owner_change, BaselineAllowlistConfig,
    };
    use crate::{
        baseline::BaselineStore,
        event::{EventKind, Severity},
        network::{SocketInfo, SocketOwnerChange},
        process::ProcessInfo,
    };

    fn process(pid: u32, exe: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: Some("worker".into()),
            exe: Some(exe.into()),
            cmdline: None,
            uid: Some(1000),
        }
    }

    fn listener(inode: u64, port: u16, process: Option<ProcessInfo>) -> SocketInfo {
        SocketInfo {
            protocol: "tcp".into(),
            local_address: "0.0.0.0".into(),
            local_port: port,
            inode: Some(inode),
            process,
        }
    }

    #[test]
    fn detects_first_seen_process_and_ignores_known_process() {
        let known = process(1, "/usr/bin/known");
        let new = process(2, "/usr/bin/new");
        let mut baseline = BaselineStore::empty("baseline.json");
        baseline.add_process(&known);

        let detected = detect_new_processes(
            &[known.clone(), new.clone()],
            &baseline,
            &BaselineAllowlistConfig::default(),
        );

        assert_eq!(detected, vec![new]);
    }

    #[test]
    fn process_executable_allowlist_suppresses_detection() {
        let process = process(1, "/usr/local/bin/approved");
        let allowlist = BaselineAllowlistConfig {
            process_executables: vec!["/usr/local/bin/approved".into()],
            ..BaselineAllowlistConfig::default()
        };

        let detected = detect_new_processes(
            &[process],
            &BaselineStore::empty("baseline.json"),
            &allowlist,
        );

        assert!(detected.is_empty());
    }

    #[test]
    fn detects_first_seen_listener_and_applies_allowlist() {
        let approved = listener(1, 22, Some(process(1, "/usr/sbin/sshd")));
        let new = listener(2, 8080, Some(process(2, "/usr/bin/service")));
        let allowlist = BaselineAllowlistConfig {
            listener_executables: vec!["/usr/sbin/sshd".into()],
            listener_ports: vec![9090],
            ..BaselineAllowlistConfig::default()
        };

        let detected = detect_new_listeners(
            &[approved, new.clone()],
            &BaselineStore::empty("baseline.json"),
            &allowlist,
        );

        assert_eq!(detected, vec![new]);
    }

    #[test]
    fn listener_port_allowlist_suppresses_detection() {
        let socket = listener(1, 8080, None);
        let allowlist = BaselineAllowlistConfig {
            listener_ports: vec![8080],
            ..BaselineAllowlistConfig::default()
        };

        let detected = detect_new_listeners(
            &[socket],
            &BaselineStore::empty("baseline.json"),
            &allowlist,
        );

        assert!(detected.is_empty());
    }

    #[test]
    fn anomaly_events_have_expected_kind_and_default_severity() {
        let process_event = event_for_first_seen_process(&process(1, "/usr/bin/worker"));
        assert_eq!(process_event.kind, EventKind::FirstSeenProcess);
        assert_eq!(process_event.severity, Severity::Low);

        let listener_event = event_for_first_seen_listener(&listener(1, 8080, None));
        assert_eq!(listener_event.kind, EventKind::FirstSeenListener);
        assert_eq!(listener_event.severity, Severity::Medium);
    }

    #[test]
    fn owner_change_event_includes_previous_and_current_owners() {
        let change = SocketOwnerChange {
            previous: Some(process(1, "/usr/bin/old")),
            current: Some(process(2, "/tmp/new")),
            socket: listener(10, 8080, Some(process(2, "/tmp/new"))),
        };

        let event = event_for_listener_owner_change(&change);

        assert_eq!(event.kind, EventKind::ListenerOwnerChanged);
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.details["previous_pid"], 1);
        assert_eq!(event.details["current_pid"], 2);
        assert_eq!(event.details["previous_exe"], "/usr/bin/old");
        assert_eq!(event.details["current_exe"], "/tmp/new");
    }
}
