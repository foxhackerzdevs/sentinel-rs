use sentinel_rs::{
    detection::{
        event_for_process, event_for_socket, severity_for_filesystem_path, severity_for_process,
    },
    event::{EventKind, SecurityEvent, Severity},
    network::SocketInfo,
    process::ProcessInfo,
};
use std::path::Path;

#[test]
fn serializes_security_event_as_json() {
    let event = SecurityEvent::new(
        EventKind::MonitorStatus,
        Severity::Info,
        "test",
        "monitor initialized",
    )
    .with_detail("read_only", true);

    let json = event.to_json_line().expect("event should serialize");
    assert!(json.contains("\"kind\":\"monitor_status\""));
    assert!(json.contains("\"read_only\":true"));
}

#[test]
fn flags_deleted_executable_as_high_severity() {
    let process = ProcessInfo {
        pid: 42,
        name: Some("suspicious".into()),
        exe: Some("/usr/bin/suspicious (deleted)".into()),
        cmdline: None,
        uid: Some(1000),
    };

    assert_eq!(severity_for_process(&process), Severity::High);
}

#[test]
fn flags_root_tmp_executable_as_high_severity() {
    let process = ProcessInfo {
        pid: 43,
        name: Some("payload".into()),
        exe: Some("/tmp/payload".into()),
        cmdline: Some("/tmp/payload --quiet".into()),
        uid: Some(0),
    };

    let event = event_for_process(&process, EventKind::ProcessStart);
    assert_eq!(event.severity, Severity::High);
    assert_eq!(event.details["pid"], 43);
}

#[test]
fn flags_public_sensitive_listening_port_as_medium() {
    let socket = SocketInfo {
        protocol: "tcp".into(),
        local_address: "0.0.0.0".into(),
        local_port: 6379,
        inode: Some(123),
        process: None,
    };

    let event = event_for_socket(&socket);
    assert_eq!(event.severity, Severity::Medium);
    assert_eq!(event.kind, EventKind::ListeningSocket);
}

#[test]
fn flags_public_root_listener_as_high() {
    let socket = SocketInfo {
        protocol: "tcp".into(),
        local_address: "0.0.0.0".into(),
        local_port: 4444,
        inode: Some(53124),
        process: Some(ProcessInfo {
            pid: 1842,
            name: Some("listener".into()),
            exe: Some("/usr/local/bin/listener".into()),
            cmdline: Some("/usr/local/bin/listener --port 4444".into()),
            uid: Some(0),
        }),
    };

    let event = event_for_socket(&socket);

    assert_eq!(event.severity, Severity::High);
    assert_eq!(event.details["pid"], 1842);
    assert_eq!(event.details["process_uid"], 0);
    assert_eq!(
        event.details["process_cmdline"],
        "/usr/local/bin/listener --port 4444"
    );
}

#[test]
fn flags_temporary_path_listener_as_high() {
    let socket = SocketInfo {
        protocol: "tcp".into(),
        local_address: "127.0.0.1".into(),
        local_port: 9001,
        inode: Some(6001),
        process: Some(ProcessInfo {
            pid: 99,
            name: Some("payload".into()),
            exe: Some("/tmp/payload".into()),
            cmdline: None,
            uid: Some(1000),
        }),
    };

    assert_eq!(event_for_socket(&socket).severity, Severity::High);
}

#[test]
fn flags_deleted_executable_listener_as_high() {
    let socket = SocketInfo {
        protocol: "tcp".into(),
        local_address: "127.0.0.1".into(),
        local_port: 9002,
        inode: Some(6002),
        process: Some(ProcessInfo {
            pid: 100,
            name: Some("stale".into()),
            exe: Some("/usr/bin/stale (deleted)".into()),
            cmdline: None,
            uid: Some(1000),
        }),
    };

    assert_eq!(event_for_socket(&socket).severity, Severity::High);
}

#[test]
fn classifies_filesystem_paths_by_sensitivity() {
    assert_eq!(
        severity_for_filesystem_path(Path::new("/etc/passwd")),
        Severity::Medium
    );
    assert_eq!(
        severity_for_filesystem_path(Path::new("/tmp/example")),
        Severity::Low
    );
}
