use crate::{
    event::{EventKind, SecurityEvent, Severity},
    network::SocketInfo,
    process::ProcessInfo,
};
use std::path::Path;

pub fn event_for_process(process: &ProcessInfo, kind: EventKind) -> SecurityEvent {
    let severity = severity_for_process(process);
    let message = format!(
        "process {} observed: {}",
        process.pid,
        process.name.as_deref().unwrap_or("unknown")
    );

    let mut event = SecurityEvent::new(kind, severity, "process", message)
        .with_detail("pid", process.pid)
        .with_detail("name", &process.name)
        .with_detail("exe", &process.exe)
        .with_detail("uid", process.uid);

    if let Some(cmdline) = &process.cmdline {
        event = event.with_detail("cmdline", cmdline);
    }

    event
}

pub fn event_for_socket(socket: &SocketInfo) -> SecurityEvent {
    let severity = severity_for_socket(socket);
    SecurityEvent::new(
        EventKind::ListeningSocket,
        severity,
        "network",
        format!(
            "{} listening on {}:{}",
            socket.protocol, socket.local_address, socket.local_port
        ),
    )
    .with_detail("protocol", &socket.protocol)
    .with_detail("local_address", &socket.local_address)
    .with_detail("local_port", socket.local_port)
    .with_detail("inode", socket.inode)
}

pub fn severity_for_process(process: &ProcessInfo) -> Severity {
    let exe = process.exe.as_deref().unwrap_or_default();
    let tmp_exec =
        exe.starts_with("/tmp/") || exe.starts_with("/var/tmp/") || exe.starts_with("/dev/shm/");
    let deleted_exec = exe.ends_with(" (deleted)");
    let root_tmp_exec = process.uid == Some(0) && tmp_exec;

    if root_tmp_exec || deleted_exec {
        Severity::High
    } else if tmp_exec {
        Severity::Medium
    } else {
        Severity::Info
    }
}

pub fn severity_for_socket(socket: &SocketInfo) -> Severity {
    let sensitive_public_ports = [22_u16, 2375, 2376, 5432, 6379, 9200, 9300];
    let public_bind = socket.local_address == "0.0.0.0" || socket.local_address == "::";

    if public_bind && sensitive_public_ports.contains(&socket.local_port) {
        Severity::Medium
    } else {
        Severity::Info
    }
}

pub fn severity_for_filesystem_path(path: &Path) -> Severity {
    let value = path.to_string_lossy();
    if value.starts_with("/etc/") || value == "/etc" {
        Severity::Medium
    } else if value.starts_with("/tmp/") || value.starts_with("/var/tmp/") {
        Severity::Low
    } else {
        Severity::Info
    }
}
