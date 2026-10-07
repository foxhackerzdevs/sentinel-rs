# sentinel-rs

`sentinel-rs` is a small, read-only Linux host telemetry monitor written in Rust. It focuses on collecting useful local security signals and emitting structured JSON events without taking response actions.

It does not kill processes, block network connections, quarantine files, change permissions, or modify watched paths.

## Features

- Process telemetry from `/proc`
  - New process observation during continuous monitoring
  - PID, process name, executable path, UID, and optional command line
  - Simple severity hints for deleted executables and execution from temporary paths
- Network telemetry from `/proc/net`
  - TCP listening sockets
  - Optional UDP socket telemetry
  - Severity hint for public binds on commonly sensitive service ports
  - Process-to-socket attribution by matching `/proc/<pid>/fd` socket inodes to `/proc/net/tcp` and `/proc/net/tcp6`
  - Owner context on attributed socket events: PID, process name, executable path, UID, and optional command line
  - High-severity hints for public root listeners, temporary-path executables that listen, and deleted executables that listen
- Persistent baseline and anomaly detection
  - JSON baseline initialized from the first monitoring snapshot
  - First-seen process and listening-socket detection
  - Listening-socket owner-change detection
  - Exact executable and listener-port allowlists
  - Automatic learning of newly observed identities
  - Safe baseline persistence through temporary-file replacement
- Process-network behavioral correlation
  - Outbound TCP and UDP connection tracking
  - Process attribution through socket inodes
  - Persistent per-process remote endpoint behavior
  - First-seen connection and behavior-change events
  - Exact remote-address, remote-port, and executable allowlists
- Filesystem monitoring
  - Watches configured paths with the Rust `notify` crate
  - Emits create, modify, remove, and other filesystem events
- Structured events
  - One JSON object per line
  - Stable event kind, severity, source, message, timestamp, and details fields
- Configuration
  - TOML config with conservative defaults
  - Module-level enablement
- CLI
  - `run` for continuous monitoring
  - `once` for a single snapshot
  - `validate-config`
  - `default-config`

## Baseline monitoring

Continuous `run` monitoring can compare process and listening-socket metadata
against a persistent JSON baseline. The baseline is initialized from the first
host snapshot, so existing processes and listeners do not generate a burst of
first-seen alerts. Later observations produce structured anomaly events for
new identities and listener owner changes.

Persistent process identity uses executable path, UID, and name rather than PID.
Persistent listener identity uses protocol, local address, local port, and
owner metadata rather than socket inode alone. Runtime socket tracking remains
independent of owner metadata so ownership changes can be detected reliably.

The baseline is only used by `run`. The `once` command remains a stateless
telemetry snapshot and does not modify the baseline.

Behavioral monitoring stores compact process-network identities rather than
every connection occurrence. Repeated observations of a learned connection do
not produce repeated anomaly events. Behavioral monitoring remains
detection-only and does not classify endpoints as malicious or take response
actions.

## Requirements

- Rust 1.78+ should work; this project was built with Rust 1.98.
- Linux is required for process and network telemetry because those collectors read `/proc`.
- Filesystem watching depends on platform watcher support and permissions for the configured paths.

The crate is kept buildable on non-Linux hosts for development and tests. On non-Linux systems, process and network collectors return empty results.

## Setup

```bash
cargo build
```

Run tests:

```bash
cargo test
```

## Usage

Print the default configuration:

```bash
cargo run -- default-config
```

Validate the included configuration:

```bash
cargo run -- --config config/sentinel.toml validate-config
```

Collect one snapshot:

```bash
cargo run -- --config config/sentinel.toml once
```

Run continuously until `Ctrl-C`:

```bash
cargo run -- --config config/sentinel.toml run
```

Each event is printed as a single JSON line:

```json
{"timestamp":"2026-10-04T14:02:11.123Z","kind":"listening_socket","severity":"high","source":"network","message":"tcp listening on 0.0.0.0:4444 owned by pid 1842 (payload)","details":{"inode":53124,"local_address":"0.0.0.0","local_port":4444,"pid":1842,"process_cmdline":"/tmp/payload --listen 4444","process_exe":"/tmp/payload","process_name":"payload","process_uid":0,"protocol":"tcp"}}
```

## Configuration

The default config lives at `config/sentinel.toml`.

```toml
[telemetry]
interval_seconds = 5

[process]
enabled = true
include_command_line = true

[network]
enabled = true
include_udp = true

[filesystem]
enabled = true
paths = ["/etc", "/usr/local/bin", "/tmp"]
recursive = false

[logging]
level = "info"
json = false

[baseline]
enabled = true
path = "state/baseline.json"
initialize_on_first_run = true
learn_new = true

[baseline.allowlist]
process_executables = ["/usr/bin/systemd", "/usr/sbin/sshd"]
listener_executables = ["/usr/sbin/sshd"]
listener_ports = [22]

[behavior]
enabled = true
learn_new = true
track_outbound = true
track_remote_endpoints = true
track_remote_ports = true

[behavior.allowlist]
remote_addresses = []
remote_ports = []
process_executables = []
```

Allowlist matching is exact; regular expressions and glob patterns are not
supported. Baseline corruption is reported as an error rather than silently
overwritten. If baseline persistence fails during monitoring, telemetry
continues and the failure is logged.

## Permissions

Most telemetry works as an unprivileged user, but visibility depends on host policy:

- Some process executable paths or command lines may be hidden by `/proc` permissions.
- Process-to-socket attribution depends on permission to inspect `/proc/<pid>/fd` symlinks. Socket events are still emitted when owner context is unavailable.
- Watching protected filesystem paths may fail without appropriate read/search permissions.
- Running as root increases visibility, but is not required for the first pass.

If a configured filesystem watch path cannot be opened, `sentinel-rs` logs that the filesystem monitor was disabled and continues with other telemetry.

## Limitations

- This is telemetry, not an EDR or prevention engine.
- Detections are intentionally simple hints, not definitive maliciousness labels.
- Process monitoring is polling-based, so very short-lived processes may be missed.
- Network process attribution is inode-based and reflects what `/proc` exposes at collection time. Very short-lived processes or restricted `/proc` entries may be unattributed.
- Filesystem event behavior can vary by kernel, filesystem, and watcher backend.
- Linux `/proc` parsing is intentionally minimal and may be expanded in later phases.
- Outbound connection visibility and process attribution depend on access to `/proc/net` and `/proc/<pid>/fd`.

## Repository Layout

```text
sentinel-rs/
├── config/
│   └── sentinel.toml
├── src/
│   ├── anomaly.rs
│   ├── baseline.rs
│   ├── behavior.rs
│   ├── config.rs
│   ├── detection.rs
│   ├── event.rs
│   ├── filesystem.rs
│   ├── lib.rs
│   ├── logger.rs
│   ├── main.rs
│   ├── network.rs
│   └── process.rs
├── tests/
│   └── event_detection.rs
├── Cargo.toml
└── README.md
```

## Next Phase Ideas

- Persisted event logs with rotation
- More robust detection rules
- Optional REST or terminal dashboard
- Linux service unit packaging
