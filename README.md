# sentinel-rs

`sentinel-rs` is a small, read-only Linux host telemetry monitor written in Rust. Phase 1 focuses on collecting useful local security signals and emitting structured JSON events without taking response actions.

It does not kill processes, block network connections, quarantine files, change permissions, or modify watched paths.

## Phase 1 Features

- Process telemetry from `/proc`
  - New process observation during continuous monitoring
  - PID, process name, executable path, UID, and optional command line
  - Simple severity hints for deleted executables and execution from temporary paths
- Network telemetry from `/proc/net`
  - TCP listening sockets
  - Optional UDP socket telemetry
  - Severity hint for public binds on commonly sensitive service ports
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
{"timestamp":"2026-10-04T14:02:11.123Z","kind":"listening_socket","severity":"medium","source":"network","message":"tcp listening on 0.0.0.0:6379","details":{"local_address":"0.0.0.0","local_port":6379,"protocol":"tcp","inode":123}}
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
```

## Permissions

Most telemetry works as an unprivileged user, but visibility depends on host policy:

- Some process executable paths or command lines may be hidden by `/proc` permissions.
- Watching protected filesystem paths may fail without appropriate read/search permissions.
- Running as root increases visibility, but is not required for the first pass.

If a configured filesystem watch path cannot be opened, `sentinel-rs` logs that the filesystem monitor was disabled and continues with other telemetry.

## Limitations

- This is telemetry, not an EDR or prevention engine.
- Detections are intentionally simple hints, not definitive maliciousness labels.
- Process monitoring is polling-based, so very short-lived processes may be missed.
- Network process attribution is not implemented yet; Phase 1 reports sockets, not owning processes.
- Filesystem event behavior can vary by kernel, filesystem, and watcher backend.
- Linux `/proc` parsing is intentionally minimal and may be expanded in later phases.

## Repository Layout

```text
sentinel-rs/
├── config/
│   └── sentinel.toml
├── src/
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

- Process-to-socket attribution via socket inode mapping
- Baseline and allowlist configuration
- Persisted event logs with rotation
- More robust detection rules
- Optional REST or terminal dashboard
- Linux service unit packaging
