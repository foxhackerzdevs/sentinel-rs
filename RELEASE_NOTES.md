# Release Notes

## v0.3.0 - Phase 3 Baseline & Anomaly Detection

This release adds persistent host baselining and stateful anomaly detection to
sentinel-rs while preserving its read-only security-monitoring model.

### Added

- Persistent JSON baseline state.
- Baseline initialization on first monitoring run.
- First-seen process detection.
- First-seen listening-socket detection.
- Listening-socket owner-change detection.
- Configurable process executable allowlists.
- Configurable listener executable allowlists.
- Configurable listener-port allowlists.
- Structured anomaly events.
- Baseline persistence with safe temporary-file replacement.
- Baseline corruption and persistence failure handling.
- Tests for baseline serialization and persistence.
- Tests for first-seen detection.
- Tests for listener owner changes.
- Tests for allowlist behavior.

### Detection Model

Persistent process identity is based on stable process metadata rather than
PID alone.

Persistent listener identity is based on protocol, local address, local port,
and process ownership metadata rather than socket inode alone.

Runtime socket identity continues to remain independent of process ownership,
allowing sentinel-rs to detect ownership changes without incorrectly treating
the socket itself as a newly created listener.

### First Run

When no baseline exists, sentinel-rs initializes the baseline from the current
host snapshot rather than generating an alert for every existing process and
listener.

Subsequent observations are compared against the persisted baseline.

### Configuration

Phase 3 adds baseline configuration for:

- baseline state path
- first-run initialization
- automatic learning of newly observed identities
- process executable allowlists
- listener executable allowlists
- listener-port allowlists

### Event Types

New structured event kinds include:

- `first_seen_process`
- `first_seen_listener`
- `listener_owner_changed`
- `baseline_initialized`

### Safety

sentinel-rs remains detection-only and read-only.

This release does not:

- terminate processes
- modify firewall rules
- modify routing
- quarantine files
- change permissions
- modify monitored system files

The only persistent state introduced by this phase is the explicitly
configured sentinel-rs baseline file.

### Compatibility

The existing `run`, `once`, `validate-config`, and `default-config` commands
remain available.

The `once` command continues to provide a stateless telemetry snapshot and
does not implicitly modify the persistent baseline.

### Limitations

- Persistent baseline identity is intentionally metadata-based rather than
  PID/inode-based.
- Short-lived processes may still be missed by polling.
- Process/socket attribution remains dependent on access to `/proc/<pid>/fd`.
- Allowlist matching is exact and does not provide regex or glob patterns.
- Baseline state is local JSON storage rather than historical event storage.
- Historical event retention and analytics are outside the scope of this
  release.

### Previous Release

See the v0.2.0 release notes for process-to-network attribution and
socket-owner context.

## v0.2.0 - Phase 2 Process-Network Attribution

Phase 2 turns network telemetry from standalone socket observations into attributed listening-socket events when Linux `/proc` exposes the owning process.

### Added

- Process-to-network attribution by matching socket inodes from `/proc/<pid>/fd` with entries from `/proc/net/tcp` and `/proc/net/tcp6`.
- Owner context on attributed listening socket events:
  - PID
  - process name
  - executable path
  - UID
  - optional command line
- High-severity detection hints for:
  - root-owned processes listening publicly
  - executables running from `/tmp`, `/var/tmp`, or `/dev/shm` that listen on sockets
  - deleted executables that continue listening on sockets
- Synthetic parser tests for `/proc/net` socket parsing, socket inode extraction, TCP attribution, and UDP preservation.
- Detection tests for attributed listener severity and event details.

### Changed

- Listening socket events now include process owner fields when attribution succeeds.
- Socket state tracking keeps socket identity stable across owner metadata changes to avoid noisy re-emission.
- README examples and limitations now describe attribution behavior and `/proc` permission constraints.

### Safety

- The monitor remains read-only.
- No processes are killed.
- No firewall, routing, permissions, or file response actions are performed.

### Limitations

- Attribution depends on permission to inspect `/proc/<pid>/fd` symlinks.
- Very short-lived processes or restricted `/proc` entries may still produce unattributed socket events.
- UDP telemetry is preserved when enabled, but UDP entries are not filtered by TCP listen state.
