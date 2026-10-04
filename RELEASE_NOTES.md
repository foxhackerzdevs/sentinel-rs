# Release Notes

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

