use crate::process::ProcessInfo;
use anyhow::Result;
use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    net::Ipv6Addr,
};

#[derive(Debug, Clone, Eq)]
pub struct SocketInfo {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub inode: Option<u64>,
    pub process: Option<ProcessInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionInfo {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub inode: Option<u64>,
    pub process: Option<ProcessInfo>,
}

impl PartialEq for SocketInfo {
    fn eq(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.local_address == other.local_address
            && self.local_port == other.local_port
            && self.inode == other.inode
    }
}

impl Hash for SocketInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.protocol.hash(state);
        self.local_address.hash(state);
        self.local_port.hash(state);
        self.inode.hash(state);
    }
}

/// A change of the process that owns a listening socket.
#[derive(Debug, Clone)]
pub struct SocketOwnerChange {
    pub previous: Option<ProcessInfo>,
    pub current: Option<ProcessInfo>,
    pub socket: SocketInfo,
}

/// Runtime socket state: identity plus the owner observed at the last scan.
///
/// Equality and hashing deliberately delegate to [`SocketInfo`], so a socket
/// whose owner metadata changes is still the same socket. Owner changes are
/// compared separately via [`SocketState::owner_changes`].
#[derive(Debug, Clone)]
struct SocketRuntimeState {
    socket: SocketInfo,
    owner: Option<ProcessInfo>,
}

impl PartialEq for SocketRuntimeState {
    fn eq(&self, other: &Self) -> bool {
        self.socket == other.socket
    }
}

impl Eq for SocketRuntimeState {}

impl Hash for SocketRuntimeState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.socket.hash(state);
    }
}

impl SocketRuntimeState {
    fn from_socket(socket: &SocketInfo) -> Self {
        Self {
            socket: socket.clone(),
            owner: socket.process.clone(),
        }
    }
}

#[derive(Debug, Default)]
pub struct SocketState {
    known: HashSet<SocketRuntimeState>,
}

impl SocketState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_sockets(&mut self, sockets: &[SocketInfo]) -> Vec<SocketInfo> {
        let fresh = sockets
            .iter()
            .filter(|socket| {
                !self
                    .known
                    .contains(&SocketRuntimeState::from_socket(socket))
            })
            .cloned()
            .collect();
        self.known = sockets
            .iter()
            .map(SocketRuntimeState::from_socket)
            .collect();
        fresh
    }

    /// Compare socket owners in `sockets` against the owners observed at the
    /// previous scan. Call this before `new_sockets`, which replaces the stored
    /// owner metadata.
    pub fn owner_changes(&self, sockets: &[SocketInfo]) -> Vec<SocketOwnerChange> {
        let mut changes = Vec::new();

        for socket in sockets {
            let key = SocketRuntimeState::from_socket(socket);
            let Some(previous_state) = self.known.get(&key) else {
                continue;
            };

            let current = socket.process.clone();
            if previous_state.owner == current {
                continue;
            }

            changes.push(SocketOwnerChange {
                previous: previous_state.owner.clone(),
                current,
                socket: socket.clone(),
            });
        }

        changes
    }
}

#[cfg(target_os = "linux")]
pub fn collect_listening_sockets(
    include_udp: bool,
    include_command_line: bool,
) -> Result<Vec<SocketInfo>> {
    linux::collect_listening_sockets(include_udp, include_command_line)
}

#[cfg(target_os = "linux")]
pub fn collect_connections(
    include_udp: bool,
    include_command_line: bool,
) -> Result<Vec<ConnectionInfo>> {
    linux::collect_connections(include_udp, include_command_line)
}

#[cfg(not(target_os = "linux"))]
pub fn collect_connections(
    _include_udp: bool,
    _include_command_line: bool,
) -> Result<Vec<ConnectionInfo>> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "linux"))]
pub fn collect_listening_sockets(
    _include_udp: bool,
    _include_command_line: bool,
) -> Result<Vec<SocketInfo>> {
    Ok(Vec::new())
}

pub fn parse_proc_net_sockets(
    raw: &str,
    protocol: &str,
    tcp_only_listen: bool,
    owners: &HashMap<u64, ProcessInfo>,
) -> Vec<SocketInfo> {
    let mut sockets = Vec::new();

    for line in raw.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }

        let state = fields[3];
        if tcp_only_listen && state != "0A" {
            continue;
        }

        if let Some((address, port)) = parse_address(fields[1], protocol.ends_with('6')) {
            let inode = fields[9].parse::<u64>().ok();
            let process = inode.and_then(|inode| owners.get(&inode).cloned());
            sockets.push(SocketInfo {
                protocol: protocol.to_string(),
                local_address: address,
                local_port: port,
                inode,
                process,
            });
        }
    }

    sockets
}

pub fn parse_proc_net_connections(
    raw: &str,
    protocol: &str,
    owners: &HashMap<u64, ProcessInfo>,
) -> Vec<ConnectionInfo> {
    raw.lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[3] == "0A" {
                return None;
            }
            let (local_address, local_port) = parse_address(fields[1], protocol.ends_with('6'))?;
            let (remote_address, remote_port) = parse_address(fields[2], protocol.ends_with('6'))?;
            if remote_address == "0.0.0.0" || remote_address == "::" || remote_port == 0 {
                return None;
            }
            let inode = fields[9].parse::<u64>().ok();
            Some(ConnectionInfo {
                protocol: protocol.to_string(),
                local_address,
                local_port,
                remote_address,
                remote_port,
                inode,
                process: inode.and_then(|inode| owners.get(&inode).cloned()),
            })
        })
        .collect()
}

pub fn socket_inode_from_link_target(value: &str) -> Option<u64> {
    let inode = value
        .strip_prefix("socket:[")
        .and_then(|value| value.strip_suffix(']'))?;
    inode.parse().ok()
}

fn parse_address(value: &str, ipv6: bool) -> Option<(String, u16)> {
    let (address_hex, port_hex) = value.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if ipv6 {
        parse_ipv6(address_hex).map(|address| (address, port))
    } else {
        parse_ipv4(address_hex).map(|address| (address, port))
    }
}

fn parse_ipv4(value: &str) -> Option<String> {
    if value.len() != 8 {
        return None;
    }

    let raw = u32::from_str_radix(value, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(format!(
        "{}.{}.{}.{}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    ))
}

fn parse_ipv6(value: &str) -> Option<String> {
    if value.len() != 32 {
        return None;
    }

    let mut bytes = [0_u8; 16];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).ok()?;
        bytes[index] = u8::from_str_radix(hex, 16).ok()?;
    }

    for chunk in bytes.chunks_exact_mut(4) {
        chunk.reverse();
    }

    Some(Ipv6Addr::from(bytes).to_string())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        parse_proc_net_connections, parse_proc_net_sockets, socket_inode_from_link_target,
        ConnectionInfo, SocketInfo,
    };
    use crate::process::read_process_from_proc_dir;
    use anyhow::{Context, Result};
    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
    };

    pub fn collect_listening_sockets(
        include_udp: bool,
        include_command_line: bool,
    ) -> Result<Vec<SocketInfo>> {
        collect_listening_sockets_from_proc(Path::new("/proc"), include_udp, include_command_line)
    }

    pub fn collect_connections(
        include_udp: bool,
        include_command_line: bool,
    ) -> Result<Vec<ConnectionInfo>> {
        let proc_root = Path::new("/proc");
        let owners = collect_socket_owners(proc_root, include_command_line)?;
        let mut connections = Vec::new();
        collect_connections_from_file(proc_root.join("net/tcp"), "tcp", &owners, &mut connections)?;
        collect_connections_from_file(
            proc_root.join("net/tcp6"),
            "tcp6",
            &owners,
            &mut connections,
        )?;
        if include_udp {
            collect_connections_from_file(
                proc_root.join("net/udp"),
                "udp",
                &owners,
                &mut connections,
            )?;
            collect_connections_from_file(
                proc_root.join("net/udp6"),
                "udp6",
                &owners,
                &mut connections,
            )?;
        }
        Ok(connections)
    }

    fn collect_listening_sockets_from_proc(
        proc_root: &Path,
        include_udp: bool,
        include_command_line: bool,
    ) -> Result<Vec<SocketInfo>> {
        let owners = collect_socket_owners(proc_root, include_command_line)?;
        let mut sockets = Vec::new();
        collect_from_file(
            proc_root.join("net/tcp"),
            "tcp",
            true,
            &owners,
            &mut sockets,
        )?;
        collect_from_file(
            proc_root.join("net/tcp6"),
            "tcp6",
            true,
            &owners,
            &mut sockets,
        )?;

        if include_udp {
            collect_from_file(
                proc_root.join("net/udp"),
                "udp",
                false,
                &owners,
                &mut sockets,
            )?;
            collect_from_file(
                proc_root.join("net/udp6"),
                "udp6",
                false,
                &owners,
                &mut sockets,
            )?;
        }

        Ok(sockets)
    }

    fn collect_socket_owners(
        proc_root: &Path,
        include_command_line: bool,
    ) -> Result<HashMap<u64, crate::process::ProcessInfo>> {
        let mut owners = HashMap::new();

        for entry in fs::read_dir(proc_root)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(pid) = file_name.to_string_lossy().parse::<u32>().ok() else {
                continue;
            };

            let proc_dir = entry.path();
            let process = read_process_from_proc_dir(&proc_dir, pid, include_command_line);
            let fd_dir = proc_dir.join("fd");
            let Ok(fd_entries) = fs::read_dir(fd_dir) else {
                continue;
            };

            for fd_entry in fd_entries.flatten() {
                let Ok(target) = fs::read_link(fd_entry.path()) else {
                    continue;
                };

                if let Some(inode) = socket_inode_from_path(target) {
                    owners.entry(inode).or_insert_with(|| process.clone());
                }
            }
        }

        Ok(owners)
    }

    fn socket_inode_from_path(path: PathBuf) -> Option<u64> {
        socket_inode_from_link_target(&path.to_string_lossy())
    }

    fn collect_from_file(
        path: PathBuf,
        protocol: &str,
        tcp_only_listen: bool,
        owners: &HashMap<u64, crate::process::ProcessInfo>,
        sockets: &mut Vec<SocketInfo>,
    ) -> Result<()> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        sockets.extend(parse_proc_net_sockets(
            &raw,
            protocol,
            tcp_only_listen,
            owners,
        ));

        Ok(())
    }

    fn collect_connections_from_file(
        path: PathBuf,
        protocol: &str,
        owners: &HashMap<u64, crate::process::ProcessInfo>,
        connections: &mut Vec<ConnectionInfo>,
    ) -> Result<()> {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        connections.extend(parse_proc_net_connections(&raw, protocol, owners));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_proc_net_connections, parse_proc_net_sockets, socket_inode_from_link_target,
        SocketInfo, SocketState,
    };
    use crate::process::ProcessInfo;
    use std::collections::HashMap;

    #[test]
    fn extracts_socket_inode_from_fd_target() {
        assert_eq!(socket_inode_from_link_target("socket:[53124]"), Some(53124));
        assert_eq!(socket_inode_from_link_target("/tmp/file"), None);
    }

    #[test]
    fn parses_proc_net_tcp_and_attaches_owner() {
        let mut owners = HashMap::new();
        owners.insert(
            53124,
            ProcessInfo {
                pid: 1842,
                name: Some("sshd".into()),
                exe: Some("/usr/sbin/sshd".into()),
                cmdline: Some("/usr/sbin/sshd -D".into()),
                uid: Some(0),
            },
        );

        let raw = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 53124 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000  1000        0 99999 1 0000000000000000 100 0 0 10 0
";

        let sockets = parse_proc_net_sockets(&raw, "tcp", true, &owners);

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_address, "0.0.0.0");
        assert_eq!(sockets[0].local_port, 22);
        assert_eq!(sockets[0].inode, Some(53124));
        assert_eq!(
            sockets[0].process.as_ref().map(|process| process.pid),
            Some(1842)
        );
    }

    #[test]
    fn parses_udp_without_listen_state_filter() {
        let owners = HashMap::new();
        let raw = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   102        0 2222 2 0000000000000000 0
";

        let sockets = parse_proc_net_sockets(&raw, "udp", false, &owners);

        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_address, "127.0.0.1");
        assert_eq!(sockets[0].local_port, 53);
    }

    #[test]
    fn detects_listener_owner_change_without_new_socket_event() {
        let old_owner = ProcessInfo {
            pid: 1,
            name: Some("old".into()),
            exe: Some("/usr/bin/old".into()),
            cmdline: None,
            uid: Some(1000),
        };
        let new_owner = ProcessInfo {
            pid: 2,
            name: Some("new".into()),
            exe: Some("/usr/bin/new".into()),
            cmdline: None,
            uid: Some(1000),
        };
        let socket = |process| SocketInfo {
            protocol: "tcp".into(),
            local_address: "127.0.0.1".into(),
            local_port: 8080,
            inode: Some(123),
            process,
        };
        let mut state = SocketState::new();

        assert!(state.new_sockets(&[socket(Some(old_owner.clone()))]).len() == 1);
        let changed = socket(Some(new_owner.clone()));
        let changes = state.owner_changes(&[changed.clone()]);

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].previous, Some(old_owner));
        assert_eq!(changes[0].current, Some(new_owner));
        assert!(state.new_sockets(&[changed]).is_empty());
    }

    #[test]
    fn parses_established_connection_and_attaches_owner() {
        let mut owners = HashMap::new();
        owners.insert(
            7777,
            ProcessInfo {
                pid: 42,
                name: Some("curl".into()),
                exe: Some("/usr/bin/curl".into()),
                cmdline: None,
                uid: Some(1000),
            },
        );
        let raw = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:C350 2A000001:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 7777 1 0000000000000000
";
        let connections = parse_proc_net_connections(&raw, "tcp", &owners);

        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].remote_address, "1.0.0.42");
        assert_eq!(connections[0].remote_port, 443);
        assert_eq!(
            connections[0].process.as_ref().map(|process| process.pid),
            Some(42)
        );
    }
}
