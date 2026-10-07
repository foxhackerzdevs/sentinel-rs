pub use crate::config::{BaselineAllowlistConfig, BaselineConfig};
use crate::{
    network::{ConnectionInfo, SocketInfo},
    process::ProcessInfo,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

const BASELINE_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    pub version: u32,

    #[serde(default)]
    pub processes: BTreeSet<ProcessBaselineKey>,

    #[serde(default)]
    pub listeners: BTreeSet<ListenerBaselineKey>,

    #[serde(default)]
    pub connections: BTreeSet<ProcessNetworkBaselineKey>,
}

impl Baseline {
    fn with_version() -> Self {
        Self {
            version: BASELINE_VERSION,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessBaselineKey {
    pub executable: Option<String>,
    pub uid: Option<u32>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ListenerBaselineKey {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub executable: Option<String>,
    pub uid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessNetworkBaselineKey {
    pub executable: Option<String>,
    pub uid: Option<u32>,
    pub name: Option<String>,
    pub protocol: String,
    pub remote_address: String,
    pub remote_port: u16,
}

/// Persistent host baseline state.
///
/// This owns the on-disk baseline only; detection lives in `anomaly`.
pub struct BaselineStore {
    path: PathBuf,
    baseline: Baseline,
}

impl BaselineStore {
    /// Load the baseline from `path`.
    ///
    /// A missing file yields an empty baseline. An unreadable or corrupt file is
    /// returned as an error so monitoring never silently overwrites operator state.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        if !path.exists() {
            return Ok(Self::empty(path));
        }

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read baseline state {}", path.display()))?;
        let mut baseline: Baseline = serde_json::from_str(&raw)
            .with_context(|| format!("failed to load baseline state {}", path.display()))?;
        if baseline.version == 0 {
            baseline.version = BASELINE_VERSION;
        }

        Ok(Self { path, baseline })
    }

    pub fn empty(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            baseline: Baseline::with_version(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn is_empty(&self) -> bool {
        self.baseline.processes.is_empty()
            && self.baseline.listeners.is_empty()
            && self.baseline.connections.is_empty()
    }

    pub fn contains_process(&self, process: &ProcessInfo) -> bool {
        self.baseline.processes.contains(&process_key(process))
    }

    pub fn contains_listener(&self, socket: &SocketInfo) -> bool {
        self.baseline.listeners.contains(&listener_key(socket))
    }

    pub fn add_process(&mut self, process: &ProcessInfo) {
        self.baseline.processes.insert(process_key(process));
    }

    pub fn add_listener(&mut self, socket: &SocketInfo) {
        self.baseline.listeners.insert(listener_key(socket));
    }

    pub fn contains_connection(&self, connection: &ConnectionInfo) -> bool {
        self.baseline
            .connections
            .contains(&crate::behavior::connection_key(connection))
    }

    pub fn add_connection(&mut self, connection: &ConnectionInfo) {
        self.baseline
            .connections
            .insert(crate::behavior::connection_key(connection));
    }

    pub fn process_count(&self) -> usize {
        self.baseline.processes.len()
    }

    pub fn listener_count(&self) -> usize {
        self.baseline.listeners.len()
    }

    pub fn connection_count(&self) -> usize {
        self.baseline.connections.len()
    }

    pub fn initialize_from_snapshot(&mut self, processes: &[ProcessInfo], sockets: &[SocketInfo]) {
        self.baseline = Baseline::with_version();
        for process in processes {
            self.add_process(process);
        }
        for socket in sockets {
            self.add_listener(socket);
        }
    }

    pub fn initialize_connections(&mut self, connections: &[ConnectionInfo]) {
        for connection in connections {
            self.add_connection(connection);
        }
    }

    /// Persist the baseline atomically: write to a temporary file, flush it to
    /// disk, then rename it over the destination.
    pub fn save(&self) -> Result<()> {
        let serialized = serde_json::to_vec_pretty(&self.baseline)
            .context("failed to serialize baseline state")?;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
        }

        let tmp = self.path.with_extension("json.tmp");
        {
            let mut file = File::create(&tmp)
                .with_context(|| format!("failed to create {}", tmp.display()))?;
            file.write_all(&serialized)
                .with_context(|| format!("failed to write {}", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("failed to flush {}", tmp.display()))?;
        }

        fs::rename(&tmp, &self.path)
            .with_context(|| format!("failed to replace {}", self.path.display()))?;

        Ok(())
    }
}

fn process_key(process: &ProcessInfo) -> ProcessBaselineKey {
    ProcessBaselineKey {
        executable: process.exe.clone(),
        uid: process.uid,
        name: process.name.clone(),
    }
}

fn listener_key(socket: &SocketInfo) -> ListenerBaselineKey {
    let process = socket.process.as_ref();
    ListenerBaselineKey {
        protocol: socket.protocol.clone(),
        local_address: socket.local_address.clone(),
        local_port: socket.local_port,
        executable: process.and_then(|process| process.exe.clone()),
        uid: process.and_then(|process| process.uid),
    }
}

#[cfg(test)]
mod tests {
    use super::{BaselineStore, ProcessBaselineKey};
    use crate::{network::SocketInfo, process::ProcessInfo};

    fn process(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: Some("sshd".into()),
            exe: Some("/usr/sbin/sshd".into()),
            cmdline: None,
            uid: Some(0),
        }
    }

    fn listener(inode: u64) -> SocketInfo {
        SocketInfo {
            protocol: "tcp".into(),
            local_address: "0.0.0.0".into(),
            local_port: 22,
            inode: Some(inode),
            process: Some(process(1842)),
        }
    }

    #[test]
    fn empty_baseline_contains_nothing() {
        let store = BaselineStore::empty("state/baseline.json");

        assert!(store.is_empty());
        assert!(!store.contains_process(&process(1)));
        assert!(!store.contains_listener(&listener(1)));
        assert_eq!(store.process_count(), 0);
        assert_eq!(store.listener_count(), 0);
    }

    #[test]
    fn process_key_ignores_pid() {
        let mut store = BaselineStore::empty("state/baseline.json");
        store.add_process(&process(1000));

        assert!(store.contains_process(&process(2000)));
        assert_eq!(store.process_count(), 1);
    }

    #[test]
    fn listener_key_ignores_inode() {
        let mut store = BaselineStore::empty("state/baseline.json");
        store.add_listener(&listener(111));

        assert!(store.contains_listener(&listener(999)));
        assert_eq!(store.listener_count(), 1);
    }

    #[test]
    fn baseline_round_trips_json() {
        let mut store = BaselineStore::empty("state/baseline.json");
        store.add_process(&process(1));
        store.add_listener(&listener(1));

        let json = serde_json::to_string(&store.baseline).unwrap();
        let restored: super::Baseline = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.version, 2);
        assert_eq!(restored.processes.len(), 1);
        assert_eq!(restored.listeners.len(), 1);
        assert!(restored.processes.contains(&ProcessBaselineKey {
            executable: Some("/usr/sbin/sshd".into()),
            uid: Some(0),
            name: Some("sshd".into()),
        }));
    }

    #[test]
    fn baseline_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/baseline.json");

        let mut store = BaselineStore::empty(&path);
        store.add_process(&process(1));
        store.add_listener(&listener(1));
        store.save().unwrap();

        assert!(path.exists());

        let reloaded = BaselineStore::load(&path).unwrap();
        assert!(reloaded.contains_process(&process(2)));
        assert!(reloaded.contains_listener(&listener(2)));
        assert_eq!(reloaded.process_count(), 1);
        assert_eq!(reloaded.listener_count(), 1);
    }

    #[test]
    fn baseline_loads_missing_file_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.json");

        let store = BaselineStore::load(&path).unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn baseline_initializes_from_snapshot() {
        let mut store = BaselineStore::empty("state/baseline.json");
        store.initialize_from_snapshot(&[process(1), process(2)], &[listener(1)]);

        assert_eq!(store.process_count(), 1);
        assert_eq!(store.listener_count(), 1);
        assert!(!store.is_empty());
    }
}
