use anyhow::Result;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: Option<String>,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub uid: Option<u32>,
}

#[derive(Debug, Default)]
pub struct ProcessState {
    seen_pids: HashSet<u32>,
}

impl ProcessState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_processes(&mut self, processes: &[ProcessInfo]) -> Vec<ProcessInfo> {
        let current: HashSet<u32> = processes.iter().map(|process| process.pid).collect();
        let fresh = processes
            .iter()
            .filter(|process| !self.seen_pids.contains(&process.pid))
            .cloned()
            .collect();
        self.seen_pids = current;
        fresh
    }
}

#[cfg(target_os = "linux")]
pub fn collect_processes(include_command_line: bool) -> Result<Vec<ProcessInfo>> {
    linux::collect_processes(include_command_line)
}

#[cfg(not(target_os = "linux"))]
pub fn collect_processes(_include_command_line: bool) -> Result<Vec<ProcessInfo>> {
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::ProcessInfo;
    use anyhow::Result;
    use std::{fs, os::unix::fs::MetadataExt, path::PathBuf};

    pub fn collect_processes(include_command_line: bool) -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            let Some(pid) = file_name.to_string_lossy().parse::<u32>().ok() else {
                continue;
            };

            let proc_dir = entry.path();
            let name = read_trimmed(proc_dir.join("comm"));
            let exe = fs::read_link(proc_dir.join("exe"))
                .ok()
                .map(|path| path.to_string_lossy().into_owned());
            let uid = fs::metadata(&proc_dir).ok().map(|metadata| metadata.uid());
            let cmdline = include_command_line
                .then(|| read_cmdline(proc_dir.join("cmdline")))
                .flatten();

            processes.push(ProcessInfo {
                pid,
                name,
                exe,
                cmdline,
                uid,
            });
        }

        Ok(processes)
    }

    fn read_trimmed(path: PathBuf) -> Option<String> {
        fs::read_to_string(path)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    fn read_cmdline(path: PathBuf) -> Option<String> {
        let bytes = fs::read(path).ok()?;
        let parts: Vec<String> = bytes
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    }
}
