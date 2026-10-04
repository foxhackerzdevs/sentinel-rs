use anyhow::Result;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketInfo {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub inode: Option<u64>,
}

#[derive(Debug, Default)]
pub struct SocketState {
    seen: HashSet<SocketInfo>,
}

impl SocketState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_sockets(&mut self, sockets: &[SocketInfo]) -> Vec<SocketInfo> {
        let current: HashSet<SocketInfo> = sockets.iter().cloned().collect();
        let fresh = sockets
            .iter()
            .filter(|socket| !self.seen.contains(*socket))
            .cloned()
            .collect();
        self.seen = current;
        fresh
    }
}

#[cfg(target_os = "linux")]
pub fn collect_listening_sockets(include_udp: bool) -> Result<Vec<SocketInfo>> {
    linux::collect_listening_sockets(include_udp)
}

#[cfg(not(target_os = "linux"))]
pub fn collect_listening_sockets(_include_udp: bool) -> Result<Vec<SocketInfo>> {
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::SocketInfo;
    use anyhow::{Context, Result};
    use std::{fs, net::Ipv6Addr};

    pub fn collect_listening_sockets(include_udp: bool) -> Result<Vec<SocketInfo>> {
        let mut sockets = Vec::new();
        collect_from_file("/proc/net/tcp", "tcp", true, &mut sockets)?;
        collect_from_file("/proc/net/tcp6", "tcp6", true, &mut sockets)?;

        if include_udp {
            collect_from_file("/proc/net/udp", "udp", false, &mut sockets)?;
            collect_from_file("/proc/net/udp6", "udp6", false, &mut sockets)?;
        }

        Ok(sockets)
    }

    fn collect_from_file(
        path: &str,
        protocol: &str,
        tcp_only_listen: bool,
        sockets: &mut Vec<SocketInfo>,
    ) -> Result<()> {
        let raw = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;

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
                sockets.push(SocketInfo {
                    protocol: protocol.to_string(),
                    local_address: address,
                    local_port: port,
                    inode,
                });
            }
        }

        Ok(())
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
}
