use crate::{
    baseline::{BaselineStore, ProcessNetworkBaselineKey},
    config::BehaviorAllowlistConfig,
    network::ConnectionInfo,
};

pub fn detect_new_connections(
    connections: &[ConnectionInfo],
    baseline: &BaselineStore,
    allowlist: &BehaviorAllowlistConfig,
) -> Vec<ConnectionInfo> {
    connections
        .iter()
        .filter(|connection| !allowlisted(connection, allowlist))
        .filter(|connection| !baseline.contains_connection(connection))
        .cloned()
        .collect()
}

pub fn allowlisted(connection: &ConnectionInfo, allowlist: &BehaviorAllowlistConfig) -> bool {
    connection
        .process
        .as_ref()
        .and_then(|process| process.exe.as_deref())
        .is_some_and(|exe| {
            allowlist
                .process_executables
                .iter()
                .any(|entry| entry == exe)
        })
        || allowlist
            .remote_addresses
            .contains(&connection.remote_address)
        || allowlist.remote_ports.contains(&connection.remote_port)
}

pub fn connection_key(connection: &ConnectionInfo) -> ProcessNetworkBaselineKey {
    ProcessNetworkBaselineKey {
        executable: connection
            .process
            .as_ref()
            .and_then(|process| process.exe.clone()),
        uid: connection.process.as_ref().and_then(|process| process.uid),
        name: connection
            .process
            .as_ref()
            .and_then(|process| process.name.clone()),
        protocol: connection.protocol.clone(),
        remote_address: connection.remote_address.clone(),
        remote_port: connection.remote_port,
    }
}

#[cfg(test)]
mod tests {
    use super::detect_new_connections;
    use crate::{
        baseline::BaselineStore, config::BehaviorAllowlistConfig, network::ConnectionInfo,
        process::ProcessInfo,
    };

    fn connection(port: u16) -> ConnectionInfo {
        ConnectionInfo {
            protocol: "tcp".into(),
            local_address: "127.0.0.1".into(),
            local_port: 40000,
            remote_address: "203.0.113.10".into(),
            remote_port: port,
            inode: Some(1),
            process: Some(ProcessInfo {
                pid: 10,
                name: Some("curl".into()),
                exe: Some("/usr/bin/curl".into()),
                cmdline: None,
                uid: Some(1000),
            }),
        }
    }

    #[test]
    fn detects_new_connection_and_deduplicates_after_learning() {
        let candidate = connection(443);
        let mut baseline = BaselineStore::empty("baseline.json");
        let allowlist = BehaviorAllowlistConfig::default();

        assert_eq!(
            detect_new_connections(&[candidate.clone()], &baseline, &allowlist),
            vec![candidate.clone()]
        );
        baseline.add_connection(&candidate);
        assert!(detect_new_connections(&[candidate], &baseline, &allowlist).is_empty());
    }

    #[test]
    fn suppresses_allowlisted_remote_port() {
        let allowlist = BehaviorAllowlistConfig {
            remote_ports: vec![443],
            ..BehaviorAllowlistConfig::default()
        };

        assert!(detect_new_connections(
            &[connection(443)],
            &BaselineStore::empty("baseline.json"),
            &allowlist,
        )
        .is_empty());
    }
}
