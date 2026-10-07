use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sentinel_rs::{
    anomaly::{
        detect_new_listeners, detect_new_processes, event_for_baseline_initialized,
        event_for_first_seen_connection, event_for_first_seen_listener,
        event_for_first_seen_process, event_for_listener_owner_change,
    },
    baseline::BaselineStore,
    config::SentinelConfig,
    detection::{event_for_process, event_for_socket},
    event::{EventKind, SecurityEvent, Severity},
    filesystem::FilesystemMonitor,
    logger,
    network::{collect_connections, collect_listening_sockets, SocketState},
    process::{collect_processes, ProcessState},
};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use tracing::{info, warn};

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct Cli {
    #[arg(short, long, default_value = "config/sentinel.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run continuously until Ctrl-C.
    Run,
    /// Collect one telemetry snapshot and print JSON events.
    Once,
    /// Validate configuration and exit.
    ValidateConfig,
    /// Print a default TOML configuration.
    DefaultConfig,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::DefaultConfig => {
            println!("{}", SentinelConfig::default().to_pretty_toml()?);
            Ok(())
        }
        Command::ValidateConfig => {
            let config = SentinelConfig::from_path(&cli.config)?;
            logger::init(&config.logging)?;
            info!(path = %cli.config.display(), "configuration is valid");
            Ok(())
        }
        Command::Once => {
            let config = load_config(&cli.config)?;
            logger::init(&config.logging)?;
            for event in collect_once(&config, false)? {
                print_event(&event)?;
            }
            Ok(())
        }
        Command::Run => {
            let config = load_config(&cli.config)?;
            logger::init(&config.logging)?;
            run(config)
        }
    }
}

fn load_config(path: &PathBuf) -> Result<SentinelConfig> {
    if path.exists() {
        SentinelConfig::from_path(path)
    } else {
        Ok(SentinelConfig::default())
    }
}

fn run(config: SentinelConfig) -> Result<()> {
    let running = Arc::new(AtomicBool::new(true));
    let signal = running.clone();
    ctrlc::set_handler(move || {
        signal.store(false, Ordering::SeqCst);
    })
    .context("failed to install Ctrl-C handler")?;

    let filesystem = if config.filesystem.enabled {
        match FilesystemMonitor::new(&config.filesystem.paths, config.filesystem.recursive) {
            Ok(monitor) => Some(monitor),
            Err(error) => {
                warn!(%error, "filesystem monitor disabled");
                None
            }
        }
    } else {
        None
    };

    let mut process_state = ProcessState::new();
    let mut socket_state = SocketState::new();

    let mut baseline = config
        .baseline
        .enabled
        .then(|| BaselineStore::load(&config.baseline.path))
        .transpose()?;
    let interval = Duration::from_secs(config.telemetry.interval_seconds.max(1));

    print_event(&SecurityEvent::new(
        EventKind::MonitorStatus,
        Severity::Info,
        "sentinel",
        "sentinel-rs started in read-only monitoring mode",
    ))?;

    while running.load(Ordering::SeqCst) {
        for event in collect_stateful(
            &config,
            &mut process_state,
            &mut socket_state,
            baseline.as_mut(),
        )? {
            print_event(&event)?;
        }

        if let Some(monitor) = &filesystem {
            for event in monitor.drain_events() {
                print_event(&event)?;
            }
        }

        thread::sleep(interval);
    }

    print_event(&SecurityEvent::new(
        EventKind::MonitorStatus,
        Severity::Info,
        "sentinel",
        "sentinel-rs stopped",
    ))?;

    Ok(())
}

fn collect_once(config: &SentinelConfig, stateful: bool) -> Result<Vec<SecurityEvent>> {
    let mut process_state = ProcessState::new();
    let mut socket_state = SocketState::new();

    if stateful {
        let mut baseline = config
            .baseline
            .enabled
            .then(|| BaselineStore::load(&config.baseline.path))
            .transpose()?;
        collect_stateful(
            config,
            &mut process_state,
            &mut socket_state,
            baseline.as_mut(),
        )
    } else {
        let mut events = Vec::new();

        if config.process.enabled {
            for process in collect_processes(config.process.include_command_line)? {
                events.push(event_for_process(&process, EventKind::ProcessObserved));
            }
        }

        if config.network.enabled {
            for socket in collect_listening_sockets(
                config.network.include_udp,
                config.process.include_command_line,
            )? {
                events.push(event_for_socket(&socket));
            }
        }

        Ok(events)
    }
}

fn collect_stateful(
    config: &SentinelConfig,
    process_state: &mut ProcessState,
    socket_state: &mut SocketState,
    baseline: Option<&mut BaselineStore>,
) -> Result<Vec<SecurityEvent>> {
    let mut events = Vec::new();
    let processes = config
        .process
        .enabled
        .then(|| collect_processes(config.process.include_command_line))
        .transpose()?;
    let sockets = config
        .network
        .enabled
        .then(|| {
            collect_listening_sockets(
                config.network.include_udp,
                config.process.include_command_line,
            )
        })
        .transpose()?;
    let connections = (config.behavior.enabled && config.behavior.track_outbound)
        .then(|| {
            collect_connections(
                config.network.include_udp,
                config.process.include_command_line,
            )
        })
        .transpose()?;

    if let Some(processes) = processes.as_ref() {
        for process in process_state.new_processes(processes) {
            events.push(event_for_process(&process, EventKind::ProcessStart));
        }
    }

    if let Some(sockets) = sockets.as_ref() {
        let owner_changes = socket_state.owner_changes(sockets);
        for socket in socket_state.new_sockets(sockets) {
            events.push(event_for_socket(&socket));
        }

        for change in owner_changes {
            events.push(event_for_listener_owner_change(&change));
        }
    }

    if let Some(baseline) = baseline {
        if let (Some(processes), Some(sockets)) = (processes.as_ref(), sockets.as_ref()) {
            if baseline.is_empty() && config.baseline.initialize_on_first_run {
                baseline.initialize_from_snapshot(processes, sockets);
                if let Some(connections) = connections.as_ref() {
                    baseline.initialize_connections(connections);
                }
                if let Err(error) = baseline.save() {
                    warn!(%error, path = %baseline.path().display(), "failed to persist baseline");
                }
                events.push(event_for_baseline_initialized(
                    baseline.process_count(),
                    baseline.listener_count(),
                ));
                return Ok(events);
            }

            let new_processes =
                detect_new_processes(processes, baseline, &config.baseline.allowlist);
            for process in new_processes {
                events.push(event_for_first_seen_process(&process));
                if config.baseline.learn_new {
                    baseline.add_process(&process);
                }
            }

            let new_listeners = detect_new_listeners(sockets, baseline, &config.baseline.allowlist);
            for socket in new_listeners {
                events.push(event_for_first_seen_listener(&socket));
                if config.baseline.learn_new {
                    baseline.add_listener(&socket);
                }

                if let Some(connections) = connections.as_ref() {
                    let new_connections = sentinel_rs::anomaly::detect_new_network_behavior(
                        connections,
                        baseline,
                        &config.behavior.allowlist,
                    );
                    for connection in new_connections {
                        events.push(event_for_first_seen_connection(&connection));
                        if config.behavior.learn_new {
                            baseline.add_connection(&connection);
                        }
                    }
                }
            }

            if config.baseline.learn_new && (!baseline.is_empty()) {
                if let Err(error) = baseline.save() {
                    warn!(%error, path = %baseline.path().display(), "failed to persist baseline");
                }
            }
        }
    }

    Ok(events)
}

fn print_event(event: &SecurityEvent) -> Result<()> {
    println!("{}", event.to_json_line()?);
    Ok(())
}
