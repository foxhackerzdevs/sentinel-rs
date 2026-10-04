use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sentinel_rs::{
    config::SentinelConfig,
    detection::{event_for_process, event_for_socket},
    event::{EventKind, SecurityEvent, Severity},
    filesystem::FilesystemMonitor,
    logger,
    network::{collect_listening_sockets, SocketState},
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
    let interval = Duration::from_secs(config.telemetry.interval_seconds.max(1));

    print_event(&SecurityEvent::new(
        EventKind::MonitorStatus,
        Severity::Info,
        "sentinel",
        "sentinel-rs started in read-only monitoring mode",
    ))?;

    while running.load(Ordering::SeqCst) {
        for event in collect_stateful(&config, &mut process_state, &mut socket_state)? {
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
        collect_stateful(config, &mut process_state, &mut socket_state)
    } else {
        let mut events = Vec::new();

        if config.process.enabled {
            for process in collect_processes(config.process.include_command_line)? {
                events.push(event_for_process(&process, EventKind::ProcessObserved));
            }
        }

        if config.network.enabled {
            for socket in collect_listening_sockets(config.network.include_udp)? {
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
) -> Result<Vec<SecurityEvent>> {
    let mut events = Vec::new();

    if config.process.enabled {
        let processes = collect_processes(config.process.include_command_line)?;
        for process in process_state.new_processes(&processes) {
            events.push(event_for_process(&process, EventKind::ProcessStart));
        }
    }

    if config.network.enabled {
        let sockets = collect_listening_sockets(config.network.include_udp)?;
        for socket in socket_state.new_sockets(&sockets) {
            events.push(event_for_socket(&socket));
        }
    }

    Ok(events)
}

fn print_event(event: &SecurityEvent) -> Result<()> {
    println!("{}", event.to_json_line()?);
    Ok(())
}
