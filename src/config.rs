use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    #[serde(default)]
    pub process: ProcessConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub baseline: BaselineConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub interval_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessConfig {
    pub enabled: bool,
    pub include_command_line: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub include_udp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemConfig {
    pub enabled: bool,
    pub paths: Vec<String>,
    pub recursive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    pub enabled: bool,

    pub path: String,

    pub initialize_on_first_run: bool,

    pub learn_new: bool,

    #[serde(default)]
    pub allowlist: BaselineAllowlistConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BaselineAllowlistConfig {
    #[serde(default)]
    pub process_executables: Vec<String>,

    #[serde(default)]
    pub listener_executables: Vec<String>,

    #[serde(default)]
    pub listener_ports: Vec<u16>,
}

impl Default for SentinelConfig {
    fn default() -> Self {
        Self {
            telemetry: TelemetryConfig::default(),
            process: ProcessConfig::default(),
            network: NetworkConfig::default(),
            filesystem: FilesystemConfig::default(),
            logging: LoggingConfig::default(),
            baseline: BaselineConfig::default(),
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 5,
        }
    }
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_command_line: true,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_udp: true,
        }
    }
}

impl Default for FilesystemConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: vec!["/etc".into(), "/usr/local/bin".into(), "/tmp".into()],
            recursive: false,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            json: false,
        }
    }
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "state/baseline.json".into(),
            initialize_on_first_run: true,
            learn_new: true,
            allowlist: BaselineAllowlistConfig::default(),
        }
    }
}

impl SentinelConfig {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {}", path.display()))?;
        toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config {}", path.display()))
    }

    pub fn to_pretty_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("failed to serialize default config")
    }
}
