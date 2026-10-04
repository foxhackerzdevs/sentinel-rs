use crate::config::LoggingConfig;
use anyhow::{anyhow, Result};
use tracing_subscriber::{fmt, EnvFilter};

pub fn init(config: &LoggingConfig) -> Result<()> {
    let filter = EnvFilter::try_new(&config.level).unwrap_or_else(|_| EnvFilter::new("info"));

    if config.json {
        fmt()
            .json()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow!("failed to initialize logger: {error}"))?;
    } else {
        fmt()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow!("failed to initialize logger: {error}"))?;
    }

    Ok(())
}
