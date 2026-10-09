use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use netplus::{Config, run};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "A lightweight Tokio-based SOCKS5 routing client")]
struct Cli {
    #[arg(short, long, default_value = "config")]
    config: PathBuf,
    #[arg(long, help = "Verify the SOCKS5 upstream and print its public IP")]
    test_upstream: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let config = Config::load(&cli.config)
        .await
        .with_context(|| format!("failed to load {}", cli.config.display()))?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(config.log_level.filter())),
        )
        .with_ansi(false)
        .init();

    if cli.test_upstream {
        let public_ip = netplus::test_upstream(&config).await?;
        println!("Public IP through upstream: {public_ip}");
        return Ok(());
    }

    run(config).await
}
