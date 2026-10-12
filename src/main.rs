use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use netplus::{Config, run, run_with_shutdown};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(version, about = "A lightweight Tokio-based SOCKS5 routing client")]
struct Cli {
    #[arg(short, long, default_value = "config")]
    config: PathBuf,
    #[arg(long, help = "Verify the SOCKS5 upstream and print its public IP")]
    test_upstream: bool,
    #[arg(long, hide = true)]
    shutdown_file: Option<PathBuf>,
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

    if let Some(shutdown_file) = cli.shutdown_file {
        run_with_shutdown(config, wait_for_gui_shutdown(shutdown_file)).await
    } else {
        run(config).await
    }
}

async fn wait_for_gui_shutdown(shutdown_file: PathBuf) -> anyhow::Result<()> {
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            signal.context("failed to listen for shutdown signal")?;
        }
        result = wait_for_shutdown_file(&shutdown_file) => {
            result?;
        }
    }
    Ok(())
}

async fn wait_for_shutdown_file(path: &PathBuf) -> anyhow::Result<()> {
    loop {
        if tokio::fs::try_exists(path).await? {
            tokio::fs::remove_file(path)
                .await
                .context("failed to remove GUI shutdown signal")?;
            tracing::info!("GUI shutdown signal received");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
