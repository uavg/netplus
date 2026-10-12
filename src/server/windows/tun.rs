use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

use anyhow::{Context, ensure};
use tokio::{net::lookup_host, process::Command, task::JoinHandle};
use tracing::{info, warn};
use tun2proxy::{ArgDns, Args, CancellationToken, LevelFilter, ProxyParameters, general_run_async};
use url::Url;

use crate::{Config, config::TunModeConfig};

const TUN_GATEWAY: &str = "10.0.0.1";
const ADAPTER_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const ENGINE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const POWERSHELL_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct TunMode {
    shutdown: CancellationToken,
    task: Option<JoinHandle<std::io::Result<usize>>>,
    routes: RouteManager,
}

impl TunMode {
    pub async fn start(
        config: &Config,
        tun: TunModeConfig,
        startup_cancel: CancellationToken,
    ) -> anyhow::Result<Self> {
        ensure_wintun_available()?;
        let (proxy_url, proxy_address) =
            startup_step(&startup_cancel, resolved_proxy(config)).await?;
        ensure!(
            proxy_address != IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "TUN upstream resolves to {TUN_GATEWAY}, which conflicts with tun2proxy's internal \
             Wintun gateway; use another reachable address for the SOCKS5 server"
        );
        let upstream_route = startup_step(&startup_cancel, find_route(proxy_address)).await?;
        let proxy = ProxyParameters::try_from(proxy_url.as_str())
            .map_err(|error| anyhow::anyhow!("invalid TUN proxy URL: {error}"))?;
        ensure_startup_active(&startup_cancel)?;
        let mut routes = RouteManager::install_proxy_bypass(proxy_address, upstream_route).await?;
        if let Err(error) = ensure_startup_active(&startup_cancel) {
            routes.cleanup().await?;
            return Err(error);
        }

        let args = Args {
            proxy,
            tun: Some(tun.interface_name.clone()),
            ipv6_enabled: false,
            setup: false,
            dns: ArgDns::Virtual,
            mtu: tun.mtu,
            tcp_mss: Some(tun.mtu.saturating_sub(40)),
            max_sessions: tun.max_sessions,
            exit_on_fatal_error: false,
            verbosity: LevelFilter::Warn,
            ..Args::default()
        };

        let shutdown = CancellationToken::new();
        let task_shutdown = shutdown.clone();
        let mtu = tun.mtu;
        let mut task =
            tokio::spawn(async move { general_run_async(args, mtu, false, task_shutdown).await });

        info!(interface = %tun.interface_name, "Waiting for Windows TUN adapter");
        let interface_index =
            match wait_for_adapter(&tun.interface_name, &mut task, &startup_cancel).await {
                Ok(interface_index) => interface_index,
                Err(error) => {
                    warn!(%error, "Windows TUN adapter startup failed; rolling back");
                    stop_engine(&shutdown, task).await;
                    routes.cleanup().await?;
                    return Err(error);
                }
            };
        info!(
            interface = %tun.interface_name,
            interface_index,
            "Windows TUN adapter is ready"
        );
        info!(
            upstream = %proxy_address,
            "Verifying Windows TUN default route"
        );
        if let Err(error) =
            startup_step(&startup_cancel, verify_default_route(interface_index)).await
        {
            warn!(
                error = %format!("{error:#}"),
                "Windows TUN route setup failed; rolling back"
            );
            stop_engine(&shutdown, task).await;
            routes.cleanup().await?;
            return Err(error);
        }

        info!(
            interface = %tun.interface_name,
            mtu = tun.mtu,
            max_sessions = tun.max_sessions,
            "Windows full-system TUN mode started"
        );
        Ok(Self {
            shutdown,
            task: Some(task),
            routes,
        })
    }

    pub async fn wait_for_failure(&mut self) -> anyhow::Error {
        let result = self
            .task
            .as_mut()
            .expect("TUN task is present while traffic mode is running")
            .await;
        self.task = None;
        task_error(result)
    }

    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        info!("Stopping Windows TUN engine");
        if let Some(task) = self.task.take() {
            stop_engine(&self.shutdown, task).await;
        }
        info!("Removing Windows TUN routes");
        self.routes.cleanup().await?;
        info!("Windows TUN routes restored");
        Ok(())
    }
}

impl Drop for TunMode {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

#[derive(Clone)]
struct Route {
    destination: String,
    interface_index: u32,
    next_hop: String,
}

struct RouteManager {
    installed: Vec<Route>,
}

impl RouteManager {
    async fn install_proxy_bypass(
        proxy_address: IpAddr,
        upstream_route: OriginalRoute,
    ) -> anyhow::Result<Self> {
        let mut manager = Self {
            installed: Vec::new(),
        };
        let bypass = Route {
            destination: format!("{proxy_address}/32"),
            interface_index: upstream_route.interface_index,
            next_hop: upstream_route.next_hop,
        };
        if let Err(error) = manager.install(bypass).await {
            if let Err(cleanup_error) = manager.cleanup().await {
                return Err(error.context(format!("route rollback also failed: {cleanup_error:#}")));
            }
            return Err(error);
        }
        Ok(manager)
    }

    async fn install(&mut self, route: Route) -> anyhow::Result<()> {
        let script = format!(
            "New-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}' \
             -InterfaceIndex {} -NextHop '{}' -RouteMetric 1 -ErrorAction Stop | Out-Null",
            route.destination, route.interface_index, route.next_hop
        );
        run_powershell(&script)
            .await
            .with_context(|| format!("failed to install route {}", route.destination))?;
        self.installed.push(route);
        Ok(())
    }

    async fn cleanup(&mut self) -> anyhow::Result<()> {
        let mut commands = Vec::new();
        for route in self.installed.drain(..).rev() {
            commands.push(format!(
                "try {{ Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '{}' \
                 -InterfaceIndex {} -NextHop '{}' -ErrorAction SilentlyContinue | \
                 Remove-NetRoute -Confirm:$false -ErrorAction Stop }} \
                 catch {{ $failures.Add($_.Exception.Message) }}",
                route.destination, route.interface_index, route.next_hop
            ));
        }
        if commands.is_empty() {
            return Ok(());
        }
        let script = format!(
            "$failures = [System.Collections.Generic.List[string]]::new(); {}; \
             if ($failures.Count -gt 0) {{ throw ($failures -join '; ') }}",
            commands.join("; ")
        );
        run_powershell(&script)
            .await
            .context("failed to restore Windows routes")?;
        Ok(())
    }
}

async fn verify_default_route(interface_index: u32) -> anyhow::Result<()> {
    let script = format!(
        "$route = Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix '0.0.0.0/0' \
         -InterfaceIndex {interface_index} -NextHop '{TUN_GATEWAY}' -ErrorAction Stop | \
         Select-Object -First 1; if (-not $route) {{ throw 'Wintun default route was not created' }}"
    );
    run_powershell(&script)
        .await
        .context("failed to verify the Wintun default route")?;
    Ok(())
}

struct OriginalRoute {
    interface_index: u32,
    next_hop: String,
}

async fn find_route(address: IpAddr) -> anyhow::Result<OriginalRoute> {
    let script = format!(
        "$route = Find-NetRoute -RemoteIPAddress '{}' | \
         Where-Object {{ $_.PSObject.Properties.Name -contains 'NextHop' }} | \
         Select-Object -First 1; \
         if (-not $route) {{ throw 'No route found' }}; \
         if ($null -eq $route.InterfaceIndex -or $null -eq $route.NextHop) {{ \
             throw 'Route is missing InterfaceIndex or NextHop' \
         }}; \
         Write-Output ($route.InterfaceIndex.ToString() + '|' + $route.NextHop.ToString())",
        address
    );
    let output = run_powershell(&script)
        .await
        .with_context(|| format!("failed to find the existing route to TUN upstream {address}"))?;
    let (interface_index, next_hop) = output
        .trim()
        .split_once('|')
        .context("PowerShell returned an invalid upstream route")?;
    Ok(OriginalRoute {
        interface_index: interface_index
            .parse()
            .context("PowerShell returned an invalid upstream interface index")?,
        next_hop: next_hop.to_owned(),
    })
}

async fn wait_for_adapter(
    interface_name: &str,
    task: &mut JoinHandle<std::io::Result<usize>>,
    startup_cancel: &CancellationToken,
) -> anyhow::Result<u32> {
    let deadline = tokio::time::Instant::now() + ADAPTER_STARTUP_TIMEOUT;
    let script = format!(
        "Write-Output ((Get-NetAdapter -Name '{}' -ErrorAction Stop).ifIndex)",
        interface_name
    );
    loop {
        tokio::select! {
            _ = startup_cancel.cancelled() => {
                anyhow::bail!("Windows TUN startup cancelled");
            }
            result = &mut *task => return Err(task_error(result)),
            result = run_powershell(&script) => {
                if let Ok(output) = result
                    && let Ok(interface_index) = output.trim().parse()
                {
                    return Ok(interface_index);
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "Wintun adapter {interface_name:?} did not become ready within {} seconds",
                ADAPTER_STARTUP_TIMEOUT.as_secs()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn startup_step<T, F>(startup_cancel: &CancellationToken, operation: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    tokio::select! {
        _ = startup_cancel.cancelled() => {
            anyhow::bail!("Windows TUN startup cancelled");
        }
        result = operation => result,
    }
}

fn ensure_startup_active(startup_cancel: &CancellationToken) -> anyhow::Result<()> {
    ensure!(
        !startup_cancel.is_cancelled(),
        "Windows TUN startup cancelled"
    );
    Ok(())
}

async fn run_powershell(script: &str) -> anyhow::Result<String> {
    let mut command = Command::new("powershell.exe");
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .kill_on_drop(true);
    let output = tokio::time::timeout(POWERSHELL_TIMEOUT, command.output())
        .await
        .context("PowerShell timed out")?
        .context("failed to run PowerShell")?;
    ensure!(
        output.status.success(),
        "PowerShell failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

async fn stop_engine(shutdown: &CancellationToken, mut task: JoinHandle<std::io::Result<usize>>) {
    shutdown.cancel();
    match tokio::time::timeout(ENGINE_SHUTDOWN_TIMEOUT, &mut task).await {
        Ok(Ok(Ok(sessions))) => info!(sessions, "Windows TUN engine stopped"),
        Ok(Ok(Err(error))) => warn!(%error, "Windows TUN engine stopped with an error"),
        Ok(Err(error)) => warn!(%error, "Windows TUN task terminated unexpectedly"),
        Err(_) => {
            warn!("Windows TUN engine did not stop in time; aborting it before route cleanup");
            task.abort();
            let _ = task.await;
        }
    }
}

async fn resolved_proxy(config: &Config) -> anyhow::Result<(String, IpAddr)> {
    let upstream = config
        .upstream()?
        .context("TUN mode requires a SOCKS5 upstream")?;
    let address = lookup_host((upstream.host.as_str(), upstream.port))
        .await
        .with_context(|| format!("failed to resolve TUN upstream {}", upstream.host))?
        .map(|address| address.ip())
        .find(IpAddr::is_ipv4)
        .context("TUN upstream did not resolve to an IPv4 address")?;

    let mut url = Url::parse(
        config
            .upstream
            .as_deref()
            .context("TUN mode requires a SOCKS5 upstream")?,
    )?;
    url.set_host(Some(&address.to_string()))
        .map_err(|_| anyhow::anyhow!("failed to pin the TUN upstream address"))?;
    Ok((url.into(), address))
}

fn ensure_wintun_available() -> anyhow::Result<()> {
    let executable = std::env::current_exe().context("failed to locate netplus.exe")?;
    let path = executable
        .parent()
        .context("netplus.exe has no parent directory")?
        .join("wintun.dll");
    ensure!(
        path.is_file(),
        "{} is missing; place the official Wintun DLL beside netplus.exe",
        path.display()
    );
    Ok(())
}

fn task_error(result: Result<std::io::Result<usize>, tokio::task::JoinError>) -> anyhow::Error {
    match result {
        Ok(Ok(sessions)) => {
            anyhow::anyhow!("Windows TUN mode stopped with {sessions} active sessions")
        }
        Ok(Err(error)) => anyhow::Error::new(error).context("Windows TUN mode failed"),
        Err(error) => anyhow::Error::new(error).context("Windows TUN task terminated unexpectedly"),
    }
}
