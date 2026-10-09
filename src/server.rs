use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{
    Config,
    config::Upstream,
    router::{Action, Router},
    socks5::{self, Target},
};

#[cfg(windows)]
mod windows;

pub async fn run(config: Config) -> anyhow::Result<()> {
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to listen on {}", config.listen))?;
    let state = Arc::new(State {
        router: config.router()?,
        upstream: config.upstream()?,
    });
    #[cfg(windows)]
    let _process_mode = windows::ProcessMode::start(&config, Arc::clone(&state)).await?;
    #[cfg(not(windows))]
    if config.process_mode.is_some() {
        anyhow::bail!("process_mode is only supported on Windows");
    }
    info!(address = %listener.local_addr()?, "SOCKS5 listener started");

    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("failed to accept connection")?;
                let state = Arc::clone(&state);
                clients.spawn(async move {
                    if let Err(error) = handle_client(stream, &state).await {
                        warn!(%peer, %error, "client connection failed");
                    }
                });
            }
            Some(result) = clients.join_next(), if !clients.is_empty() => {
                if let Err(error) = result {
                    warn!(%error, "client task terminated unexpectedly");
                }
            }
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to listen for shutdown signal")?;
                info!("shutdown signal received");
                break;
            }
        }
    }

    drop(listener);
    clients.shutdown().await;
    Ok(())
}

pub async fn test_upstream(config: &Config) -> anyhow::Result<IpAddr> {
    let upstream = config
        .upstream()?
        .context("no SOCKS5 upstream is configured")?;
    tokio::time::timeout(Duration::from_secs(10), query_public_ip(&upstream))
        .await
        .context("upstream public IP test timed out after 10 seconds")?
}

#[derive(Debug)]
pub(super) struct State {
    router: Router,
    upstream: Option<Upstream>,
}

async fn handle_client(mut client: TcpStream, state: &State) -> anyhow::Result<()> {
    let target = socks5::accept_request(&mut client).await?;
    let action = state.router.action_for(&target);
    debug!(target = %target.display(), ?action, "routing connection");

    if action == Action::Block {
        socks5::write_reply(&mut client, 2, unspecified_address()).await?;
        return Ok(());
    }

    let mut remote = match connect(action, &target, state.upstream.as_ref()).await {
        Ok(remote) => remote,
        Err(error) => {
            socks5::write_reply(&mut client, reply_code(&error), unspecified_address()).await?;
            return Err(error);
        }
    };
    let bound_address = remote
        .local_addr()
        .unwrap_or_else(|_| unspecified_address());
    socks5::write_reply(&mut client, 0, bound_address).await?;
    let (uploaded, downloaded) = copy_bidirectional(&mut client, &mut remote).await?;
    debug!(target = %target.display(), uploaded, downloaded, "connection closed");
    Ok(())
}

pub(super) async fn connect(
    action: Action,
    target: &Target,
    upstream: Option<&Upstream>,
) -> anyhow::Result<TcpStream> {
    match action {
        Action::Direct => connect_direct(target).await,
        Action::Proxy => {
            connect_proxy(
                target,
                upstream.context("proxy route has no configured upstream")?,
            )
            .await
        }
        Action::Block => unreachable!("blocked connections are handled before connect"),
    }
}

async fn connect_direct(target: &Target) -> anyhow::Result<TcpStream> {
    let stream = match target {
        Target::Ip(ip, port) => TcpStream::connect((*ip, *port)).await?,
        Target::Domain(domain, port) => TcpStream::connect((domain.as_str(), *port)).await?,
    };
    Ok(stream)
}

async fn connect_proxy(target: &Target, upstream: &Upstream) -> anyhow::Result<TcpStream> {
    let mut stream = TcpStream::connect((upstream.host.as_str(), upstream.port))
        .await
        .with_context(|| format!("failed to connect to upstream {}", upstream.host))?;
    socks5::connect_upstream(
        &mut stream,
        target,
        upstream.username.as_deref(),
        upstream.password.as_deref(),
    )
    .await?;
    Ok(stream)
}

async fn query_public_ip(upstream: &Upstream) -> anyhow::Result<IpAddr> {
    const SERVICES: [(&str, &str); 3] = [
        ("ifconfig.me", "/ip"),
        ("api.ipify.org", "/"),
        ("checkip.amazonaws.com", "/"),
    ];

    let mut failures = Vec::new();
    for (host, path) in SERVICES {
        match tokio::time::timeout(
            Duration::from_secs(3),
            query_public_ip_service(upstream, host, path),
        )
        .await
        {
            Ok(Ok(ip)) => return Ok(ip),
            Ok(Err(error)) => failures.push(format!("{host}: {error:#}")),
            Err(_) => failures.push(format!("{host}: timed out after 3 seconds")),
        }
    }

    anyhow::bail!("all public IP services failed: {}", failures.join("; "))
}

async fn query_public_ip_service(
    upstream: &Upstream,
    host: &str,
    path: &str,
) -> anyhow::Result<IpAddr> {
    let target = Target::Domain(host.into(), 80);
    let mut stream = connect_proxy(&target, upstream).await?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nAccept: text/plain\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("failed to send public IP request")?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .context("failed to read public IP response")?;
    parse_public_ip_response(&response)
}

fn parse_public_ip_response(response: &[u8]) -> anyhow::Result<IpAddr> {
    let response = std::str::from_utf8(response).context("public IP response was not UTF-8")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .context("public IP response was malformed")?;
    let status = headers.lines().next().unwrap_or_default();
    anyhow::ensure!(
        status.contains(" 200 "),
        "public IP service returned {status}"
    );
    body.trim().parse().with_context(|| {
        format!(
            "public IP service returned an invalid address: {}",
            body.trim()
        )
    })
}

fn reply_code(error: &anyhow::Error) -> u8 {
    error
        .downcast_ref::<io::Error>()
        .map_or(1, |error| match error.kind() {
            io::ErrorKind::ConnectionRefused => 5,
            io::ErrorKind::HostUnreachable => 4,
            io::ErrorKind::NetworkUnreachable => 3,
            io::ErrorKind::TimedOut => 6,
            _ => 1,
        })
}

fn unspecified_address() -> SocketAddr {
    "0.0.0.0:0".parse().expect("valid unspecified address")
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn relays_a_direct_socks_connection() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo_listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            let state = State {
                router: Router::new(Action::Direct, &[]).unwrap(),
                upstream: None,
            };
            handle_client(stream, &state).await.unwrap();
        });

        let mut client = TcpStream::connect(proxy_address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method_reply = [0; 2];
        client.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [5, 0]);

        let mut request = vec![5, 1, 0, 1];
        request.extend_from_slice(&match echo_address.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => unreachable!("test listener uses IPv4"),
        });
        request.extend_from_slice(&echo_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();

        let mut connect_reply = [0; 10];
        client.read_exact(&mut connect_reply).await.unwrap();
        assert_eq!(&connect_reply[..2], &[5, 0]);

        client.write_all(b"ping").await.unwrap();
        let mut echoed = [0; 4];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");
        client.shutdown().await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn parses_public_ip_response() {
        assert_eq!(
            parse_public_ip_response(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n203.0.113.9\n")
                .unwrap(),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        assert!(parse_public_ip_response(b"HTTP/1.1 503 Error\r\n\r\n").is_err());
    }
}
