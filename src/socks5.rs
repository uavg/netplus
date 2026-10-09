use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const USERNAME_PASSWORD: u8 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

impl Target {
    pub fn display(&self) -> String {
        match self {
            Self::Ip(ip, port) => format!("{ip}:{port}"),
            Self::Domain(domain, port) => format!("{domain}:{port}"),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum SocksError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported SOCKS version {0}")]
    UnsupportedVersion(u8),
    #[error("no acceptable authentication method")]
    NoAuthMethod,
    #[error("unsupported command {0}")]
    UnsupportedCommand(u8),
    #[error("unsupported address type {0}")]
    UnsupportedAddressType(u8),
    #[error("invalid domain name")]
    InvalidDomain,
    #[error("upstream authentication failed")]
    AuthenticationFailed,
    #[error("upstream rejected request with code {0}")]
    UpstreamRejected(u8),
    #[error("credential is longer than 255 bytes")]
    CredentialTooLong,
}

pub(crate) async fn accept_request<S>(stream: &mut S) -> Result<Target, SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }
    let method_count = stream.read_u8().await? as usize;
    let mut methods = vec![0; method_count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTH) {
        stream.write_all(&[VERSION, 0xff]).await?;
        return Err(SocksError::NoAuthMethod);
    }
    stream.write_all(&[VERSION, NO_AUTH]).await?;

    let version = stream.read_u8().await?;
    if version != VERSION {
        return Err(SocksError::UnsupportedVersion(version));
    }
    let command = stream.read_u8().await?;
    let _reserved = stream.read_u8().await?;
    if command != 1 {
        write_reply(stream, 7, unspecified_address()).await?;
        return Err(SocksError::UnsupportedCommand(command));
    }
    read_target(stream).await
}

pub(crate) async fn connect_upstream<S>(
    stream: &mut S,
    target: &Target,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let methods: &[u8] = if username.is_some() {
        &[NO_AUTH, USERNAME_PASSWORD]
    } else {
        &[NO_AUTH]
    };
    stream.write_all(&[VERSION, methods.len() as u8]).await?;
    stream.write_all(methods).await?;

    let response_version = stream.read_u8().await?;
    let method = stream.read_u8().await?;
    if response_version != VERSION {
        return Err(SocksError::UnsupportedVersion(response_version));
    }
    match method {
        NO_AUTH => {}
        USERNAME_PASSWORD if username.is_some() => {
            authenticate(stream, username.unwrap_or_default(), password.unwrap_or("")).await?
        }
        _ => return Err(SocksError::NoAuthMethod),
    }

    stream.write_all(&[VERSION, 1, 0]).await?;
    write_target(stream, target).await?;
    let response_version = stream.read_u8().await?;
    let reply = stream.read_u8().await?;
    let _reserved = stream.read_u8().await?;
    if response_version != VERSION {
        return Err(SocksError::UnsupportedVersion(response_version));
    }
    if reply != 0 {
        return Err(SocksError::UpstreamRejected(reply));
    }
    let _bound_address = read_target(stream).await?;
    Ok(())
}

pub(crate) async fn write_reply<S>(
    stream: &mut S,
    code: u8,
    address: SocketAddr,
) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[VERSION, code, 0]).await?;
    write_target(stream, &Target::Ip(address.ip(), address.port())).await
}

async fn authenticate<S>(stream: &mut S, username: &str, password: &str) -> Result<(), SocksError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let username = credential_bytes(username)?;
    let password = credential_bytes(password)?;
    stream.write_all(&[1, username.len() as u8]).await?;
    stream.write_all(username).await?;
    stream.write_all(&[password.len() as u8]).await?;
    stream.write_all(password).await?;
    let version = stream.read_u8().await?;
    let status = stream.read_u8().await?;
    if version != 1 || status != 0 {
        return Err(SocksError::AuthenticationFailed);
    }
    Ok(())
}

fn credential_bytes(credential: &str) -> Result<&[u8], SocksError> {
    let bytes = credential.as_bytes();
    if bytes.len() > u8::MAX as usize {
        return Err(SocksError::CredentialTooLong);
    }
    Ok(bytes)
}

async fn read_target<S>(stream: &mut S) -> Result<Target, SocksError>
where
    S: AsyncRead + Unpin,
{
    let address_type = stream.read_u8().await?;
    let target = match address_type {
        1 => {
            let ip = Ipv4Addr::from(stream.read_u32().await?);
            Target::Ip(IpAddr::V4(ip), stream.read_u16().await?)
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            let mut domain = vec![0; length];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| SocksError::InvalidDomain)?;
            Target::Domain(domain, stream.read_u16().await?)
        }
        4 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            Target::Ip(IpAddr::V6(Ipv6Addr::from(octets)), stream.read_u16().await?)
        }
        value => return Err(SocksError::UnsupportedAddressType(value)),
    };
    Ok(target)
}

async fn write_target<S>(stream: &mut S, target: &Target) -> Result<(), SocksError>
where
    S: AsyncWrite + Unpin,
{
    match target {
        Target::Ip(IpAddr::V4(ip), port) => {
            stream.write_u8(1).await?;
            stream.write_all(&ip.octets()).await?;
            stream.write_u16(*port).await?;
        }
        Target::Ip(IpAddr::V6(ip), port) => {
            stream.write_u8(4).await?;
            stream.write_all(&ip.octets()).await?;
            stream.write_u16(*port).await?;
        }
        Target::Domain(domain, port) => {
            let bytes = credential_bytes(domain)?;
            stream.write_u8(3).await?;
            stream.write_u8(bytes.len() as u8).await?;
            stream.write_all(bytes).await?;
            stream.write_u16(*port).await?;
        }
    }
    Ok(())
}

fn unspecified_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    #[tokio::test]
    async fn accepts_domain_connect_request() {
        let (mut client, mut server) = duplex(128);
        let client_task = tokio::spawn(async move {
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut response = [0; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 0]);
            client
                .write_all(&[
                    5, 1, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o',
                    b'm', 0, 80,
                ])
                .await
                .unwrap();
        });

        let target = accept_request(&mut server).await.unwrap();
        assert_eq!(target, Target::Domain("example.com".into(), 80));
        client_task.await.unwrap();
    }
}
