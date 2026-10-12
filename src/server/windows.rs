use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    path::Path,
    sync::{Arc, RwLock},
    thread,
};

use anyhow::{Context, ensure};
use tokio::{io::copy_bidirectional, net::TcpListener};
use tracing::{debug, info, warn};
use windivert::prelude::*;
use windivert_sys::ChecksumFlags;
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    },
    UI::Shell::IsUserAnAdmin,
};

use super::{State, connect};
use crate::{
    Config,
    config::{ProcessBackend, ProcessModeConfig},
    router::Action,
    socks5::Target,
};

mod netch;
mod tun;

type FlowTable = Arc<RwLock<HashMap<u16, Ipv4Flow>>>;

#[derive(Clone, Debug)]
struct Ipv4Flow {
    endpoint_id: u64,
    remote_address: Ipv4Addr,
    remote_port: u16,
    process_id: u32,
    process_name: String,
}

pub(super) enum TrafficMode {
    None,
    WinDivert {
        listener_task: tokio::task::JoinHandle<()>,
    },
    Netch {
        _mode: netch::NetchProcessMode,
    },
    Tun(tun::TunMode),
}

impl TrafficMode {
    pub async fn start_with_cancellation(
        config: &Config,
        state: Arc<State>,
        startup_cancel: tun2proxy::CancellationToken,
    ) -> anyhow::Result<Self> {
        if let Some(tun_config) = config.tun_mode.clone() {
            ensure!(
                unsafe { IsUserAnAdmin() } != 0,
                "Windows TUN mode requires Administrator privileges"
            );
            return tun::TunMode::start(config, tun_config, startup_cancel)
                .await
                .map(Self::Tun);
        }
        let Some(process_config) = config.process_mode.clone() else {
            return Ok(Self::None);
        };
        ensure!(
            unsafe { IsUserAnAdmin() } != 0,
            "Windows process mode requires Administrator privileges"
        );
        if process_config.backend == ProcessBackend::Netch {
            return netch::NetchProcessMode::start(config, process_config)
                .map(|mode| Self::Netch { _mode: mode });
        }

        let listener = TcpListener::bind("0.0.0.0:0")
            .await
            .context("failed to bind the transparent process-mode listener")?;
        let listener_port = listener.local_addr()?.port();
        let socket_handle =
            WinDivert::socket("protocol == 6", 100, WinDivertFlags::new().set_sniff())
                .context("failed to open the WinDivert socket layer")?;
        let packet_filter = format!(
            "outbound and ip and tcp and !impostor and \
             (tcp.DstPort != {listener_port} or tcp.SrcPort == {listener_port})"
        );
        let network_handle = WinDivert::network(&packet_filter, 0, WinDivertFlags::new())
            .context("failed to open the WinDivert network layer")?;

        let flows = FlowTable::default();
        start_socket_worker(socket_handle, process_config, Arc::clone(&flows))?;
        start_packet_worker(network_handle, listener_port, Arc::clone(&flows))?;
        let listener_task = start_listener(listener, state, flows);
        info!(listener_port, "Windows process interception started");
        Ok(Self::WinDivert { listener_task })
    }

    pub async fn shutdown(&mut self) -> anyhow::Result<()> {
        match self {
            Self::WinDivert { listener_task } => listener_task.abort(),
            Self::Tun(mode) => return mode.shutdown().await,
            Self::None | Self::Netch { .. } => {}
        }
        Ok(())
    }

    pub async fn wait_for_failure(&mut self) -> anyhow::Error {
        match self {
            Self::Tun(mode) => mode.wait_for_failure().await,
            Self::None | Self::WinDivert { .. } | Self::Netch { .. } => {
                std::future::pending().await
            }
        }
    }
}

fn start_socket_worker(
    handle: WinDivert<SocketLayer>,
    config: ProcessModeConfig,
    flows: FlowTable,
) -> anyhow::Result<()> {
    thread::Builder::new()
        .name("netplus-socket-events".into())
        .spawn(move || socket_worker(handle, ProcessMatcher::new(config), flows))
        .context("failed to start the process matching worker")?;
    Ok(())
}

fn socket_worker(handle: WinDivert<SocketLayer>, matcher: ProcessMatcher, flows: FlowTable) {
    loop {
        let event = match handle.recv(None) {
            Ok(event) => event,
            Err(error) => {
                warn!(%error, "WinDivert socket worker stopped");
                return;
            }
        };
        let address = event.address;
        match address.event() {
            WinDivertEvent::SocketConnect => {
                let Some(process_name) = matcher.matching_process_name(address.process_id()) else {
                    continue;
                };
                let IpAddr::V4(remote_address) = address.remote_address() else {
                    debug!(
                        process_id = address.process_id(),
                        "ignoring IPv6 process flow"
                    );
                    continue;
                };
                if matcher.should_bypass(remote_address) {
                    debug!(
                        process = %process_name,
                        %remote_address,
                        "bypassing local or private process flow"
                    );
                    continue;
                }
                let flow = Ipv4Flow {
                    endpoint_id: address.endpoint_id(),
                    remote_address,
                    remote_port: address.remote_port(),
                    process_id: address.process_id(),
                    process_name,
                };
                if let Some(replaced) = write_flows(&flows).insert(address.local_port(), flow) {
                    debug!(
                        local_port = address.local_port(),
                        replaced_endpoint_id = replaced.endpoint_id,
                        endpoint_id = address.endpoint_id(),
                        "replaced process flow mapping"
                    );
                }
            }
            WinDivertEvent::SocketClose => {
                remove_closed_flow(
                    &mut write_flows(&flows),
                    address.local_port(),
                    address.endpoint_id(),
                );
            }
            _ => {}
        }
    }
}

fn remove_closed_flow(flows: &mut HashMap<u16, Ipv4Flow>, local_port: u16, endpoint_id: u64) {
    if flows
        .get(&local_port)
        .is_some_and(|flow| flow.endpoint_id == endpoint_id)
    {
        flows.remove(&local_port);
    }
}

fn start_packet_worker(
    handle: WinDivert<NetworkLayer>,
    listener_port: u16,
    flows: FlowTable,
) -> anyhow::Result<()> {
    thread::Builder::new()
        .name("netplus-packet-nat".into())
        .spawn(move || packet_worker(handle, listener_port, flows))
        .context("failed to start the packet interception worker")?;
    Ok(())
}

fn packet_worker(handle: WinDivert<NetworkLayer>, listener_port: u16, flows: FlowTable) {
    let mut buffer = vec![0; windivert_sys::WINDIVERT_MTU_MAX as usize];
    loop {
        let mut packet = match handle.recv(Some(&mut buffer)) {
            Ok(packet) => packet.into_owned(),
            Err(error) => {
                warn!(%error, "WinDivert packet worker stopped");
                return;
            }
        };
        if rewrite_ipv4_tcp(packet.data.to_mut(), listener_port, &read_flows(&flows))
            && let Err(error) = packet.recalculate_checksums(ChecksumFlags::new())
        {
            warn!(%error, "failed to update intercepted packet checksums");
            continue;
        }
        if let Err(error) = handle.send(&packet) {
            warn!(%error, "failed to reinject intercepted packet");
        }
    }
}

fn start_listener(
    listener: TcpListener,
    state: Arc<State>,
    flows: FlowTable,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    warn!(%error, "process-mode listener stopped");
                    return;
                }
            };
            let flow = read_flows(&flows).get(&peer.port()).cloned();
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                let Some(flow) = flow else {
                    warn!(%peer, "original destination is unavailable");
                    return;
                };
                if let Err(error) = relay_process_stream(stream, &flow, &state).await {
                    warn!(%peer, %error, "intercepted process connection failed");
                }
            });
        }
    })
}

async fn relay_process_stream(
    mut client: tokio::net::TcpStream,
    flow: &Ipv4Flow,
    state: &State,
) -> anyhow::Result<()> {
    let target = Target::Ip(IpAddr::V4(flow.remote_address), flow.remote_port);
    let action = state.router.action_for(&target);
    debug!(
        process = %flow.process_name,
        process_id = flow.process_id,
        target = %target.display(),
        ?action,
        "routing process connection"
    );
    ensure!(
        action != Action::Block,
        "connection blocked by routing rule"
    );
    let mut remote = connect(action, &target, state.upstream.as_ref()).await?;
    let (uploaded, downloaded) = copy_bidirectional(&mut client, &mut remote).await?;
    debug!(
        process = %flow.process_name,
        process_id = flow.process_id,
        target = %target.display(),
        uploaded,
        downloaded,
        "process connection closed"
    );
    Ok(())
}

fn rewrite_ipv4_tcp(packet: &mut [u8], listener_port: u16, flows: &HashMap<u16, Ipv4Flow>) -> bool {
    let Some(header_length) = ipv4_tcp_header_length(packet) else {
        return false;
    };
    let source_port = u16::from_be_bytes([packet[header_length], packet[header_length + 1]]);
    let destination_port =
        u16::from_be_bytes([packet[header_length + 2], packet[header_length + 3]]);

    if source_port == listener_port {
        let Some(flow) = flows.get(&destination_port) else {
            return false;
        };
        packet[12..16].copy_from_slice(&flow.remote_address.octets());
        packet[header_length..header_length + 2].copy_from_slice(&flow.remote_port.to_be_bytes());
        return true;
    }

    let Some(flow) = flows.get(&source_port) else {
        return false;
    };
    if packet[16..20] != flow.remote_address.octets() || destination_port != flow.remote_port {
        return false;
    }
    let source_address = [packet[12], packet[13], packet[14], packet[15]];
    packet[16..20].copy_from_slice(&source_address);
    packet[header_length + 2..header_length + 4].copy_from_slice(&listener_port.to_be_bytes());
    true
}

fn ipv4_tcp_header_length(packet: &[u8]) -> Option<usize> {
    if packet.len() < 24 || packet[0] >> 4 != 4 || packet[9] != 6 {
        return None;
    }
    let header_length = usize::from(packet[0] & 0x0f) * 4;
    let fragment_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
    (header_length >= 20 && fragment_offset == 0 && packet.len() >= header_length + 4)
        .then_some(header_length)
}

struct ProcessMatcher {
    executable_names: Vec<String>,
    process_ids: Vec<u32>,
    bypass_private: bool,
}

impl ProcessMatcher {
    fn new(config: ProcessModeConfig) -> Self {
        Self {
            executable_names: config
                .executable_names
                .into_iter()
                .map(|name| name.to_ascii_lowercase())
                .collect(),
            process_ids: config.process_ids,
            bypass_private: config.bypass_private,
        }
    }

    fn matching_process_name(&self, process_id: u32) -> Option<String> {
        if process_id == std::process::id() {
            return None;
        }
        let executable_name = process_executable_name(process_id);
        if self.process_ids.contains(&process_id) {
            return Some(executable_name.unwrap_or_else(|| format!("PID {process_id}")));
        }
        executable_name.filter(|name| self.executable_names.contains(name))
    }

    fn should_bypass(&self, address: Ipv4Addr) -> bool {
        self.bypass_private
            && (address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
                || is_shared_address(address))
    }
}

fn is_shared_address(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn process_executable_name(process_id: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id);
        if handle.is_null() {
            return None;
        }
        let mut buffer = vec![0_u16; 32_768];
        let mut length = buffer.len() as u32;
        let succeeded =
            QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut length) != 0;
        CloseHandle(handle);
        if !succeeded {
            return None;
        }
        let path = String::from_utf16_lossy(&buffer[..length as usize]);
        Path::new(&path)
            .file_name()
            .map(|name| name.to_string_lossy().to_ascii_lowercase())
    }
}

fn read_flows(flows: &FlowTable) -> std::sync::RwLockReadGuard<'_, HashMap<u16, Ipv4Flow>> {
    flows
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write_flows(flows: &FlowTable) -> std::sync::RwLockWriteGuard<'_, HashMap<u16, Ipv4Flow>> {
    flows
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_both_directions() {
        let remote = Ipv4Addr::new(203, 0, 113, 10);
        let flows = HashMap::from([(
            50_000,
            Ipv4Flow {
                endpoint_id: 42,
                remote_address: remote,
                remote_port: 443,
                process_id: 1234,
                process_name: "game.exe".into(),
            },
        )]);
        let mut outbound = tcp_packet(Ipv4Addr::new(192, 0, 2, 5), remote, 50_000, 443);
        assert!(rewrite_ipv4_tcp(&mut outbound, 15_000, &flows));
        assert_eq!(&outbound[16..20], &Ipv4Addr::new(192, 0, 2, 5).octets());
        assert_eq!(u16::from_be_bytes([outbound[22], outbound[23]]), 15_000);

        let mut inbound = tcp_packet(
            Ipv4Addr::new(192, 0, 2, 5),
            Ipv4Addr::new(192, 0, 2, 5),
            15_000,
            50_000,
        );
        assert!(rewrite_ipv4_tcp(&mut inbound, 15_000, &flows));
        assert_eq!(&inbound[12..16], &remote.octets());
        assert_eq!(u16::from_be_bytes([inbound[20], inbound[21]]), 443);
    }

    #[test]
    fn identifies_addresses_that_should_not_be_intercepted() {
        assert!(is_shared_address(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_shared_address(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!is_shared_address(Ipv4Addr::new(100, 128, 0, 1)));
    }

    #[test]
    fn socket_close_only_removes_its_own_flow() {
        let mut flows = HashMap::from([(
            50_000,
            Ipv4Flow {
                endpoint_id: 42,
                remote_address: Ipv4Addr::new(203, 0, 113, 10),
                remote_port: 443,
                process_id: 1234,
                process_name: "game.exe".into(),
            },
        )]);

        remove_closed_flow(&mut flows, 50_000, 99);
        assert!(flows.contains_key(&50_000));

        remove_closed_flow(&mut flows, 50_000, 42);
        assert!(!flows.contains_key(&50_000));
    }

    fn tcp_packet(source: Ipv4Addr, destination: Ipv4Addr, source_port: u16, port: u16) -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&port.to_be_bytes());
        packet
    }
}
