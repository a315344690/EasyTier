use std::{any::Any, sync::Arc, time::Duration};

use anyhow::Context as _;
use cidr::Ipv4Inet;
use easytier_core::{
    gateway::dhcp::{DhcpIpv4ApplyOutcome, DhcpIpv4ApplyPermit, DhcpIpv4Host},
    host::packet::HostPacketReceiver,
    instance::CorePacketPlane,
};
use futures::FutureExt as _;
use tokio::{
    sync::{Mutex, Notify, oneshot},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use super::{MagicDnsRuntime, tun_common::TunNicState};
use crate::{
    common::{
        config::ConfigLoader as _,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    instance::virtual_nic::NicCtx,
};

#[cfg(target_os = "linux")]
use crate::instance::default_route::DefaultRouteManager;

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
use crate::instance::default_route_macos::{
    DefaultRouteManager, extract_ipv4_from_url, extract_ipv4_from_url_str,
};
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
use tokio_util::task::AbortOnDropHandle;

/// Activate the default route manager if configured. Returns a guard that
/// cleans up routing rules when dropped. The guard should be stored alongside
/// the NIC context so its lifetime matches the TUN device.
#[cfg(any(target_os = "linux", all(target_os = "macos", not(feature = "macos-ne"))))]
async fn activate_default_route(
    global_ctx: &ArcGlobalCtx,
    ifname: &str,
    #[cfg(target_os = "macos")] packet_plane: &Arc<CorePacketPlane>,
    #[cfg(not(target_os = "macos"))] _packet_plane: &Arc<CorePacketPlane>,
    #[cfg(target_os = "macos")] cancel: &CancellationToken,
    #[cfg(not(target_os = "macos"))] _cancel: &CancellationToken,
) -> Option<Box<dyn Any + Send>> {
    if !global_ctx.config.get_flags().default_route {
        return None;
    }

    #[cfg(target_os = "linux")]
    {
        // Fixed internal mark; not user-configurable. Must match the mark stamped
        // on our own sockets (see `default_route_socket_mark`) or self-traffic
        // self-routes into the TUN.
        let socket_mark = easytier_core::instance::DEFAULT_ROUTE_SOCKET_MARK;
        let mut mgr = DefaultRouteManager::new(ifname.to_owned(), socket_mark);
        match mgr.activate().await {
            Ok(()) => Some(Box::new(mgr)),
            Err(e) => {
                tracing::error!(?e, "failed to activate default route");
                None
            }
        }
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
    {
        use crate::proto::api::instance::PeerConnInfo;

        fn peer_ipv4(info: &PeerConnInfo) -> Option<std::net::Ipv4Addr> {
            info.tunnel
                .as_ref()
                .and_then(|t| t.effective_remote_addr())
                .and_then(|u| extract_ipv4_from_url_str(&u.url))
        }

        let mut mgr = DefaultRouteManager::new(ifname.to_owned());
        let config_ips = global_ctx
            .config
            .get_peers()
            .iter()
            .filter_map(|p| extract_ipv4_from_url(&p.uri))
            .collect::<Vec<_>>();
        let active_ips = packet_plane
            .list_peer_conns()
            .await
            .iter()
            .filter_map(|conn| {
                conn.tunnel
                    .as_ref()
                    .and_then(|t| t.effective_remote_addr())
                    .and_then(|u| extract_ipv4_from_url_str(&u.url))
            })
            .collect::<Vec<_>>();
        let initial_ips: Vec<_> = config_ips
            .into_iter()
            .chain(active_ips.into_iter())
            .collect();

        match mgr.activate(initial_ips).await {
            Ok(()) => {
                let mgr = Arc::new(tokio::sync::Mutex::new(mgr));
                let task = {
                    let mgr = mgr.clone();
                    let mut subscriber = global_ctx.subscribe();
                    let cancel = cancel.clone();
                    AbortOnDropHandle::new(tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                _ = cancel.cancelled() => break,
                                event = subscriber.recv() => {
                                    match event {
                                        Ok(GlobalCtxEvent::PeerConnAdded(info)) => {
                                            if let Some(addr) = peer_ipv4(&info) {
                                                let _ = mgr.lock().await.add_peer_route(addr).await;
                                            }
                                        }
                                        Ok(GlobalCtxEvent::PeerConnRemoved(info)) => {
                                            if let Some(addr) = peer_ipv4(&info) {
                                                let _ = mgr.lock().await.remove_peer_route(addr).await;
                                            }
                                        }
                                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }))
                };
                Some(Box::new((task, mgr)) as Box<dyn Any + Send>)
            }
            Err(e) => {
                tracing::error!(?e, "failed to activate default route (macOS)");
                None
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", all(target_os = "macos", not(feature = "macos-ne")))))]
async fn activate_default_route(
    _global_ctx: &ArcGlobalCtx,
    _ifname: &str,
    _packet_plane: &Arc<CorePacketPlane>,
    _cancel: &CancellationToken,
) -> Option<Box<dyn Any + Send>> {
    None
}

pub(super) struct NativeTunRuntime {
    global_ctx: ArcGlobalCtx,
    cancel: CancellationToken,
    nic: TunNicState,
    static_ip_task: Mutex<Option<JoinHandle<()>>>,
}

impl NativeTunRuntime {
    pub(super) fn new(global_ctx: ArcGlobalCtx, cancel: CancellationToken) -> Self {
        Self {
            global_ctx,
            cancel,
            nic: TunNicState::empty(),
            static_ip_task: Mutex::new(None),
        }
    }

    pub(super) fn install_packet_receiver(
        &self,
        receiver: HostPacketReceiver,
    ) -> anyhow::Result<()> {
        self.nic.install_receiver(receiver)
    }

    fn report_static_ip_cancelled(output: &mut Option<oneshot::Sender<Result<(), Error>>>) {
        if let Some(output) = output.take() {
            let _ = output.send(Err(anyhow::anyhow!(
                "instance is closing; static IP setup cancelled"
            )
            .into()));
        }
    }

    async fn start_static_ip(&self, packet_plane: Arc<CorePacketPlane>) -> anyhow::Result<()> {
        let ipv4 = self.global_ctx.get_ipv4();
        let ipv6 = self.global_ctx.get_ipv6();
        if ipv4.is_none() && ipv6.is_none() {
            return Ok(());
        }

        let nic_state = self.nic.clone();
        let cancel = self.cancel.clone();
        let global_ctx = self.global_ctx.clone();
        let receiver = self.nic.receiver();
        let (output, first_round) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut output = Some(output);
            loop {
                if cancel.is_cancelled() {
                    Self::report_static_ip_cancelled(&mut output);
                    return;
                }
                let closed = Arc::new(Notify::new());
                let mut nic = NicCtx::new(
                    global_ctx.clone(),
                    packet_plane.clone(),
                    receiver.clone(),
                    closed.clone(),
                );
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        Self::report_static_ip_cancelled(&mut output);
                        return;
                    }
                    result = nic.run(ipv4, ipv6) => result,
                };
                if let Err(error) = result {
                    if let Some(output) = output.take() {
                        let _ = output.send(Err(error));
                        return;
                    }
                    tracing::error!(?error, "failed to create native interface");
                    tokio::select! {
                        _ = cancel.cancelled() => return,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                    continue;
                }

                let ifname = nic.ifname().await.unwrap_or_default();
                let default_route_guard = activate_default_route(
                    &global_ctx, &ifname, &packet_plane, &cancel,
                ).await;

                let magic_dns = if let Some(ip) = ipv4 {
                    MagicDnsRuntime::start(
                        global_ctx.clone(),
                        packet_plane.clone(),
                        Some(ifname),
                        ip,
                    )
                } else {
                    MagicDnsRuntime::default()
                };
                nic_state.install(nic, magic_dns, default_route_guard).await;
                if let Some(output) = output.take() {
                    let _ = output.send(Ok(()));
                }
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = closed.notified() => {}
                }
            }
        });
        self.static_ip_task.lock().await.replace(task);
        first_round
            .await
            .context("static IP setup task stopped")??;
        Ok(())
    }

    pub(super) async fn prepare(&self, packet_plane: Arc<CorePacketPlane>) -> anyhow::Result<()> {
        self.nic.drain().await;
        if !self.global_ctx.config.get_flags().no_tun {
            self.start_static_ip(packet_plane).await?;
        }
        Ok(())
    }

    pub(super) async fn shutdown(&self) {
        if let Some(task) = self.static_ip_task.lock().await.take() {
            let _ = task.await;
        }
        self.nic.stop().await;
    }

    pub(super) fn attach_fd(&self, _fd: i32) -> anyhow::Result<()> {
        anyhow::bail!("external TUN attachment is only supported on mobile Hosts")
    }

    pub(super) fn dhcp_host(
        &self,
        operation: Arc<Mutex<()>>,
        packet_plane: Arc<CorePacketPlane>,
    ) -> Arc<dyn DhcpIpv4Host> {
        Arc::new(NativeDhcpIpv4Host {
            global_ctx: self.global_ctx.clone(),
            operation,
            cancel: self.cancel.clone(),
            nic: self.nic.clone(),
            closed: Arc::new(Notify::new()),
            packet_plane,
        })
    }
}

struct NativeDhcpIpv4Host {
    global_ctx: ArcGlobalCtx,
    operation: Arc<Mutex<()>>,
    cancel: CancellationToken,
    nic: TunNicState,
    closed: Arc<Notify>,
    packet_plane: Arc<CorePacketPlane>,
}

impl NativeDhcpIpv4Host {
    fn ensure_open(&self) -> anyhow::Result<()> {
        if self.cancel.is_cancelled() {
            anyhow::bail!("instance is closing; DHCP update cancelled");
        }
        Ok(())
    }

    async fn apply(&self, next: Option<Ipv4Inet>) -> anyhow::Result<Option<Ipv4Inet>> {
        self.ensure_open()?;
        tokio::select! {
            _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; DHCP update cancelled"),
            _ = self.nic.drain() => {}
        }
        self.ensure_open()?;

        let Some(ip) = next else {
            self.global_ctx.set_ipv4(None);
            return Ok(None);
        };
        if self.global_ctx.no_tun() {
            self.global_ctx.set_ipv4(Some(ip));
            return Ok(Some(ip));
        }

        let mut nic = NicCtx::new(
            self.global_ctx.clone(),
            self.packet_plane.clone(),
            self.nic.receiver(),
            self.closed.clone(),
        );
        tokio::select! {
            _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; DHCP update cancelled"),
            result = nic.run(Some(ip), self.global_ctx.get_ipv6()) => result?,
        }
        let ifname = nic.ifname().await.unwrap_or_default();
        let default_route_guard = activate_default_route(
            &self.global_ctx, &ifname, &self.packet_plane, &self.cancel,
        ).await;
        let magic_dns = MagicDnsRuntime::start(
            self.global_ctx.clone(),
            self.packet_plane.clone(),
            Some(ifname),
            ip,
        );
        self.nic.install(nic, magic_dns, default_route_guard).await;
        self.global_ctx.set_ipv4(Some(ip));
        Ok(Some(ip))
    }
}

#[async_trait::async_trait]
impl DhcpIpv4Host for NativeDhcpIpv4Host {
    fn take_interface_closed(&self) -> bool {
        self.closed.notified().now_or_never().is_some()
    }

    async fn apply_dhcp_ipv4(
        &self,
        _previous: Option<Ipv4Inet>,
        next: Option<Ipv4Inet>,
    ) -> DhcpIpv4ApplyOutcome {
        let permit = self.operation.clone().lock_owned().await;
        let outcome = match self.apply(next).await {
            Ok(actual) => DhcpIpv4ApplyOutcome::applied(actual),
            Err(error) => DhcpIpv4ApplyOutcome::failed(self.global_ctx.get_ipv4(), error),
        };
        outcome.with_permit(DhcpIpv4ApplyPermit::new(permit))
    }

    fn publish_dhcp_ipv4(
        &self,
        previous: Option<Ipv4Inet>,
        requested: Option<Ipv4Inet>,
        actual: Option<Ipv4Inet>,
    ) {
        let event = if requested.is_none() {
            GlobalCtxEvent::DhcpIpv4Conflicted(previous)
        } else {
            GlobalCtxEvent::DhcpIpv4Changed(previous, actual)
        };
        self.global_ctx.issue_event(event);
    }
}
