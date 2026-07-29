use std::{num::NonZeroUsize, sync::Arc, sync::atomic::AtomicUsize, time::Duration};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        protocol::{
            ClientProtocolUpgrader, ServerProtocolAdmission, ServerProtocolUpgrade,
            ServerProtocolUpgrader,
        },
        transport::ConnectedTransport,
    },
    socket::udp::UdpSession,
    tunnel::Tunnel,
};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    socket::tcp::RuntimeTcpSocket,
    tunnel::fakehttp::{
        CONNECT_TIMEOUT, FakeHttpPayload, HANDSHAKE_TIMEOUT, upgrade_accepted, upgrade_connected,
    },
};

use super::{ClientAdapter, ServerAdapter};

struct FakeHttpAdapter;

impl FakeHttpAdapter {
    fn new(_global_ctx: &ArcGlobalCtx) -> Self {
        Self
    }

    fn is_scheme_supported(&self, scheme: &str) -> bool {
        scheme == "fakehttp"
    }

    fn payload_for_url(url: &url::Url) -> FakeHttpPayload {
        let host = url.host_str().unwrap_or("").to_string();
        if url.port().unwrap_or(80) == 443 {
            FakeHttpPayload::Https { host }
        } else {
            FakeHttpPayload::Http { host }
        }
    }
}

pub(super) fn client_adapter(global_ctx: &ArcGlobalCtx) -> ClientAdapter {
    Arc::new(FakeHttpAdapter::new(global_ctx))
}

pub(super) fn server_adapter(global_ctx: &ArcGlobalCtx) -> ServerAdapter {
    Arc::new(FakeHttpAdapter::new(global_ctx))
}


#[async_trait]
impl ClientProtocolUpgrader<RuntimeTcpSocket> for FakeHttpAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        self.is_scheme_supported(scheme)
    }

    fn connect_timeout(&self, scheme: &str) -> Option<Duration> {
        self.is_scheme_supported(scheme).then_some(CONNECT_TIMEOUT)
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<RuntimeTcpSocket>,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let ConnectedTransport::Tcp(socket) = connected else {
            anyhow::bail!("FakeHTTP protocol requires a TCP transport");
        };
        let payload = Self::payload_for_url(&requested_url);
        let counter = AtomicUsize::new(0);
        Ok(tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            upgrade_connected(socket, requested_url, std::slice::from_ref(&payload), &counter),
        )
        .await
        .map_err(|_| anyhow::anyhow!("fakehttp client handshake timed out"))??)
    }
}

#[async_trait]
impl ServerProtocolUpgrader<RuntimeTcpSocket> for FakeHttpAdapter {
    fn supports_scheme(&self, scheme: &str) -> bool {
        self.is_scheme_supported(scheme)
    }

    fn max_pending_tcp_upgrades(&self, scheme: &str) -> Option<NonZeroUsize> {
        self.is_scheme_supported(scheme).then_some(NonZeroUsize::MIN)
    }

    async fn upgrade_tcp(
        &self,
        socket: RuntimeTcpSocket,
        local_url: url::Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        Ok(ServerProtocolUpgrade::Tunnel(
            tokio::time::timeout(HANDSHAKE_TIMEOUT, upgrade_accepted(socket, local_url)).await??,
        ))
    }

    async fn upgrade_udp(
        &self,
        _session: UdpSession,
        _local_url: url::Url,
        _admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("FakeHTTP protocol requires a TCP transport")
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: RuntimeTcpSocket,
        _local_url: url::Url,
        _remote_url: Option<url::Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        anyhow::bail!("FakeHTTP protocol requires a TCP transport")
    }
}
