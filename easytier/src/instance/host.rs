use std::{net::IpAddr, sync::Arc};

use easytier_core::{
    connectivity::composite::{ConnectorEnvironment, ConnectorHostAdapter},
    socket::{NetNamespace, SocketContext},
};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    host_runtime::{NativeHostRuntime, native_host_runtime},
};

pub type NativeInstanceHost = ConnectorHostAdapter<NativeHostRuntime, NativeInstanceEnvironment>;

/// Instance facts queried by portable connector policy.
///
/// This Adapter never creates or operates sockets. Mechanical network I/O is
/// owned by the process-wide [`NativeHostRuntime`] composed beside it.
pub struct NativeInstanceEnvironment {
    global_ctx: ArcGlobalCtx,
    runtime: Arc<NativeHostRuntime>,
    socket_context: SocketContext,
}

impl NativeInstanceEnvironment {
    fn new(global_ctx: ArcGlobalCtx, runtime: Arc<NativeHostRuntime>) -> Self {
        // SO_MARK is driven solely by `default_route` (fixed internal mark, not
        // user-configurable). This must agree with the `ip rule not fwmark <MARK>`
        // installed by the route manager, or our own peer/DNS traffic self-routes
        // into the TUN and black-holes. `default_route_socket_mark` is the single
        // source shared with the core-layer socket context and the `ip rule` side.
        let socket_context = SocketContext::default()
            .with_socket_mark(easytier_core::instance::default_route_socket_mark(
                global_ctx.config.get_flags().default_route,
            ))
            .with_netns(global_ctx.net_ns.name().map(NetNamespace::new));
        Self {
            global_ctx,
            runtime,
            socket_context,
        }
    }
}

pub(crate) fn native_instance_host(global_ctx: ArcGlobalCtx) -> Arc<NativeInstanceHost> {
    let runtime = native_host_runtime();
    Arc::new(ConnectorHostAdapter::new(
        runtime.clone(),
        Arc::new(NativeInstanceEnvironment::new(global_ctx, runtime)),
    ))
}

impl ConnectorEnvironment for NativeInstanceEnvironment {
    fn socket_context(&self) -> SocketContext {
        self.socket_context.clone()
    }

    fn mapped_listeners(&self) -> Vec<url::Url> {
        self.global_ctx.config.get_mapped_listeners()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_ip_local_virtual_ip(ip)
            || self.runtime.is_local_ip(ip, &self.socket_context)
    }
}
