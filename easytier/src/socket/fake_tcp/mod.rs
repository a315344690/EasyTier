mod netfilter;
mod packet;
mod stack;

use bytes::{Bytes, BytesMut};
use network_interface::NetworkInterfaceConfig;
use pnet::util::MacAddr;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
};

use easytier_core::{
    socket::tcp::VirtualTcpSocket,
    tunnel::{IpVersion, TunnelError},
};

use crate::{
    common::netns::NetNS,
    tunnel::{
        FromUrl,
        common::{BindDev, bind},
    },
};

use self::netfilter::create_tun;

use futures::Future;
use tokio_util::task::AbortOnDropHandle;

use dashmap::DashMap;

struct IpToIfNameCache {
    ip_to_ifname: DashMap<IpAddr, (String, Option<MacAddr>)>,
}

impl IpToIfNameCache {
    fn new() -> Self {
        Self {
            ip_to_ifname: DashMap::new(),
        }
    }

    fn reload_ip_to_ifname(&self) {
        self.ip_to_ifname.clear();
        let Ok(interfaces) = network_interface::NetworkInterface::show() else {
            tracing::warn!("failed to enumerate interfaces when reloading faketcp ip cache");
            return;
        };
        for iface in interfaces {
            let mac = iface.mac_addr.as_deref().and_then(|mac| {
                mac.parse::<MacAddr>().map_err(|e| {
                    tracing::debug!(iface = %iface.name, mac, ?e, "failed to parse interface mac")
                }).ok()
            });
            for ip in iface.addr.iter() {
                self.ip_to_ifname.insert(ip.ip(), (iface.name.clone(), mac));
            }
        }
    }

    fn get_ifname(&self, ip: &IpAddr) -> Option<(String, Option<MacAddr>)> {
        // interfaces are cached in their native family, so unwrap ::ffff: forms
        let ip = &ip.to_canonical();
        if let Some(ifname) = self.ip_to_ifname.get(ip) {
            Some(ifname.clone())
        } else {
            self.reload_ip_to_ifname();
            self.ip_to_ifname.get(ip).map(|s| s.clone())
        }
    }
}

fn faketcp_transport_label(driver_type: &str) -> String {
    format!("faketcp_{}", driver_type)
}

async fn create_tun_off_runtime(
    interface_name: String,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
    net_ns: NetNS,
) -> Result<Arc<dyn stack::Tun>, TunnelError> {
    tokio::task::spawn_blocking(move || {
        net_ns.run(|| create_tun(&interface_name, src_addr, dst_addr))
    })
    .await
    .map_err(|e| TunnelError::InternalError(format!("faketcp create_tun task failed: {e}")))?
    .map_err(Into::into)
}

pub(crate) struct FakeTcpSocketListener {
    addr: url::Url,
    os_listener: Option<tokio::net::TcpListener>,
    // (interface_name, local_addr) -> fake tcp stack.
    // local_addr is part of the key because the stack's packet filter is pinned
    // to it, so a dual-stack interface needs one stack per address family.
    stack_map: DashMap<(String, SocketAddr), Arc<stack::Stack>>,
    // a cache from ip addr to interface name
    ip_to_ifname: IpToIfNameCache,
}

impl std::fmt::Debug for FakeTcpSocketListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FakeTcpSocketListener")
            .field("addr", &self.addr)
            .field("listening", &self.os_listener.is_some())
            .finish()
    }
}

impl FakeTcpSocketListener {
    pub(crate) fn new(addr: url::Url) -> Self {
        FakeTcpSocketListener {
            addr,
            os_listener: None,
            stack_map: DashMap::new(),
            ip_to_ifname: IpToIfNameCache::new(),
        }
    }

    async fn do_accept(&mut self) -> Result<AcceptResult, TunnelError> {
        loop {
            match self.os_listener.as_mut().unwrap().accept().await {
                Ok((s, remote_addr)) => {
                    let Ok(local_addr) = s.local_addr() else {
                        tracing::warn!("accept fail with local_addr error");
                        continue;
                    };
                    let Some((interface_name, mac)) =
                        self.ip_to_ifname.get_ifname(&local_addr.ip())
                    else {
                        tracing::warn!("accept fail with interface_name error");
                        continue;
                    };
                    return Ok(AcceptResult {
                        socket: s,
                        local_addr,
                        remote_addr,
                        interface_name,
                        mac,
                    });
                }
                Err(e) => {
                    use std::io::ErrorKind::*;
                    if matches!(
                        e.kind(),
                        NotConnected | ConnectionAborted | ConnectionRefused | ConnectionReset
                    ) {
                        tracing::warn!(?e, "accept fail with retryable error: {:?}", e);
                        continue;
                    }
                    tracing::warn!(?e, "accept fail");
                    return Err(e.into());
                }
            }
        }
    }

    async fn get_stack(
        &self,
        accept_result: &AcceptResult,
    ) -> Result<Arc<stack::Stack>, TunnelError> {
        let local_socket_addr = accept_result.local_addr;

        let interface_name = &accept_result.interface_name;
        let key = accept_result.stack_key();

        if let Some(entry) = self.stack_map.get(&key) {
            let stack = entry.clone();
            drop(entry);

            if !stack.is_closed() {
                return Ok(stack);
            }

            tracing::warn!(
                interface_name,
                ?local_socket_addr,
                "fake_tcp stack reader_task finished, recreating stack"
            );
            self.stack_map.remove(&key);
        }

        let tun = create_tun_off_runtime(
            interface_name.to_string(),
            None,
            local_socket_addr,
            NetNS::new(None),
        )
        .await?;
        tracing::info!(
            ?local_socket_addr,
            "create new stack with interface_name: {:?}",
            interface_name
        );
        // drop stacks of retired local addrs (e.g. rotated IPv6 privacy addrs),
        // which are otherwise only evicted when their own key is looked up again
        self.stack_map.retain(|_, stack| !stack.is_closed());

        let stack = Arc::new(stack::Stack::new(tun, accept_result.mac));
        self.stack_map.insert(key, stack.clone());

        Ok(stack)
    }
}

/// State copied out of the kernel socket that completed the real handshake.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct KernelTcpState {
    /// The kernel's send sequence, i.e. where our crafted segments must start.
    pub seq: u32,
    /// The kernel's receive sequence. Nothing has arrived since the handshake,
    /// so this is the peer's ISN+1 -- exactly what our segments must acknowledge.
    pub ack: u32,
    /// Added to our TSval so it lines up with the kernel's TCP timestamp clock,
    /// which carries a random per-destination offset when `tcp_timestamps=1`.
    pub ts_offset: u32,
}

/// Freezes the kernel socket that performed the handshake and reads its sequence
/// state, so our crafted segments continue exactly where the kernel left off.
///
/// `TCP_REPAIR` does double duty: besides exposing the sequence numbers, it stops
/// the kernel from emitting anything further on this 4-tuple -- no ACKs, no window
/// updates, and no FIN or RST when the socket is closed. Those would otherwise
/// collide with our own segments, since we and the kernel disagree about how far
/// the sequence space has advanced. The socket is deliberately *left* in repair
/// mode for the rest of its life.
///
/// Needs `CAP_NET_ADMIN`. On failure the caller aborts the connection: TCP_REPAIR
/// is FakeTCP's only kernel-quieting mechanism, so there is no safe way to run
/// without it.
fn freeze_kernel_socket(socket: &TcpStream) -> io::Result<KernelTcpState> {
    use nix::libc;
    use std::os::unix::io::AsRawFd;

    // Not in libc: see include/uapi/linux/tcp.h.
    const TCP_REPAIR: libc::c_int = 19;
    const TCP_REPAIR_QUEUE: libc::c_int = 20;
    const TCP_QUEUE_SEQ: libc::c_int = 21;
    const TCP_TIMESTAMP: libc::c_int = 24;
    const TCP_RECV_QUEUE: libc::c_int = 1;
    const TCP_SEND_QUEUE: libc::c_int = 2;

    let fd = socket.as_raw_fd();

    fn set_int(fd: i32, opt: libc::c_int, value: libc::c_int) -> io::Result<()> {
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                opt,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn get_u32(fd: i32, opt: libc::c_int) -> io::Result<u32> {
        let mut value: u32 = 0;
        let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_TCP,
                opt,
                &mut value as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(value)
    }

    set_int(fd, TCP_REPAIR, 1).map_err(|e| {
        tracing::warn!(
            errno = e.raw_os_error(),
            "faketcp: TCP_REPAIR failed, kernel will keep talking on this tuple"
        );
        e
    })?;

    // Any failure past this point leaves the socket frozen but us without usable
    // numbers, so hand it back to the kernel rather than stranding it.
    let read_state = || -> io::Result<(u32, u32)> {
        set_int(fd, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)?;
        let seq = get_u32(fd, TCP_QUEUE_SEQ)?;
        set_int(fd, TCP_REPAIR_QUEUE, TCP_RECV_QUEUE)?;
        let ack = get_u32(fd, TCP_QUEUE_SEQ)?;
        Ok((seq, ack))
    };
    let (seq, ack) = match read_state() {
        Ok(v) => v,
        Err(e) => {
            let _ = set_int(fd, TCP_REPAIR, 0);
            tracing::warn!(errno = e.raw_os_error(), "faketcp: reading repair queues failed");
            return Err(e);
        }
    };

    // `tcp_timestamps=1` (the default) adds a random per-destination offset to
    // every TSval. Recover it so our segments and the kernel's handshake segments
    // present one continuous timestamp clock to any middlebox doing PAWS checks.
    let ts_offset = match get_u32(fd, TCP_TIMESTAMP) {
        Ok(kernel_ts) => {
            kernel_ts.wrapping_sub(stack::ts_base().elapsed().as_millis() as u32)
        }
        Err(e) => {
            tracing::warn!(
                errno = e.raw_os_error(),
                "faketcp: TCP_TIMESTAMP failed, timestamps will not match the kernel's"
            );
            0
        }
    };

    tracing::debug!(seq, ack, ts_offset, "faketcp: froze kernel socket");
    Ok(KernelTcpState {
        seq,
        ack,
        ts_offset,
    })
}

fn build_os_socket_reader_task(mut socket: TcpStream) -> AbortOnDropHandle<()> {
    // The decoy socket exists only to hold the 4-tuple; no payload ever flows
    // through it, so keep its buffers minimal, and keep the kernel from probing a
    // peer that will never answer at the kernel's sequence numbers.
    let sock_ref = socket2::SockRef::from(&socket);
    let _ = sock_ref.set_recv_buffer_size(1024);
    let _ = sock_ref.set_send_buffer_size(1024);
    let _ = sock_ref.set_nodelay(true);
    let _ = sock_ref.set_keepalive(false);

    AbortOnDropHandle::new(tokio::spawn(async move {
        // read the os socket until it's closed
        let mut buf = [0u8; 1024];
        while let Ok(size) = socket.read(&mut buf).await {
            tracing::trace!("read {} bytes from os socket", size);
            if size == 0 {
                break;
            }
        }
        tracing::info!("FakeTcpSocketListener os socket closed");
    }))
}

type FakeTcpReadFuture = Pin<Box<dyn Future<Output = Option<Bytes>> + Send + Sync + 'static>>;

enum FakeTcpReadState {
    // A zero-copy view into a received frame, consumed from the front as the
    // caller reads. Holding `Bytes` rather than `BytesMut` is what lets
    // `recv_payload` hand us the payload without an intermediate copy.
    Buffered(Bytes),
    Receiving(FakeTcpReadFuture),
    Closed,
}

const MAX_COALESCED_PAYLOAD: usize = 1348;
const BATCH_SIZE: usize = 64;

pub(crate) struct FakeTcpSocket {
    socket: Arc<stack::Socket>,
    read_state: FakeTcpReadState,
    transport_label: String,
    raw_pending: BytesMut,
    pending_frames: Vec<Bytes>,
    _ack_task: tokio_util::task::AbortOnDropHandle<()>,
    _lifetime_guard: Box<dyn Send + Sync>,
}

impl FakeTcpSocket {
    fn new<T>(socket: stack::Socket, transport_label: String, lifetime_guard: T) -> Self
    where
        T: Send + Sync + 'static,
    {
        let socket = Arc::new(socket);
        let ack_socket = socket.clone();
        let notify = socket.ack_notify().clone();
        let ack_task = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            ack_socket.send_ack();

            let mut idle_deadline =
                tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                tokio::select! {
                    _ = notify.notified() => {
                        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
                        ack_socket.send_ack();
                        idle_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                    }
                    _ = tokio::time::sleep_until(idle_deadline) => {
                        ack_socket.send_ack();
                        idle_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
                    }
                }
            }
        }));
        Self {
            socket,
            read_state: FakeTcpReadState::Buffered(Bytes::new()),
            transport_label,
            raw_pending: BytesMut::new(),
            pending_frames: Vec::new(),
            _ack_task: ack_task,
            _lifetime_guard: Box::new(lifetime_guard),
        }
    }

    fn seal_current_frame(&mut self) {
        if self.raw_pending.is_empty() {
            return;
        }
        let data = self.raw_pending.split().freeze();
        if let Some(frame) = self.socket.build_packet(&data) {
            self.pending_frames.push(frame);
        } else {
            self.raw_pending = BytesMut::from(data.as_ref());
        }
    }

    fn do_flush(&mut self) {
        if self.pending_frames.is_empty() {
            return;
        }
        let sent = self.socket.flush_batch(&self.pending_frames);
        if sent >= self.pending_frames.len() {
            self.pending_frames.clear();
        } else if sent > 0 {
            self.pending_frames.drain(..sent);
        }
    }
}

impl AsyncRead for FakeTcpSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            let state = std::mem::replace(&mut this.read_state, FakeTcpReadState::Closed);
            match state {
                FakeTcpReadState::Buffered(mut buffer) if !buffer.is_empty() => {
                    let length = buffer.len().min(output.remaining());
                    output.put_slice(&buffer.split_to(length));
                    this.read_state = FakeTcpReadState::Buffered(buffer);
                    return Poll::Ready(Ok(()));
                }
                FakeTcpReadState::Buffered(_) => {
                    let socket = this.socket.clone();
                    this.read_state = FakeTcpReadState::Receiving(Box::pin(async move {
                        socket.recv_payload().await
                    }));
                }
                FakeTcpReadState::Receiving(mut receive) => match receive.as_mut().poll(context) {
                    Poll::Ready(Some(buffer)) => {
                        this.read_state = FakeTcpReadState::Buffered(buffer);
                    }
                    Poll::Ready(None) => {
                        this.read_state = FakeTcpReadState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => {
                        this.read_state = FakeTcpReadState::Receiving(receive);
                        return Poll::Pending;
                    }
                },
                FakeTcpReadState::Closed => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for FakeTcpSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.raw_pending.len() + buffer.len() > MAX_COALESCED_PAYLOAD {
            this.seal_current_frame();
        }
        if this.pending_frames.len() >= BATCH_SIZE {
            this.do_flush();
        }
        this.raw_pending.extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.seal_current_frame();
        this.do_flush();
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.seal_current_frame();
        this.do_flush();
        this.socket.close();
        Poll::Ready(Ok(()))
    }
}

impl VirtualTcpSocket for FakeTcpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.socket.local_addr())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.socket.remote_addr())
    }

    fn transport_label(&self) -> Option<&str> {
        Some(&self.transport_label)
    }
}

#[derive(Debug)]
struct AcceptResult {
    socket: TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    interface_name: String,
    mac: Option<MacAddr>,
}

impl AcceptResult {
    fn stack_key(&self) -> (String, SocketAddr) {
        (self.interface_name.clone(), self.local_addr)
    }
}

impl FakeTcpSocketListener {
    pub(crate) async fn accept_socket(&mut self) -> Result<FakeTcpSocket, TunnelError> {
        tracing::debug!("FakeTcpSocketListener waiting for accept");
        let (res, stack, socket) = loop {
            let res = self.do_accept().await?;
            // Freeze the decoy kernel socket with TCP_REPAIR: this silences the
            // kernel on the 4-tuple (no ACK/window/FIN/RST to collide with our
            // crafted segments) and yields its authoritative sequence numbers.
            // It is the sole quieting mechanism, so a failure is fatal rather than
            // degraded -- returning `Err` surfaces the missing capability
            // immediately instead of silently rejecting every future peer.
            let kernel_state = freeze_kernel_socket(&res.socket).map_err(|e| {
                TunnelError::InternalError(format!(
                    "faketcp: TCP_REPAIR unavailable ({e}); needs CAP_NET_ADMIN"
                ))
            })?;
            let stack = self.get_stack(&res).await?;
            let socket = stack.try_alloc_established_socket(
                res.local_addr,
                res.remote_addr,
                stack::State::Established,
                Some(kernel_state),
            );
            let Some(socket) = socket else {
                tracing::warn!(
                    interface_name = res.interface_name,
                    local_addr = ?res.local_addr,
                    "fake_tcp stack closed while accepting connection, dropping accepted socket"
                );
                self.stack_map.remove(&res.stack_key());
                continue;
            };
            break (res, stack, socket);
        };

        tracing::info!(
            ?res,
            remote = socket.remote_addr().to_string(),
            driver = stack.driver_type(),
            "FakeTcpSocketListener accepted connection"
        );

        let transport_label = faketcp_transport_label(stack.driver_type());
        Ok(FakeTcpSocket::new(
            socket,
            transport_label,
            (build_os_socket_reader_task(res.socket), stack),
        ))
    }

    async fn listen_socket(&mut self) -> Result<(), TunnelError> {
        let port = self.addr.port().unwrap_or(0);
        let bind_addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        // must bind V6ONLY: a `[::]` shadow listener shares the port with the
        // `0.0.0.0` one, and tokio's TcpListener::bind never sets IPV6_V6ONLY
        let os_listener = bind::<tokio::net::TcpListener>()
            .addr(bind_addr)
            .dev(BindDev::Disabled)
            .only_v6(bind_addr.is_ipv6())
            .call()?;
        // bind() only warns on ipv6 bind failure, and listen() then auto-binds an
        // ephemeral port, so verify we really own the requested address
        let bound_addr = os_listener.local_addr().map_err(|e| {
            TunnelError::InternalError(format!("faketcp listener has no local address: {e}"))
        })?;
        if bound_addr.ip() != bind_addr.ip() || (port != 0 && bound_addr.port() != port) {
            return Err(TunnelError::InternalError(format!(
                "faketcp listener bound to {bound_addr} instead of {bind_addr}"
            )));
        }
        tracing::info!(?bound_addr, "FakeTcpSocketListener listening");
        self.os_listener = Some(os_listener);
        Ok(())
    }
}

#[async_trait::async_trait]
impl easytier_core::socket::SocketListener for FakeTcpSocketListener {
    type Accepted = FakeTcpSocket;

    async fn listen(&mut self) -> anyhow::Result<()> {
        Ok(self.listen_socket().await?)
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.accept_socket().await?)
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

fn get_local_ip_for_destination(destination: IpAddr) -> Option<IpAddr> {
    // 使用一个不可路由的、私有的、或回环地址创建一个临时的 socket，让内核自动选择源接口。
    // 对于 IPv4，使用 0.0.0.0; 对于 IPv6，使用 ::
    let bind_addr = if destination.is_ipv4() {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
    };

    // 绑定到一个临时端口 (0)
    let socket = UdpSocket::bind((bind_addr, 0)).ok()?;

    // 尝试连接到目标地址。这不会真正发送数据包，只是让内核确定路由。
    socket.connect((destination, 80)).ok()?; // 使用一个常见的端口，例如 80

    // 获取 socket 的本地地址信息
    socket.local_addr().map(|addr| addr.ip()).ok()
}

async fn connect_socket_with_cache(
    remote_addr: SocketAddr,
    socket_mark: Option<u32>,
    ip_to_if_name: &IpToIfNameCache,
    net_ns: NetNS,
) -> Result<FakeTcpSocket, TunnelError> {
    let (local_addr, interface_name, mac, os_socket) = net_ns.run(|| {
        let local_ip = get_local_ip_for_destination(remote_addr.ip())
            .ok_or(TunnelError::InternalError("Failed to get local ip".into()))?;

        let os_socket = if remote_addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        // SO_MARK applies only to the kernel-visible "decoy" socket below.
        // The actual FakeTCP payload travels via crafted segments written
        // straight to the TUN device, which the kernel doesn't tag with
        // SO_MARK. Operators relying on fwmark for FakeTCP must mark the
        // TUN device's traffic with a separate nftables/iptables rule.
        crate::tunnel::common::apply_socket_mark(&socket2::SockRef::from(&os_socket), socket_mark)?;
        let bind_addr: SocketAddr = if remote_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        os_socket.bind(bind_addr)?;
        let local_addr = SocketAddr::new(local_ip, os_socket.local_addr()?.port());

        let (interface_name, mac) =
            ip_to_if_name
                .get_ifname(&local_ip)
                .ok_or(TunnelError::InternalError(
                    "Failed to get interface name".into(),
                ))?;
        Ok::<_, TunnelError>((local_addr, interface_name, mac, os_socket))
    })?;

    let tun = create_tun_off_runtime(interface_name, Some(remote_addr), local_addr, net_ns).await?;
    let stack = stack::Stack::new(tun, mac);
    let transport_label = faketcp_transport_label(stack.driver_type());

    // Registered before `connect()` so the reader task has somewhere to dispatch
    // the SYN-ACK the kernel is about to receive.
    let socket = stack
        .try_alloc_established_socket(local_addr, remote_addr, stack::State::SynSent, None)
        .ok_or(TunnelError::InternalError(
            "FakeTCP stack closed while allocating socket".into(),
        ))?;

    let os_stream = os_socket.connect(remote_addr).await?;

    tracing::info!(
        ?remote_addr,
        driver = stack.driver_type(),
        "FakeTCP socket connecting"
    );

    let mut buf = BytesMut::new();
    socket
        .recv(&mut buf)
        .await
        .ok_or(TunnelError::InternalError(
            "Failed to recv bytes to establish connection".into(),
        ))?;

    // Only now that the handshake is done are the kernel's sequence numbers final,
    // so the freeze happens here rather than at allocation time. It replaces the
    // SYN-ACK-derived numbers with the kernel's authoritative ones and, more
    // importantly, silences the kernel for good. It is the sole quieting mechanism,
    // so a failure is fatal rather than degraded.
    let kernel_state = freeze_kernel_socket(&os_stream).map_err(|e| {
        TunnelError::InternalError(format!(
            "faketcp: TCP_REPAIR unavailable ({e}); needs CAP_NET_ADMIN"
        ))
    })?;
    socket.adopt_kernel_state(kernel_state);

    tracing::info!(local_addr = ?socket.local_addr(), "FakeTCP socket connected");

    Ok(FakeTcpSocket::new(
        socket,
        transport_label,
        (build_os_socket_reader_task(os_stream), stack),
    ))
}

pub(crate) async fn connect_socket(
    remote_addr: SocketAddr,
    socket_mark: Option<u32>,
    net_ns: NetNS,
) -> Result<FakeTcpSocket, TunnelError> {
    connect_socket_with_cache(remote_addr, socket_mark, &IpToIfNameCache::new(), net_ns).await
}

#[cfg(test)]
mod tests {
    use easytier_core::socket::SocketListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// Needs raw packet capture, so it is `#[ignore]`d rather than silently
    /// returning when run unprivileged -- a test that reports success without
    /// having exercised anything is worse than one that is visibly skipped.
    /// Run with `sudo -E cargo test --features faketcp -- --ignored`.
    #[tokio::test]
    #[ignore = "requires root for raw packet capture"]
    async fn faketcp_socket_pingpong() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            #[cfg(target_family = "unix")]
            {
                if unsafe { nix::libc::geteuid() } != 0 {
                    eprintln!("faketcp_socket_pingpong: skipped (not root)");
                    return;
                }
            }

            let mut listener =
                FakeTcpSocketListener::new("faketcp://0.0.0.0:31011".parse().unwrap());
            listener.listen().await.unwrap();
            let (server_ready_tx, server_ready_rx) = tokio::sync::oneshot::channel();

            let server = tokio::spawn(async move {
                let mut socket = listener.accept().await.unwrap();
                server_ready_tx.send(()).unwrap();
                let mut request = [0; 4];
                socket.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"ping");
                socket.write_all(b"pong").await.unwrap();
            });

            let mut socket =
                connect_socket("127.0.0.1:31011".parse().unwrap(), None, NetNS::new(None))
                    .await
                    .unwrap();
            server_ready_rx.await.unwrap();
            socket.write_all(b"ping").await.unwrap();
            let mut response = [0; 4];
            socket.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"pong");

            server.await.unwrap();
        })
        .await
        .expect("FakeTCP socket ping-pong timed out");
    }
}
