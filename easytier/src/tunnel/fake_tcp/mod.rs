mod netfilter;
#[cfg(target_os = "linux")]
mod netfilter_guard;
mod packet;
mod stack;

use bytes::{Bytes, BytesMut};
use futures::{Sink, Stream};
use network_interface::NetworkInterfaceConfig;
use pnet::util::MacAddr;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
};
use tokio::{io::AsyncReadExt, net::{TcpListener, TcpSocket, TcpStream}};

use crate::tunnel::{
    FromUrl, IpVersion, SinkError, SinkItem, StreamItem, Tunnel, TunnelConnector, TunnelError,
    TunnelInfo, TunnelListener,
    common::{TunnelWrapper, bind},
    fake_tcp::netfilter::create_tun,
    packet_def::{PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType},
};

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
        if let Some(ifname) = self.ip_to_ifname.get(ip) {
            Some(ifname.clone())
        } else {
            self.reload_ip_to_ifname();
            self.ip_to_ifname.get(ip).map(|s| s.clone())
        }
    }
}

fn get_faketcp_tunnel_type_str(_driver_type: &str) -> String {
    "faketcp".to_owned()
}

async fn create_tun_off_runtime(
    interface_name: String,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> Result<Arc<dyn stack::Tun>, TunnelError> {
    tokio::task::spawn_blocking(move || create_tun(&interface_name, src_addr, dst_addr))
        .await
        .map_err(|e| TunnelError::InternalError(format!("faketcp create_tun task failed: {e}")))?
        .map_err(Into::into)
}

pub struct FakeTcpTunnelListener {
    addr: url::Url,
    os_listener: Option<TcpListener>,
    // interface_name -> fake tcp stack
    stack_map: DashMap<String, Arc<stack::Stack>>,
    // a cache from ip addr to interface name
    ip_to_ifname: IpToIfNameCache,
    socket_mark: Option<u32>,
}

impl FakeTcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        FakeTcpTunnelListener {
            addr,
            os_listener: None,
            stack_map: DashMap::new(),
            ip_to_ifname: IpToIfNameCache::new(),
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
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

        let (local_ip, local_ip6) = match local_socket_addr.ip() {
            IpAddr::V4(ip) => (Some(ip), None),
            IpAddr::V6(ip) => (None, Some(ip)),
        };

        if let Some(entry) = self.stack_map.get(interface_name) {
            let stack = entry.clone();
            drop(entry);

            if !stack.is_closed() {
                return Ok(stack);
            }

            tracing::warn!(
                interface_name,
                "fake_tcp stack reader_task finished, recreating stack"
            );
            self.stack_map.remove(interface_name);
        }

        let filter_addr = SocketAddr::new(
            if local_socket_addr.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            },
            local_socket_addr.port(),
        );
        let tun = create_tun_off_runtime(interface_name.to_string(), None, filter_addr).await?;
        tracing::info!(
            ?local_socket_addr,
            "create new stack with interface_name: {:?}",
            interface_name
        );
        let stack = Arc::new(stack::Stack::new(
            tun,
            local_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            local_ip6,
            accept_result.mac,
        ));
        self.stack_map
            .insert(interface_name.to_string(), stack.clone());

        Ok(stack)
    }
}

fn build_os_socket_reader_task(mut socket: TcpStream) -> AbortOnDropHandle<()> {
    let sock_ref = socket2::SockRef::from(&socket);
    let _ = sock_ref.set_recv_buffer_size(1024);
    let _ = sock_ref.set_send_buffer_size(1024);
    let _ = sock_ref.set_nodelay(true);
    let _ = sock_ref.set_keepalive(false);

    #[cfg(target_os = "linux")]
    {
        use nix::libc;
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
        let repair: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                19, // TCP_REPAIR
                &repair as *const _ as *const libc::c_void,
                std::mem::size_of_val(&repair) as libc::socklen_t,
            )
        };
        if ret != 0 {
            tracing::warn!(
                errno = std::io::Error::last_os_error().raw_os_error(),
                "faketcp: TCP_REPAIR setsockopt failed, kernel may send RST"
            );
            let timeout_ms: libc::c_int = 0;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    18, // TCP_USER_TIMEOUT
                    &timeout_ms as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&timeout_ms) as libc::socklen_t,
                );
            }
        } else {
            tracing::debug!("faketcp: TCP_REPAIR set successfully");
        }
    }

    AbortOnDropHandle::new(tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match socket.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        tracing::info!("FakeTcpTunnelListener os socket closed");
    }))
}

#[cfg(target_os = "linux")]
fn get_tcp_seq_ack(socket: &TcpStream) -> (u32, u32) {
    use nix::libc;
    use std::os::unix::io::AsRawFd;

    let fd = socket.as_raw_fd();

    // Enter TCP_REPAIR mode to freeze the kernel TCP state machine
    let repair: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            19, // TCP_REPAIR
            &repair as *const _ as *const libc::c_void,
            std::mem::size_of_val(&repair) as libc::socklen_t,
        )
    };
    if ret != 0 {
        tracing::warn!(
            errno = std::io::Error::last_os_error().raw_os_error(),
            "faketcp: TCP_REPAIR failed in get_tcp_seq_ack, using seq=0 ack=0"
        );
        return (0, 0);
    }

    // Get send seq: set queue to SEND (1), then read TCP_QUEUE_SEQ
    let send_queue: libc::c_int = 1; // TCP_SEND_QUEUE
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            20, // TCP_REPAIR_QUEUE
            &send_queue as *const _ as *const libc::c_void,
            std::mem::size_of_val(&send_queue) as libc::socklen_t,
        );
    }
    let mut seq: u32 = 0;
    let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            21, // TCP_QUEUE_SEQ
            &mut seq as *mut _ as *mut libc::c_void,
            &mut len,
        );
    }

    // Get recv ack: set queue to RECV (0), then read TCP_QUEUE_SEQ
    let recv_queue: libc::c_int = 0; // TCP_RECV_QUEUE
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            20, // TCP_REPAIR_QUEUE
            &recv_queue as *const _ as *const libc::c_void,
            std::mem::size_of_val(&recv_queue) as libc::socklen_t,
        );
    }
    let mut ack: u32 = 0;
    len = std::mem::size_of::<u32>() as libc::socklen_t;
    unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            21, // TCP_QUEUE_SEQ
            &mut ack as *mut _ as *mut libc::c_void,
            &mut len,
        );
    }

    tracing::debug!(seq, ack, "faketcp: got TCP seq/ack via TCP_REPAIR");
    (seq, ack)
}

#[cfg(not(target_os = "linux"))]
fn get_tcp_seq_ack(_socket: &TcpStream) -> (u32, u32) {
    (0, 0)
}

#[derive(Debug)]
struct AcceptResult {
    socket: TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    interface_name: String,
    mac: Option<MacAddr>,
}

#[async_trait::async_trait]
impl TunnelListener for FakeTcpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        self.os_listener = None;
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let os_listener = bind::<TcpListener>()
            .addr(addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;
        let port = os_listener.local_addr()?.port();
        self.addr.set_port(Some(port)).unwrap();
        tracing::info!(port, "FakeTcpTunnelListener listening");
        self.os_listener = Some(os_listener);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        tracing::debug!("FakeTcpTunnelListener waiting for accept");
        #[cfg(target_os = "linux")]
        let mut nft_guard;

        let (res, stack, socket) = loop {
            let res = self.do_accept().await?;
            let (seq, ack) = get_tcp_seq_ack(&res.socket);

            #[cfg(target_os = "linux")]
            {
                nft_guard = Some(netfilter_guard::NftGuard::new(
                    res.local_addr,
                    res.remote_addr,
                ));
            }

            let stack = self.get_stack(&res).await?;
            let socket = stack.try_alloc_established_socket(
                res.local_addr,
                res.remote_addr,
                seq,
                ack,
                stack::State::Established,
            );
            let Some(socket) = socket else {
                tracing::warn!(
                    interface_name = res.interface_name,
                    "fake_tcp stack closed while accepting connection, dropping accepted socket"
                );
                self.stack_map.remove(&res.interface_name);
                continue;
            };
            break (res, stack, socket);
        };

        tracing::info!(
            ?res,
            remote = socket.remote_addr().to_string(),
            "FakeTcpTunnelListener accepted connection"
        );

        let info = TunnelInfo {
            tunnel_type: get_faketcp_tunnel_type_str(stack.driver_type()),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.remote_addr().to_string(),
                    "faketcp",
                )
                .into(),
            ),
            resolved_remote_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.remote_addr().to_string(),
                    "faketcp",
                )
                .into(),
            ),
        };

        let socket = Arc::new(socket);
        let reader = FakeTcpStream::new(socket.clone());
        let writer = FakeTcpSink::new(socket);

        #[cfg(target_os = "linux")]
        let associate_data: Box<dyn std::any::Any + Send> = Box::new((
            build_os_socket_reader_task(res.socket),
            nft_guard,
        ));
        #[cfg(not(target_os = "linux"))]
        let associate_data: Box<dyn std::any::Any + Send> =
            Box::new(build_os_socket_reader_task(res.socket));

        Ok(Box::new(TunnelWrapper::new_with_associate_data(
            reader,
            writer,
            Some(info),
            Some(associate_data),
        )))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct FakeTcpTunnelConnector {
    addr: url::Url,
    ip_to_if_name: IpToIfNameCache,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
}

impl FakeTcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        FakeTcpTunnelConnector {
            addr,
            ip_to_if_name: IpToIfNameCache::new(),
            resolved_addr: None,
            socket_mark: None,
        }
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

#[async_trait::async_trait]
impl TunnelConnector for FakeTcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let remote_addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?,
        };
        let local_ip = get_local_ip_for_destination(remote_addr.ip())
            .ok_or(TunnelError::InternalError("Failed to get local ip".into()))?;

        let bind_addr: SocketAddr = if remote_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let os_socket = bind::<TcpSocket>()
            .addr(bind_addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;
        let local_port = os_socket.local_addr()?.port();
        let local_addr = SocketAddr::new(local_ip, local_port);

        let (interface_name, mac) =
            self.ip_to_if_name
                .get_ifname(&local_ip)
                .ok_or(TunnelError::InternalError(
                    "Failed to get interface name".into(),
                ))?;

        let (local_ip, local_ip6) = match local_ip {
            IpAddr::V4(ip) => (Some(ip), None),
            IpAddr::V6(ip) => (None, Some(ip)),
        };

        let tun =
            create_tun_off_runtime(interface_name.clone(), Some(remote_addr), local_addr).await?;
        let local_ip = local_ip.unwrap_or("0.0.0.0".parse().unwrap());
        let stack = stack::Stack::new(tun, local_ip, local_ip6, mac);
        let driver_type = stack.driver_type();

        let socket = stack
            .try_alloc_established_socket(local_addr, remote_addr, 0, 0, stack::State::SynSent)
            .ok_or(TunnelError::InternalError(
                "FakeTCP stack closed while allocating socket".into(),
            ))?;

        let os_stream = os_socket.connect(remote_addr).await?;

        // Set TCP_REPAIR immediately after connect to prevent kernel from
        // interfering with the connection before the userspace stack takes over
        #[cfg(target_os = "linux")]
        {
            use nix::libc;
            use std::os::unix::io::AsRawFd;
            let fd = os_stream.as_raw_fd();
            let repair: libc::c_int = 1;
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    19, // TCP_REPAIR
                    &repair as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&repair) as libc::socklen_t,
                )
            };
            if ret != 0 {
                tracing::warn!(
                    errno = std::io::Error::last_os_error().raw_os_error(),
                    "faketcp connector: TCP_REPAIR failed, kernel may send RST"
                );
            }
        }

        #[cfg(target_os = "linux")]
        let nft_guard = netfilter_guard::NftGuard::new(local_addr, remote_addr);

        tracing::info!(?remote_addr, "FakeTcpTunnelConnector connecting");

        let mut buf = BytesMut::new();
        socket
            .recv(&mut buf)
            .await
            .ok_or(TunnelError::InternalError(
                "Failed to recv bytes to establish connection".into(),
            ))?;

        tracing::info!(local_addr = ?socket.local_addr(), "FakeTcpTunnelConnector connected");

        let info = TunnelInfo {
            tunnel_type: get_faketcp_tunnel_type_str(driver_type),
            local_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.local_addr().to_string(),
                    "faketcp",
                )
                .into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
            resolved_remote_addr: Some(
                crate::tunnel::build_url_from_socket_addr(&remote_addr.to_string(), "faketcp")
                    .into(),
            ),
        };

        let socket = Arc::new(socket);
        let reader = FakeTcpStream::new(socket.clone());
        let writer = FakeTcpSink::new(socket.clone());

        #[cfg(target_os = "linux")]
        let associate_data: Box<dyn std::any::Any + Send> = Box::new((
            build_os_socket_reader_task(os_stream),
            stack,
            nft_guard,
        ));
        #[cfg(not(target_os = "linux"))]
        let associate_data: Box<dyn std::any::Any + Send> =
            Box::new((build_os_socket_reader_task(os_stream), stack));

        Ok(Box::new(TunnelWrapper::new_with_associate_data(
            reader,
            writer,
            Some(info),
            Some(associate_data),
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

type RecvFut = Pin<Box<dyn Future<Output = Option<(BytesMut, usize)>> + Send + Sync>>;

enum FakeTcpStreamState {
    ConsumingBuf(BytesMut),
    PollFuture(RecvFut),
    Closed,
}

struct FakeTcpStream {
    socket: Arc<stack::Socket>,
    state: FakeTcpStreamState,
    _ack_task: AbortOnDropHandle<()>,
}

impl FakeTcpStream {
    fn new(socket: Arc<stack::Socket>) -> Self {
        let ack_socket = socket.clone();
        let ack_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_millis(40));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                ack_socket.send_ack();
            }
        }));
        Self {
            socket,
            state: FakeTcpStreamState::ConsumingBuf(BytesMut::new()),
            _ack_task: ack_task,
        }
    }
}

impl Stream for FakeTcpStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();
        loop {
            let state = std::mem::replace(&mut s.state, FakeTcpStreamState::Closed);
            match state {
                FakeTcpStreamState::ConsumingBuf(buf) => {
                    let buf_len = buf.len();
                    // check peer manager header and split buf out
                    let packet = ZCPacket::new_from_buf(buf, ZCPacketType::TCP);
                    if let Some(tcp_hdr) = packet.tcp_tunnel_header() {
                        let expected_payload_len = tcp_hdr.len.get() as usize;
                        let min_packet_len = TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE;
                        if expected_payload_len < min_packet_len {
                            tracing::warn!(
                                "drop fake tcp packet with invalid length: expected_payload_len={}, min_required={}",
                                expected_payload_len,
                                min_packet_len
                            );
                            s.state = FakeTcpStreamState::Closed;
                            return Poll::Ready(None);
                        }

                        if expected_payload_len <= buf_len {
                            let mut buf = packet.inner();
                            let new_inner = buf.split_to(expected_payload_len);
                            s.state = FakeTcpStreamState::ConsumingBuf(buf);
                            return Poll::Ready(Some(Ok(ZCPacket::new_from_buf(
                                new_inner,
                                ZCPacketType::TCP,
                            ))));
                        }
                    }

                    let mut buf = packet.inner();
                    buf.truncate(0);

                    let socket = s.socket.clone();
                    s.state = FakeTcpStreamState::PollFuture(Box::pin(async move {
                        let ret = socket.recv(&mut buf).await;
                        ret.map(|s| (buf, s))
                    }));
                }
                FakeTcpStreamState::PollFuture(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Some((buf, _sz))) => {
                        s.state = FakeTcpStreamState::ConsumingBuf(buf);
                    }
                    Poll::Ready(None) => {
                        s.state = FakeTcpStreamState::Closed;
                    }
                    Poll::Pending => {
                        s.state = FakeTcpStreamState::PollFuture(fut);
                        return Poll::Pending;
                    }
                },
                FakeTcpStreamState::Closed => {
                    return Poll::Ready(None);
                }
            }
        }
    }
}

const FAKE_TCP_SINK_BATCH_SIZE: usize = 64;

struct FakeTcpSink {
    socket: Arc<stack::Socket>,
    pending: Vec<Bytes>,
}

impl FakeTcpSink {
    fn new(socket: Arc<stack::Socket>) -> Self {
        Self {
            socket,
            pending: Vec::with_capacity(FAKE_TCP_SINK_BATCH_SIZE),
        }
    }

    fn do_flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        self.socket.flush_batch(&self.pending);
        self.pending.clear();
    }
}

impl Sink<SinkItem> for FakeTcpSink {
    type Error = SinkError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        if self.pending.len() >= FAKE_TCP_SINK_BATCH_SIZE {
            self.do_flush();
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        let mut packet = item.convert_type(ZCPacketType::TCP);
        let len = packet.buf_len();
        packet.mut_tcp_tunnel_header().unwrap().len.set(len as u32);
        let data = packet.into_bytes();

        if let Some(built) = self.socket.build_packet(&data) {
            self.pending.push(built);
        }

        Ok(())
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.do_flush();
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.do_flush();
        self.socket.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::common::tests::_tunnel_pingpong;

    use super::*;

    #[tokio::test]
    async fn faketcp_pingpong() {
        #[cfg(target_family = "unix")]
        {
            if unsafe { nix::libc::geteuid() } != 0 {
                return;
            }
        }

        let listener = FakeTcpTunnelListener::new("faketcp://0.0.0.0:31011".parse().unwrap());
        let connector = FakeTcpTunnelConnector::new("faketcp://127.0.0.1:31011".parse().unwrap());

        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn faketcp_pingpong_ipv6() {
        #[cfg(target_family = "unix")]
        {
            if unsafe { nix::libc::geteuid() } != 0 {
                return;
            }
        }

        let listener = FakeTcpTunnelListener::new("faketcp://[::]:31012".parse().unwrap());
        let connector = FakeTcpTunnelConnector::new("faketcp://[::1]:31012".parse().unwrap());

        _tunnel_pingpong(listener, connector).await
    }
}
