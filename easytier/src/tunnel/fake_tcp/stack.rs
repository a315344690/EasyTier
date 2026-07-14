//! A minimum, userspace TCP based datagram stack
//!
//! # Overview
//!
//! `fake-tcp` is a reusable library that implements a minimum TCP stack in
//! user space using the Tun interface. It allows programs to send datagrams
//! as if they are part of a TCP connection. `fake-tcp` has been tested to
//! be able to pass through a variety of NAT and stateful firewalls while
//! fully preserves certain desirable behavior such as out of order delivery
//! and no congestion/flow controls.
//!
//! # Core Concepts
//!
//! The core of the `fake-tcp` crate compose of two structures. [`Stack`] and
//! [`Socket`].
//!
//! ## [`Stack`]
//!
//! [`Stack`] represents a virtual TCP stack that operates at
//! Layer 3. It is responsible for:
//!
//! * TCP active and passive open and handshake
//! * `RST` handling
//! * Interact with the Tun interface at Layer 3
//! * Distribute incoming datagrams to corresponding [`Socket`]
//!
//! ## [`Socket`]
//!
//! [`Socket`] represents a TCP connection. It registers the identifying
//! tuple `(src_ip, src_port, dest_ip, dest_port)` inside the [`Stack`] so
//! so that incoming packets can be distributed to the right [`Socket`] with
//! using a channel. It is also what the client should use for
//! sending/receiving datagrams.
//!
//! # Examples
//!
//! Please see [`client.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/client.rs)
//! and [`server.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/server.rs) files
//! from the `phantun` crate for how to use this library in client/server mode, respectively.

use super::packet::*;
use bytes::{Bytes, BytesMut};
use crossbeam::atomic::AtomicCell;
use pnet::packet::Packet as _;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::tcp;
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU16, AtomicU32, Ordering},
};
use tokio::sync::broadcast;
use tokio::time;
use tokio_util::task::AbortOnDropHandle;
use tracing::{error, info, trace, warn};

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 4096;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB
const ACK_THRESHOLD: u32 = 65536; // 64KB: send immediate standalone ACK after this much unacked data

fn system_boot_instant() -> std::time::Instant {
    #[cfg(target_os = "linux")]
    {
        let mut ts = nix::libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe {
            nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut ts);
        }
        let since_boot = std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
        std::time::Instant::now() - since_boot
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::time::Instant::now()
    }
}

pub(crate) struct ParsedPacketMeta {
    pub src_mac: MacAddr,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub window: u16,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub tsval: Option<u32>,
    pub has_sack: bool,
}

#[async_trait::async_trait]
pub trait Tun: Send + Sync + 'static {
    async fn recv(&self) -> Result<Bytes, std::io::Error>;
    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error>;
    fn try_send_batch(&self, packets: &[Bytes]) -> Result<usize, std::io::Error> {
        let mut sent = 0;
        for p in packets {
            self.try_send(p)?;
            sent += 1;
        }
        Ok(sent)
    }
    fn driver_type(&self) -> &'static str;
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

type DispatchItem = (Bytes, ParsedPacketMeta);

#[derive(Default)]
struct StackState {
    tuples: HashMap<AddrTuple, flume::Sender<DispatchItem>>,
    closed: bool,
}

struct Shared {
    state: RwLock<StackState>,
    listening: RwLock<HashSet<u16>>,
    tun: Arc<dyn Tun>,
    tuples_purge: broadcast::Sender<AddrTuple>,
}

impl Shared {
    fn is_closed(&self) -> bool {
        self.state.read().unwrap().closed
    }

    fn mark_closed_and_clear_tuples(&self) -> usize {
        let mut state = self.state.write().unwrap();
        state.closed = true;
        let len = state.tuples.len();
        state.tuples.clear();
        len
    }
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    local_mac: MacAddr,
    reader_task: AbortOnDropHandle<()>,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<dyn Tun>,
    incoming: flume::Receiver<DispatchItem>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    local_mac: MacAddr,
    remote_mac: AtomicCell<Option<MacAddr>>,
    seq: AtomicU32,
    ack: AtomicU32,
    last_ack: AtomicU32,
    remote_ack: AtomicU32,
    remote_window: AtomicU32,
    ts_base: std::time::Instant,
    remote_tsval: AtomicU32,
    ip_id: AtomicU16,
    state: AtomicCell<State>,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    #[allow(clippy::too_many_arguments)]
    fn new(
        shared: Arc<Shared>,
        tun: Arc<dyn Tun>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        local_mac: MacAddr,
        remote_mac: Option<MacAddr>,
        seq: u32,
        ack: u32,
        state: State,
    ) -> (Socket, flume::Sender<DispatchItem>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                local_mac,
                remote_mac: AtomicCell::new(remote_mac),
                seq: AtomicU32::new(seq),
                ack: AtomicU32::new(ack),
                last_ack: AtomicU32::new(ack),
                remote_ack: AtomicU32::new(seq),
                remote_window: AtomicU32::new(0xFFFF << 14),
                ts_base: system_boot_instant(),
                remote_tsval: AtomicU32::new(0),
                ip_id: AtomicU16::new(1),
                state: AtomicCell::new(state),
            },
            incoming_tx,
        )
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        self.build_tcp_packet_with_seq(flags, payload, self.seq.load(Ordering::Relaxed))
    }

    fn build_tcp_packet_with_seq(&self, flags: u8, payload: Option<&[u8]>, seq: u32) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);

        let tsval = self.ts_base.elapsed().as_millis() as u32;
        let tsecr = self.remote_tsval.load(Ordering::Relaxed);
        let ip_id = self.ip_id.fetch_add(1, Ordering::Relaxed);

        build_tcp_packet(
            self.local_mac,
            self.remote_mac.load().unwrap_or(MacAddr::zero()),
            self.local_addr,
            self.remote_addr,
            seq,
            ack,
            flags,
            payload,
            Some((tsval, tsecr)),
            ip_id,
        )
    }

    /// Sends a datagram to the other end.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub fn try_send(&self, payload: &[u8]) -> Option<()> {
        match self.state.load() {
            State::Established => {
                let remote_ack = self.remote_ack.load(Ordering::Relaxed);
                let current_seq = self.seq.load(Ordering::Relaxed);
                let unacked = current_seq.wrapping_sub(remote_ack);

                if unacked > MAX_UNACKED_LEN {
                    tracing::trace!("unacked {} exceeds limit, dropping send", unacked);
                    return Some(());
                }

                let seq = self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                let buf = self.build_tcp_packet_with_seq(
                    tcp::TcpFlags::ACK,
                    Some(payload),
                    seq,
                );
                self.tun.try_send(&buf).ok().and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    pub fn build_packet(&self, payload: &[u8]) -> Option<Bytes> {
        match self.state.load() {
            State::Established => {
                let remote_ack = self.remote_ack.load(Ordering::Relaxed);
                let current_seq = self.seq.load(Ordering::Relaxed);
                let unacked = current_seq.wrapping_sub(remote_ack);

                if unacked > MAX_UNACKED_LEN {
                    return None;
                }

                let seq = self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                let buf = self.build_tcp_packet_with_seq(
                    tcp::TcpFlags::ACK,
                    Some(payload),
                    seq,
                );
                Some(buf)
            }
            _ => None,
        }
    }

    pub fn flush_batch(&self, packets: &[Bytes]) -> usize {
        self.tun.try_send_batch(packets).unwrap_or(0)
    }

    pub fn send_ack(&self) {
        let ack = self.ack.load(Ordering::Relaxed);
        let last = self.last_ack.load(Ordering::Relaxed);
        if ack == last {
            return;
        }
        let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, None);
        let _ = self.tun.try_send(&buf);
    }

    pub fn close(&self) {
        if self.state.load() != State::Idle {
            let buf = self.build_tcp_packet(tcp::TcpFlags::RST, None);
            let _ = self.tun.try_send(&buf);
            self.state.store(State::Idle);
        }
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut BytesMut) -> Option<usize> {
        tracing::trace!(
            "Socket recv called, local_addr: {:?}, remote_addr: {:?}",
            self.local_addr,
            self.remote_addr
        );
        loop {
            match self.state.load() {
                State::Established => {
                    let Ok((frame, meta)) = self.incoming.recv_async().await else {
                        info!("Connection {} recv error", self);
                        return None;
                    };

                    self.remote_mac.store(Some(meta.src_mac));

                    if (meta.flags & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    if (meta.flags & tcp::TcpFlags::ACK) != 0 {
                        let _ = self.remote_ack.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |current| {
                                let diff = meta.ack.wrapping_sub(current);
                                if diff > 0 && diff < MAX_UNACKED_LEN {
                                    Some(meta.ack)
                                } else {
                                    None
                                }
                            },
                        );

                        self.remote_window.store((meta.window as u32) << 14, Ordering::Relaxed);

                        if let Some(tsval) = meta.tsval {
                            self.remote_tsval.store(tsval, Ordering::Relaxed);
                        }
                    }

                    let new_ack = meta.seq.wrapping_add(meta.payload_len as u32);
                    let _ = self.ack.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |current| {
                            let diff = new_ack.wrapping_sub(current);
                            if diff > 0 && diff < MAX_UNACKED_LEN {
                                Some(new_ack)
                            } else {
                                None
                            }
                        },
                    );

                    let last = self.last_ack.load(Ordering::Relaxed);
                    if new_ack.wrapping_sub(last) >= ACK_THRESHOLD {
                        self.send_ack();
                    }

                    if meta.has_sack {
                        self.send_ack();
                    }

                    if meta.payload_len == 0 {
                        continue;
                    }

                    buf.extend_from_slice(&frame[meta.payload_offset..meta.payload_offset + meta.payload_len]);

                    return Some(meta.payload_len);
                }
                State::SynSent => {
                    let Ok(Ok((_frame, meta))) = time::timeout(TIMEOUT, self.incoming.recv_async()).await
                    else {
                        info!("Waiting for client SYN + ACK timed out");
                        return None;
                    };

                    if (meta.flags & tcp::TcpFlags::RST) != 0 {
                        tracing::trace!("Connection {} reset by peer", self);
                        return None;
                    }

                    let expected_flag = tcp::TcpFlags::SYN | tcp::TcpFlags::ACK;
                    if (meta.flags & expected_flag) == expected_flag {
                        let initial_seq = meta.ack;
                        self.seq.store(initial_seq, Ordering::Relaxed);
                        self.remote_ack.store(initial_seq, Ordering::Relaxed);
                        self.ack.store(meta.seq + 1, Ordering::Relaxed);
                        self.remote_window.store((meta.window as u32) << 14, Ordering::Relaxed);
                        self.remote_mac.store(Some(meta.src_mac));
                        if let Some(tsval) = meta.tsval {
                            self.remote_tsval.store(tsval, Ordering::Relaxed);
                        }
                        self.state.store(State::Established);
                        return Some(0);
                    }
                }

                _ => unreachable!(),
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        let (removed, closed) = {
            let mut state = self.shared.state.write().unwrap();
            (state.tuples.remove(&tuple).is_some(), state.closed)
        };
        if !removed {
            if closed {
                trace!(?tuple, "Fake TCP tuple already removed after stack closed");
            } else {
                warn!(?tuple, "Fake TCP tuple missing while dropping socket");
            }
        }
        // purge cache
        let _ = self.shared.tuples_purge.send(tuple);

        let buf = build_tcp_packet(
            self.local_mac,
            self.remote_mac.load().unwrap_or(MacAddr::zero()),
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
            None,
            self.ip_id.fetch_add(1, Ordering::Relaxed),
        );
        if let Err(e) = self.tun.try_send(&buf) {
            warn!("Unable to send RST to remote end: {}", e);
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`Tun`](tokio_tun::Tun).
    /// When more than one [`Tun`](tokio_tun::Tun) object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    pub fn new(
        tun: Arc<dyn Tun>,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
        local_mac: Option<MacAddr>,
    ) -> Stack {
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            state: RwLock::new(StackState::default()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            tuples_purge: tuples_purge_tx.clone(),
        });

        let t = tokio::spawn(Stack::reader_task(
            tun,
            shared.clone(),
            tuples_purge_tx.subscribe(),
        ));

        Stack {
            shared,
            local_ip,
            local_ip6,
            local_mac: local_mac.unwrap_or(MacAddr::zero()),
            reader_task: AbortOnDropHandle::new(t),
        }
    }

    /// Returns the driver type of the stack.
    pub fn driver_type(&self) -> &'static str {
        self.shared.tun.driver_type()
    }

    pub fn is_closed(&self) -> bool {
        self.shared.is_closed() || self.reader_task.is_finished()
    }

    /// Listens for incoming connections on the given `port`.
    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    pub fn try_alloc_established_socket(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        initial_seq: u32,
        initial_ack: u32,
        state: State,
    ) -> Option<Socket> {
        let tuple = AddrTuple::new(local_addr, remote_addr);
        let mut stack_state = self.shared.state.write().unwrap();
        if stack_state.closed || self.reader_task.is_finished() {
            stack_state.closed = true;
            warn!(
                ?tuple,
                "fake_tcp stack is closed, refusing to allocate socket"
            );
            return None;
        }
        let (sock, incoming) = Socket::new(
            self.shared.clone(),
            self.shared.tun.clone(),
            local_addr,
            remote_addr,
            self.local_mac,
            None,
            initial_seq,
            initial_ack,
            state,
        );
        assert!(stack_state.tuples.insert(tuple, incoming).is_none());
        Some(sock)
    }

    async fn reader_task(
        tun: Arc<dyn Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<DispatchItem>> = HashMap::new();

        loop {
            tokio::select! {
                result = tun.recv() => {
                    let buf = match result {
                        Ok(buf) => buf,
                        Err(e) => {
                            let shared_tuple_count = shared.mark_closed_and_clear_tuples();
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            error!(
                                ?e,
                                driver_type = tun.driver_type(),
                                shared_tuple_count,
                                cached_tuple_count,
                                "fake_tcp tun recv failed, reader_task exiting"
                            );
                            break;
                        }
                    };
                    tracing::trace!(len = buf.len(), "received packet");

                    match parse_ip_packet(&buf) {
                        Some((src_mac, _dst_mac, ip_packet, tcp_packet)) => {
                            let local_addr = SocketAddr::new(
                                ip_packet.get_destination(),
                                tcp_packet.get_destination(),
                            );
                            let remote_addr = SocketAddr::new(
                                ip_packet.get_source(),
                                tcp_packet.get_source(),
                            );

                            let flags = tcp_packet.get_flags();
                            let payload = tcp_packet.payload();
                            let payload_offset = if payload.is_empty() {
                                0
                            } else {
                                let offset = payload.as_ptr() as usize - buf.as_ptr() as usize;
                                if offset + payload.len() > buf.len() {
                                    trace!("Dropping packet with invalid payload offset");
                                    continue;
                                }
                                offset
                            };

                            let mut tsval = None;
                            let mut has_sack = false;
                            for opt in tcp_packet.get_options_iter() {
                                match opt.get_number() {
                                    TcpOptionNumbers::TIMESTAMPS if opt.payload().len() >= 4 => {
                                        tsval = Some(u32::from_be_bytes(
                                            opt.payload()[0..4].try_into().unwrap(),
                                        ));
                                    }
                                    TcpOptionNumbers::SACK => {
                                        has_sack = true;
                                    }
                                    _ => {}
                                }
                            }

                            let meta = ParsedPacketMeta {
                                src_mac,
                                flags,
                                seq: tcp_packet.get_sequence(),
                                ack: tcp_packet.get_acknowledgement(),
                                window: tcp_packet.get_window(),
                                payload_offset,
                                payload_len: payload.len(),
                                tsval,
                                has_sack,
                            };

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            let item: DispatchItem = (buf, meta);
                            if let Some(c) = tuples.get(&tuple) {
                                if c.try_send(item).is_err() {
                                    tracing::warn!("fake_tcp dispatch channel full, dropping packet for {:?}", tuple);
                                }

                                continue;
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let state = shared.state.read().unwrap();
                                    state.tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    let send_result = c.try_send(item);
                                    tuples.insert(tuple, c.clone());
                                    if send_result.is_err() {
                                        tracing::warn!("fake_tcp dispatch channel full, dropping packet");
                                    }
                                    continue;
                                }
                            }

                            if flags == tcp::TcpFlags::SYN
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&local_addr.port())
                            {
                                trace!("Received SYN packet for port {}, ignoring", local_addr.port());
                                continue;
                            } else if (flags & tcp::TcpFlags::RST) != 0 {
                                info!("Unknown RST TCP packet from {}, ignoring", remote_addr);
                                continue;
                            } else {
                                trace!("Unknown TCP packet from {}, ignoring", remote_addr);
                                continue;
                            }
                        }
                        None => {
                            trace!("Dropping packet with no IP/TCP header");
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    match tuple {
                        Ok(tuple) => {
                            tuples.remove(&tuple);
                            trace!("Removed cached tuple: {:?}", tuple);
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            warn!(
                                skipped,
                                cached_tuple_count,
                                "fake_tcp tuples purge receiver lagged, cleared local cache"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            let shared_tuple_count = shared.mark_closed_and_clear_tuples();
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            warn!(
                                shared_tuple_count,
                                cached_tuple_count,
                                "fake_tcp tuples purge channel closed, reader_task exiting"
                            );
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio::{
        sync::Notify,
        time::{Duration, timeout},
    };

    #[derive(Default)]
    struct FailingTun {
        fail: Notify,
    }

    impl FailingTun {
        fn fail(&self) {
            self.fail.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl Tun for FailingTun {
        async fn recv(&self) -> Result<Bytes, io::Error> {
            self.fail.notified().await;
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "test tun closed"))
        }

        fn try_send(&self, _packet: &Bytes) -> Result<(), io::Error> {
            Ok(())
        }

        fn driver_type(&self) -> &'static str {
            "test"
        }
    }

    #[tokio::test]
    async fn reader_task_closes_sockets_on_tun_recv_error() {
        let tun = Arc::new(FailingTun::default());
        let mut stack = Stack::new(tun.clone(), Ipv4Addr::LOCALHOST, None, None);
        let socket = stack
            .try_alloc_established_socket(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 10_000),
                SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 20_000),
                0,
                0,
                State::Established,
            )
            .expect("socket allocation should succeed before tun failure");

        tun.fail();

        let join_result = timeout(Duration::from_secs(1), &mut stack.reader_task)
            .await
            .expect("reader task should exit after tun recv error");
        assert!(join_result.is_ok());
        assert!(stack.is_closed());

        let mut buf = BytesMut::new();
        let recv_result = timeout(Duration::from_secs(1), socket.recv(&mut buf))
            .await
            .expect("socket recv should not hang after reader task exits");
        assert_eq!(recv_result, None);

        let new_socket = stack.try_alloc_established_socket(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 10_001),
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 20_001),
            0,
            0,
            State::Established,
        );
        assert!(new_socket.is_none());

        drop(socket);
    }
}
