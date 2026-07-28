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
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::{Packet, tcp};
use pnet::util::MacAddr;
use rand::{RngCore, SeedableRng, rngs::SmallRng};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{
    Arc, OnceLock, RwLock,
    atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering},
};
use std::time::Instant;
use tokio::sync::{Notify, broadcast};
use tokio::time;
use tokio_util::task::AbortOnDropHandle;
use tracing::{error, info, trace, warn};

/// The instant that TCP timestamp values are measured from.
///
/// Real stacks derive TSval from a clock that started at boot, so a connection
/// opened on a long-running host starts with a large TSval, and two connections
/// opened minutes apart carry visibly different ones. Deriving the base from a
/// per-socket `Instant::now()` would instead restart every connection near
/// zero, which no real host does. Resolve it once per process and share it
/// across all sockets.
pub(super) fn ts_base() -> Instant {
    static TS_BASE: OnceLock<Instant> = OnceLock::new();
    *TS_BASE.get_or_init(|| {
        // `CLOCK_MONOTONIC` counts from boot on Linux and the BSDs (including
        // macOS), so subtracting it from now recovers the boot instant.
        #[cfg(unix)]
        {
            let mut ts = nix::libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
                let since_boot = std::time::Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);
                if let Some(boot) = Instant::now().checked_sub(since_boot) {
                    return boot;
                }
            }
        }
        // Windows exposes no `CLOCK_MONOTONIC` through `nix`, so fall back to
        // the process start. TSval still advances monotonically and is shared by
        // every socket; it just doesn't encode the host's uptime.
        Instant::now()
    })
}

const HANDSHAKE_TIMEOUT: time::Duration = time::Duration::from_secs(3);
const MPMC_BUFFER_LEN: usize = 4096;
const KEEPALIVE_INTERVAL_SECS: u32 = 20;
/// Only advance our tracked ACK forward, and only within this window, so a stale
/// or reordered inbound segment cannot drag it backwards. Half the sequence space
/// is the usual "is this ahead of us" boundary for wrapping u32 comparisons.
const MAX_UNACKED_LEN: u32 = u32::MAX / 2;
/// Advertised receive window: `u16::MAX` minus a small random deduction. The
/// value matters to stateful middleboxes -- see `build_tcp_packet_inner`. The
/// ceiling stays at the maximum because the middlebox window-tracking bound is
/// `advertised_win << negotiated_wscale`, and a lower ceiling shrinks the range
/// of in-flight bytes conntrack will tolerate; the small jitter only breaks the
/// "window never moves" fingerprint.
const RECV_WINDOW_MAX: u16 = u16::MAX;
const RECV_WINDOW_JITTER: u16 = 512;

thread_local! {
    // Window jitter is a fingerprint-breaker, not a security value, so a fast
    // non-cryptographic PRNG is the right tool. Seeded once from thread_rng();
    // each packet is then a few xoshiro ops instead of a ChaCha12 draw. Mirrors
    // easytier-core/src/tunnel/padding.rs.
    static WINDOW_RNG: RefCell<SmallRng> =
        RefCell::new(SmallRng::from_rng(rand::thread_rng()).unwrap());
}
/// How many inbound RSTs to absorb within `RST_WINDOW_SECS` before treating the
/// connection as reset, and the width of that window.
///
/// A single RST must not tear the connection down: the segments we craft are
/// out-of-sequence as far as the kernel decoy socket is concerned, so the local
/// or peer kernel can emit one before the RST-suppression rules take effect (or
/// if installing them failed), and an off-path attacker who guesses the tuple
/// needs only one forged packet. Real stacks validate a RST's sequence number
/// against the receive window; we cannot, since our peer's sequence space is
/// deliberately not the kernel's, so absorb a short burst instead.
const MAX_RST_ALLOWED: u32 = 3;
const RST_WINDOW_SECS: u32 = 10;

#[async_trait::async_trait]
pub trait Tun: Send + Sync + 'static {
    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error>;
    async fn recv_bytes(&self) -> Result<Bytes, std::io::Error> {
        let mut buf = BytesMut::with_capacity(2048);
        self.recv(&mut buf).await?;
        Ok(buf.freeze())
    }
    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error>;
    fn try_send_batch(&self, packets: &[Bytes]) -> Result<usize, std::io::Error> {
        let mut sent = 0;
        for p in packets {
            if self.try_send(p).is_err() {
                break;
            }
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

#[derive(Default)]
struct StackState {
    tuples: HashMap<AddrTuple, flume::Sender<Bytes>>,
    closed: bool,
}

struct Shared {
    state: RwLock<StackState>,
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
    local_mac: MacAddr,
    reader_task: AbortOnDropHandle<()>,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum State {
    Idle,
    SynSent,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<dyn Tun>,
    incoming: flume::Receiver<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    local_mac: MacAddr,
    remote_mac: AtomicCell<Option<MacAddr>>,
    seq: AtomicU32,
    /// Our receive progress: the peer's sequence number plus the bytes we have
    /// taken from it. Written to outgoing segments' acknowledgement field ONLY
    /// when `repair_active` -- see that field and `build_tcp_packet_inner`.
    ack: AtomicU32,
    /// The peer *kernel*'s initial sequence number plus one. This is the only
    /// value the peer's frozen kernel will accept in our ACK field, so it is what
    /// we send when the kernel is NOT silenced (`repair_active == false`).
    peer_isn_ack: AtomicU32,
    /// Whether we may advance the ACK field with received data (the way a real
    /// receiver does, which keeps a middlebox's forward-window right edge sliding),
    /// versus pinning it at `peer_isn_ack`.
    ///
    /// It is set exactly when the kernel's own sequence numbers were adopted --
    /// which happens only after `freeze_kernel_socket` has put our kernel in
    /// TCP_REPAIR (listener: at construction via `kernel_state`; connector: in
    /// `adopt_kernel_state`). So a true value implies our kernel is frozen and
    /// therefore will not emit a corrective ACK of its own when ours climbs.
    ///
    /// When false, either TCP_REPAIR was unavailable or the seed numbers were both
    /// zero: our kernel is still live, so a rising ACK would make the *peer's*
    /// kernel drop our segments (RFC 9293 3.10.7.4). Pinning at `peer_isn_ack`
    /// avoids that. Tracks `seq_calibrated`'s initial value bit-for-bit; the two
    /// are seeded together and only ever transition false->true.
    repair_active: AtomicBool,
    /// Payload bytes received since our last bare ACK. Drives `send_ack` on the
    /// fail-soft path, where the pinned ACK field can't signal "new data arrived".
    recv_since_ack: AtomicU32,
    state: AtomicCell<State>,
    seq_calibrated: AtomicBool,
    ts_base: Instant,
    /// Set once the kernel socket's timestamp offset is known, which for a
    /// connector is only after its handshake completes.
    ts_offset: AtomicU32,
    remote_tsval: AtomicU32,
    ip_id: AtomicU16,
    last_send_time_secs: AtomicU32,
    /// Inbound RSTs in the current window, and when the last one landed. See
    /// `count_rst` for why this is windowed rather than a running total.
    rst_received: AtomicU32,
    last_rst_time_secs: AtomicU32,
    ack_notify: Arc<Notify>,
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
        kernel_state: Option<super::KernelTcpState>,
        state: State,
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);
        // With the kernel's numbers in hand we are already calibrated; otherwise
        // the first inbound segment (or the SYN-ACK, for a connector) supplies them.
        let kernel_state = kernel_state.unwrap_or_default();
        let calibrated = kernel_state.seq != 0 || kernel_state.ack != 0;

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                local_mac,
                remote_mac: AtomicCell::new(remote_mac),
                seq: AtomicU32::new(kernel_state.seq),
                ack: AtomicU32::new(kernel_state.ack),
                peer_isn_ack: AtomicU32::new(kernel_state.ack),
                // True here only when a listener was constructed with a frozen
                // kernel's numbers (calibrated). A connector starts false and is
                // flipped by `adopt_kernel_state` once its handshake completes.
                repair_active: AtomicBool::new(calibrated),
                recv_since_ack: AtomicU32::new(0),
                state: AtomicCell::new(state),
                seq_calibrated: AtomicBool::new(calibrated),
                ts_base: ts_base(),
                ts_offset: AtomicU32::new(kernel_state.ts_offset),
                remote_tsval: AtomicU32::new(0),
                ip_id: AtomicU16::new(rand::random()),
                last_send_time_secs: AtomicU32::new(0),
                rst_received: AtomicU32::new(0),
                last_rst_time_secs: AtomicU32::new(0),
                ack_notify: Arc::new(Notify::new()),
            },
            incoming_tx,
        )
    }

    pub fn ack_notify(&self) -> &Arc<Notify> {
        &self.ack_notify
    }

    /// Overwrites the sequence state with the kernel socket's own.
    ///
    /// A connector calibrates from the SYN-ACK it captured, which is enough to
    /// start sending, but the kernel's numbers are authoritative -- and they only
    /// become readable once its handshake has finished.
    /// Must be called before the socket is shared across tasks: the stores here
    /// are Relaxed and rely on the `Arc` publication barrier that hands the socket
    /// to the read/write halves. Re-adopting on a live, shared socket would let
    /// another core observe a torn mix of old and new sequence state.
    pub fn adopt_kernel_state(&self, kernel_state: super::KernelTcpState) {
        self.seq.store(kernel_state.seq, Ordering::Relaxed);
        self.ack.store(kernel_state.ack, Ordering::Relaxed);
        self.peer_isn_ack.store(kernel_state.ack, Ordering::Relaxed);
        self.ts_offset
            .store(kernel_state.ts_offset, Ordering::Relaxed);
        // Our kernel is frozen, so we may advance the ACK field with received data.
        self.repair_active.store(true, Ordering::Relaxed);
        self.seq_calibrated.store(true, Ordering::Release);
        tracing::debug!(
            seq = kernel_state.seq,
            ack = kernel_state.ack,
            "faketcp: adopted kernel sequence state"
        );
    }

    fn build_tcp_packet_inner(
        &self,
        flags: u8,
        payload: Option<&[u8]>,
        seq: u32,
        padding_len: usize,
    ) -> Bytes {
        // The ACK field depends on whether our kernel is silenced. When it is
        // (`repair_active`), advance with received data like a real receiver: this
        // keeps a middlebox's forward-window right edge (`ack + win<<wscale`)
        // sliding, so large transfers stay in-window. The peer kernel that would
        // otherwise reject a rising ACK is silenced on the peer's side by its own
        // guard. When TCP_REPAIR was unavailable, pin at the peer kernel's ISN+1:
        // a rising ACK there would make the peer kernel drop our segment and reply
        // with a corrective ACK (RFC 9293 3.10.7.4).
        let ack = if self.repair_active.load(Ordering::Relaxed) {
            self.ack.load(Ordering::Relaxed)
        } else {
            self.peer_isn_ack.load(Ordering::Relaxed)
        };
        let tsval = (self.ts_base.elapsed().as_millis() as u32)
            .wrapping_add(self.ts_offset.load(Ordering::Relaxed));
        let tsecr = self.remote_tsval.load(Ordering::Relaxed);
        let ip_id = self.ip_id.fetch_add(1, Ordering::Relaxed);
        // FakeTCP has no flow control -- payload is handed straight to the caller in `recv`
        // with no backlog buffer -- so the only readers of the advertised window are stateful
        // middleboxes (conntrack, NAT gateways, commercial firewalls). Two things matter to
        // them: the value must not sit frozen across a long flow (a fingerprint), and it must
        // be large, because the window they track is `advertised_win << negotiated_wscale` and
        // a smaller value shrinks the in-flight bytes they tolerate before judging us
        // out-of-window. So advertise the 16-bit maximum minus a small jitter. A bare RST
        // advertises a zero window, as real stacks do.
        let window = if flags == tcp::TcpFlags::RST {
            0
        } else {
            let jitter =
                WINDOW_RNG.with(|r| (r.borrow_mut().next_u32() % RECV_WINDOW_JITTER as u32) as u16);
            RECV_WINDOW_MAX - jitter
        };

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
            window,
            padding_len,
        )
    }

    /// Builds a TCP packet with the given payload but does not send it.
    /// Returns `None` if the socket is not established or SEQ is not yet calibrated.
    pub fn build_packet(&self, payload: &[u8]) -> Option<Bytes> {
        if !matches!(self.state.load(), State::Established) {
            return None;
        }
        if !self.seq_calibrated.load(Ordering::Acquire) {
            return None;
        }
        let seq = self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
        let buf = self.build_tcp_packet_inner(
            tcp::TcpFlags::ACK | tcp::TcpFlags::PSH,
            Some(payload),
            seq,
            0,
        );
        self.last_send_time_secs
            .store(self.ts_base.elapsed().as_secs() as u32, Ordering::Relaxed);
        Some(buf)
    }

    /// Sends multiple pre-built TCP frames to the TUN device in a batch.
    ///
    /// Returns how many made it out.
    pub fn flush_batch(&self, packets: &[Bytes]) -> usize {
        // Claim the whole debt atomically rather than reading a snapshot and
        // subtracting it afterwards: a concurrent `send_ack`/`flush_batch` would
        // otherwise read the same snapshot and subtract it a second time, wrapping
        // the counter past zero. With `swap` the loser sees 0 and retires nothing.
        let owed = self.recv_since_ack.swap(0, Ordering::Relaxed);
        let sent = self.tun.try_send_batch(packets).unwrap_or(0);
        if sent > 0 {
            // Those frames carried the pinned acknowledgement, so inbound data seen
            // before this flush is now acknowledged and no bare ACK is owed for it.
            // Retiring it here rather than at build time matters: frames are queued
            // by `build_packet` and may sit unsent, or fail to send at all.
        } else if owed > 0 {
            // Nothing reached the wire, so that acknowledgement never went out; hand
            // the debt back, folding in anything that arrived since the swap.
            self.recv_since_ack.fetch_add(owed, Ordering::Relaxed);
        }
        sent
    }

    /// Records an inbound RST and returns how many have arrived in the current
    /// window, restarting the window if the last one is older than it.
    ///
    /// The threshold has to apply to a burst, not to the connection's lifetime: a
    /// long-lived tunnel will legitimately meet the odd stray RST hours apart, and
    /// a plain running total would eventually tear it down for no reason. A genuine
    /// reset arrives as a burst, because whatever decided to reset us keeps doing it
    /// for every segment we send.
    fn count_rst(&self) -> u32 {
        let now_secs = self.ts_base.elapsed().as_secs() as u32;
        let last = self.last_rst_time_secs.load(Ordering::Relaxed);
        let prior = self.rst_received.load(Ordering::Relaxed);
        // `prior == 0` is the first RST ever: `seen` is only ever stored as 1 or
        // `prior + 1`, so the count never returns to 0 once one has arrived, and
        // there is no earlier window to extend.
        let seen = if prior == 0 || now_secs.wrapping_sub(last) > RST_WINDOW_SECS {
            1
        } else {
            prior + 1
        };
        self.rst_received.store(seen, Ordering::Relaxed);
        self.last_rst_time_secs.store(now_secs, Ordering::Relaxed);
        seen
    }

    /// Sends a bare ACK if we have unacknowledged inbound data or the keepalive
    /// interval has elapsed.
    ///
    /// The trigger is the volume of payload received, not movement of the ACK
    /// field. On the fail-soft path that field is pinned and cannot signal new
    /// data at all; on the repair path a bare ACK is only needed when we have no
    /// outgoing data segment to carry the advance, i.e. exactly when the pure
    /// receive direction has unacknowledged bytes. `recv_since_ack` covers both.
    pub fn send_ack(&self) {
        if !self.seq_calibrated.load(Ordering::Acquire) {
            return;
        }
        let now_secs = self.ts_base.elapsed().as_secs() as u32;
        let last_send_secs = self.last_send_time_secs.load(Ordering::Relaxed);
        let force_keepalive = now_secs.wrapping_sub(last_send_secs) >= KEEPALIVE_INTERVAL_SECS;
        // Claim the debt atomically so a concurrent `flush_batch`/`send_ack` sees 0
        // and cannot subtract the same snapshot again, which would underflow the
        // counter. Anything that lands after this swap is fresh debt and re-notifies
        // the ACK task. Swapping unconditionally is safe: when the value was already
        // 0 the swap is a no-op we fall straight out of.
        let owed = self.recv_since_ack.swap(0, Ordering::Relaxed);
        if owed == 0 && !force_keepalive {
            return;
        }
        let seq = self.seq.load(Ordering::Relaxed);
        let buf = self.build_tcp_packet_inner(tcp::TcpFlags::ACK, None, seq, 0);
        if self.tun.try_send(&buf).is_err() {
            // The ACK never reached the wire, so that data is still unacknowledged;
            // hand the debt back, folding in anything that arrived since the swap.
            self.recv_since_ack.fetch_add(owed, Ordering::Relaxed);
        }
        self.last_send_time_secs.store(now_secs, Ordering::Relaxed);
    }

    pub fn close(&self) {
        if self.state.load() != State::Idle {
            // Without a calibrated SEQ our RST would carry sequence 0, far outside
            // any window the peer will accept, so it can only add noise.
            if !self.seq_calibrated.load(Ordering::Acquire) {
                self.state.store(State::Idle);
                return;
            }
            let seq = self.seq.load(Ordering::Relaxed);
            let buf = self.build_tcp_packet_inner(tcp::TcpFlags::RST, None, seq, 0);
            let _ = self.tun.try_send(&buf);
            self.state.store(State::Idle);
        }
    }

    /// Attempt to receive a datagram from the other end, appending its payload to
    /// `buf`. See [`recv_payload`](Self::recv_payload) for the zero-copy primitive
    /// this wraps; this form exists for callers that accumulate into a buffer
    /// (the handshake path and tests).
    ///
    /// A return of `None` means the TCP connection is broken and the socket must
    /// be closed.
    pub async fn recv(&self, buf: &mut BytesMut) -> Option<usize> {
        let payload = self.recv_payload().await?;
        let len = payload.len();
        buf.extend_from_slice(&payload);
        Some(len)
    }

    /// Attempt to receive a datagram, returning its payload as a zero-copy slice
    /// of the underlying frame (no allocation, no copy).
    ///
    /// This is the hot-path form: the returned `Bytes` shares the frame's
    /// refcounted buffer, so the only copy in the read path is the final one into
    /// the caller's `ReadBuf`. Takes `&self` and is safe to call concurrently.
    ///
    /// A handshake completing in the `SynSent` state yields an empty `Bytes`; a
    /// return of `None` means the connection is broken.
    pub async fn recv_payload(&self) -> Option<Bytes> {
        tracing::trace!(
            "Socket recv called, local_addr: {:?}, remote_addr: {:?}",
            self.local_addr,
            self.remote_addr
        );
        loop {
            match self.state.load() {
                State::Established => {
                    let Ok(raw_buf) = self.incoming.recv_async().await else {
                        info!("Connection {} recv error", self);
                        return None;
                    };

                    let Some((src_mac, dst_mac, _v4_packet, tcp_packet)) =
                        parse_ip_packet(&raw_buf)
                    else {
                        trace!("Dropping malformed fake tcp packet for established socket");
                        continue;
                    };

                    tracing::trace!(
                        "Socket received TCP packet from {}({:?}) to {}({:?}): {:?}",
                        self.remote_addr,
                        src_mac,
                        self.local_addr,
                        dst_mac,
                        tcp_packet
                    );

                    self.remote_mac.store(Some(src_mac));

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        let seen = self.count_rst();
                        if seen > MAX_RST_ALLOWED {
                            info!(seen, "Connection {} reset by peer", self);
                            return None;
                        }
                        // Log only the first one: a middlebox or kernel that has
                        // decided to reset us tends to do it for every segment.
                        if seen == 1 {
                            warn!(
                                max = MAX_RST_ALLOWED,
                                "Connection {} got a RST, absorbing it", self
                            );
                        } else {
                            trace!(seen, "Connection {} absorbed another RST", self);
                        }
                        continue;
                    }

                    // Extract TCP timestamp from options
                    if (tcp_packet.get_flags() & tcp::TcpFlags::ACK) != 0 {
                        for opt in tcp_packet.get_options_iter() {
                            if opt.get_number() == TcpOptionNumbers::TIMESTAMPS {
                                let data = opt.payload();
                                if data.len() >= 4 {
                                    let tsval =
                                        u32::from_be_bytes(data[0..4].try_into().unwrap());
                                    self.remote_tsval.store(tsval, Ordering::Relaxed);
                                }
                                break;
                            }
                        }
                    }

                    let payload = tcp_packet.payload();

                    if !payload.is_empty() {
                        // Advance our receive cursor. On the repair path this is what
                        // outgoing segments acknowledge, so a middlebox sees a real
                        // receiver's ACK climb; on the fail-soft path it is unused for
                        // the ACK field but still drives `send_ack`. Move forward only,
                        // and only within half the sequence space, so a stale or
                        // reordered segment can't drag the cursor backwards.
                        let new_ack =
                            tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
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
                        self.recv_since_ack
                            .fetch_add(payload.len() as u32, Ordering::Relaxed);
                        self.ack_notify.notify_one();
                    }

                    // One-time calibration off the peer's first segment, reached only
                    // when the kernel's own numbers were unavailable: a connector
                    // calibrates in the `SynSent` arm from the SYN-ACK, and a
                    // successful `freeze_kernel_socket` marks us calibrated before
                    // the first segment arrives. So in practice this is the
                    // non-Linux listener path, or Linux without CAP_NET_ADMIN.
                    //
                    // The peer's kernel stopped sending after the handshake, so its
                    // send sequence is frozen at ISN+1 -- which is precisely where
                    // the peer's fake stack began numbering its own segments. The
                    // first segment we see therefore carries the value we must
                    // acknowledge from here on. If that segment were lost and we
                    // calibrated off a later one we would latch too high, and the
                    // peer's kernel would reject our ACKs; nothing recovers from that
                    // short of the connection being retried.
                    if !self.seq_calibrated.load(Ordering::Acquire)
                        && (tcp_packet.get_flags() & tcp::TcpFlags::ACK) != 0
                        && tcp_packet.get_acknowledgement() != 0
                    {
                        self.seq
                            .store(tcp_packet.get_acknowledgement(), Ordering::Relaxed);
                        self.peer_isn_ack
                            .store(tcp_packet.get_sequence(), Ordering::Relaxed);
                        // Reaching this block means `freeze_kernel_socket` did not run
                        // (fail-soft), so `ack` was never seeded from the kernel and the
                        // `fetch_update` above may have started from 0. Seed it to this
                        // segment's right edge -- the same value that `fetch_update`
                        // would land on -- so the receive cursor is correct from here.
                        // (The wire ACK is pinned at `peer_isn_ack` on this path, so
                        // `ack` only feeds `send_ack`'s cursor, not the header.)
                        let seg_end = tcp_packet
                            .get_sequence()
                            .wrapping_add(payload.len() as u32);
                        self.ack.store(seg_end, Ordering::Relaxed);
                        self.seq_calibrated.store(true, Ordering::Release);
                    }

                    if payload.is_empty() {
                        continue;
                    }

                    // Zero-copy: hand back a refcounted view into the frame rather
                    // than copying the payload out. `raw_buf` stays alive behind the
                    // returned `Bytes`.
                    return Some(raw_buf.slice_ref(payload));
                }
                State::SynSent => {
                    let Ok(Ok(buf)) =
                        time::timeout(HANDSHAKE_TIMEOUT, self.incoming.recv_async()).await
                    else {
                        info!("Waiting for client SYN + ACK timed out");
                        return None;
                    };
                    let Some((src_mac, _dst_mac, _v4_packet, tcp_packet)) = parse_ip_packet(&buf)
                    else {
                        trace!("Dropping malformed fake tcp packet during handshake");
                        continue;
                    };

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        tracing::trace!("Connection {} reset by peer", self);
                        return None;
                    }

                    let expected_flag = tcp::TcpFlags::SYN | tcp::TcpFlags::ACK;
                    if (tcp_packet.get_flags() & expected_flag) == expected_flag {
                        // found our SYN + ACK
                        self.seq
                            .store(tcp_packet.get_acknowledgement(), Ordering::Relaxed);
                        // The SYN-ACK's sequence number *is* the peer kernel's ISN,
                        // so ISN+1 is what the fail-soft path pins the ACK field to,
                        // and also the baseline our receive cursor advances from.
                        let peer_isn_next = tcp_packet.get_sequence().wrapping_add(1);
                        self.peer_isn_ack.store(peer_isn_next, Ordering::Relaxed);
                        self.ack.store(peer_isn_next, Ordering::Relaxed);
                        self.remote_mac.store(Some(src_mac));
                        for opt in tcp_packet.get_options_iter() {
                            if opt.get_number() == TcpOptionNumbers::TIMESTAMPS {
                                let data = opt.payload();
                                if data.len() >= 4 {
                                    let tsval =
                                        u32::from_be_bytes(data[0..4].try_into().unwrap());
                                    self.remote_tsval.store(tsval, Ordering::Relaxed);
                                }
                                break;
                            }
                        }
                        self.seq_calibrated.store(true, Ordering::Release);
                        self.state.store(State::Established);
                        // Handshake done, no payload to deliver.
                        return Some(Bytes::new());
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

        // As in `close`: a RST built on an uncalibrated SEQ would sit at sequence
        // 0, outside any window the peer accepts, so skip it entirely.
        if !self.seq_calibrated.load(Ordering::Acquire) {
            info!(
                "Fake TCP connection to {} closed (SEQ uncalibrated, skipping RST)",
                self
            );
            return;
        }

        let seq = self.seq.load(Ordering::Relaxed);
        let buf = self.build_tcp_packet_inner(tcp::TcpFlags::RST, None, seq, 0);
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
    pub fn new(tun: Arc<dyn Tun>, local_mac: Option<MacAddr>) -> Stack {
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            state: RwLock::new(StackState::default()),
            tun: tun.clone(),
            tuples_purge: tuples_purge_tx.clone(),
        });

        let t = tokio::spawn(Stack::reader_task(
            tun,
            shared.clone(),
            tuples_purge_tx.subscribe(),
        ));

        Stack {
            shared,
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

    /// Allocates a socket for a 4-tuple whose handshake the kernel already did.
    ///
    /// `kernel_state` carries the frozen kernel socket's sequence numbers when we
    /// were able to read them (Linux with `CAP_NET_ADMIN`). Without it the socket
    /// calibrates itself from the first inbound segment instead.
    pub fn try_alloc_established_socket(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        state: State,
        kernel_state: Option<super::KernelTcpState>,
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
            // self.shared.tun.choose(&mut rng).unwrap().clone(),
            self.shared.tun.clone(), // Simplification: just use the first tun
            local_addr,
            remote_addr,
            self.local_mac,
            None,
            kernel_state,
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
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();

        loop {
            tokio::select! {
                result = tun.recv_bytes() => {
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
                        Some((_src_mac, _dst_mac, ip_packet, tcp_packet)) => {
                            let local_addr = SocketAddr::new(
                                ip_packet.get_destination(),
                                tcp_packet.get_destination(),
                            );
                            let remote_addr = SocketAddr::new(
                                ip_packet.get_source(),
                                tcp_packet.get_source(),
                            );

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                if c.try_send(buf).is_err() {
                                    trace!("fake_tcp dispatch: channel full or closed, dropping packet");
                                }

                                continue;

                                // If not Ok, receiver has been closed and just fall through to the slow
                                // path below
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let state = shared.state.read().unwrap();
                                    state.tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    if let Err(e) = c.try_send(buf) {
                                        trace!("Error sending packet to connection: {:?}", e);
                                    }
                                    continue;
                                }
                            }

                            if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
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
        async fn recv(&self, _packet: &mut BytesMut) -> Result<usize, io::Error> {
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

    /// A `Tun` that records everything written to it and never yields a packet,
    /// so tests drive the socket by pushing frames into its `incoming` channel
    /// directly and then assert on what the socket wrote back.
    #[derive(Default)]
    struct MockTun {
        sent: std::sync::Mutex<Vec<Bytes>>,
    }

    impl MockTun {
        fn sent(&self) -> Vec<Bytes> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Tun for MockTun {
        async fn recv(&self, _packet: &mut BytesMut) -> Result<usize, io::Error> {
            std::future::pending().await
        }

        fn try_send(&self, packet: &Bytes) -> Result<(), io::Error> {
            self.sent.lock().unwrap().push(packet.clone());
            Ok(())
        }

        fn driver_type(&self) -> &'static str {
            "mock"
        }
    }

    const TEST_LOCAL: &str = "10.0.0.1:10000";
    const TEST_REMOTE: &str = "10.0.0.2:20000";

    /// Builds a stack backed by `MockTun` plus an established socket, returning
    /// the sender side of the socket's dispatch channel so tests can inject
    /// inbound frames without going through a real capture device.
    /// A `MockTun`-backed established socket on the FAIL-SOFT path (`repair_active
    /// == false`): allocated with `None` kernel state, so it calibrates from the
    /// first inbound segment and pins the ACK field at `peer_isn_ack`.
    fn mock_socket() -> (Arc<MockTun>, Stack, Socket, flume::Sender<Bytes>) {
        let tun = Arc::new(MockTun::default());
        let stack = Stack::new(tun.clone(), None);
        let local: SocketAddr = TEST_LOCAL.parse().unwrap();
        let remote: SocketAddr = TEST_REMOTE.parse().unwrap();
        let socket = stack
            .try_alloc_established_socket(local, remote, State::Established, None)
            .expect("fresh stack should allocate");
        // Take a clone of the dispatch sender the stack registered for us.
        let tx = stack
            .shared
            .state
            .read()
            .unwrap()
            .tuples
            .get(&AddrTuple::new(local, remote))
            .expect("tuple registered by try_alloc_established_socket")
            .clone();
        (tun, stack, socket, tx)
    }

    /// A `MockTun`-backed established socket on the REPAIR path (`repair_active ==
    /// true`), as if `freeze_kernel_socket` had handed us the kernel's numbers.
    fn mock_socket_repair(
        seq: u32,
        ack: u32,
    ) -> (Arc<MockTun>, Stack, Socket, flume::Sender<Bytes>) {
        let tun = Arc::new(MockTun::default());
        let stack = Stack::new(tun.clone(), None);
        let local: SocketAddr = TEST_LOCAL.parse().unwrap();
        let remote: SocketAddr = TEST_REMOTE.parse().unwrap();
        let socket = stack
            .try_alloc_established_socket(
                local,
                remote,
                State::Established,
                Some(super::super::KernelTcpState {
                    seq,
                    ack,
                    ts_offset: 0,
                }),
            )
            .expect("fresh stack should allocate");
        assert!(socket.repair_active.load(Ordering::Relaxed));
        let tx = stack
            .shared
            .state
            .read()
            .unwrap()
            .tuples
            .get(&AddrTuple::new(local, remote))
            .expect("tuple registered by try_alloc_established_socket")
            .clone();
        (tun, stack, socket, tx)
    }

    /// An inbound frame addressed to our local socket, as the peer would send it.
    fn inbound(seq: u32, ack: u32, flags: u8, payload: Option<&[u8]>) -> Bytes {
        build_tcp_packet(
            MacAddr::zero(),
            MacAddr::zero(),
            TEST_REMOTE.parse().unwrap(),
            TEST_LOCAL.parse().unwrap(),
            seq,
            ack,
            flags,
            payload,
            None,
            0,
            0xffff,
            0,
        )
    }

    /// `recv_payload` returns the payload as a zero-copy slice of the frame, and
    /// `recv` wrapping it still delivers identical bytes.
    #[tokio::test]
    async fn recv_payload_returns_exact_bytes() {
        let (_tun, _stack, socket, tx) = mock_socket();

        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"hello world")))
            .unwrap();
        let payload = socket.recv_payload().await.expect("payload");
        assert_eq!(&payload[..], b"hello world");

        // The `recv` wrapper appends the same bytes to an existing buffer.
        tx.send(inbound(1011, 5000, tcp::TcpFlags::ACK, Some(b"more")))
            .unwrap();
        let mut buf = BytesMut::from(&b"pre-"[..]);
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(&buf[..], b"pre-more");
    }

    /// `slice_ref` reconstructs the payload's position by pointer arithmetic
    /// against the frame, so it must hold for the IPv6 header layout (40-byte
    /// header, no options) as well as IPv4 -- a wrong-family panic here would only
    /// surface at runtime on a v6 tunnel.
    #[tokio::test]
    async fn recv_payload_zero_copies_ipv6_frames() {
        let tun = Arc::new(MockTun::default());
        let stack = Stack::new(tun.clone(), None);
        let local: SocketAddr = "[2001:db8::1]:10000".parse().unwrap();
        let remote: SocketAddr = "[2001:db8::2]:20000".parse().unwrap();
        let socket = stack
            .try_alloc_established_socket(local, remote, State::Established, None)
            .expect("allocate");
        let tx = stack
            .shared
            .state
            .read()
            .unwrap()
            .tuples
            .get(&AddrTuple::new(local, remote))
            .expect("tuple")
            .clone();

        let frame = build_tcp_packet(
            MacAddr::zero(),
            MacAddr::zero(),
            remote,
            local,
            1000,
            5000,
            tcp::TcpFlags::ACK,
            Some(b"v6 payload"),
            None,
            0,
            0xffff,
            0,
        );
        tx.send(frame).unwrap();
        let payload = socket.recv_payload().await.expect("payload");
        assert_eq!(&payload[..], b"v6 payload");
    }

    /// Empty (payload-less) inbound segments are skipped, not surfaced as a
    /// zero-length read that a caller might mistake for EOF.
    #[tokio::test]
    async fn recv_payload_skips_empty_segments() {
        let (_tun, _stack, socket, tx) = mock_socket();

        // A bare ACK (no payload) followed by real data: recv_payload must block
        // past the empty one and return only the data.
        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, None)).unwrap();
        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"data")))
            .unwrap();
        let payload = socket.recv_payload().await.expect("payload");
        assert_eq!(&payload[..], b"data");
    }

    /// FAIL-SOFT path: with our kernel NOT silenced, the ACK field must stay at
    /// the peer kernel's ISN+1 no matter how much payload arrives. Advancing it
    /// would acknowledge data the peer's kernel never sent, and RFC 9293 3.10.7.4
    /// obliges that kernel to drop our segment and answer with a corrective ACK --
    /// which is what made throughput collapse.
    #[tokio::test]
    async fn fail_soft_pins_the_acknowledgement_field() {
        let (_tun, _stack, socket, tx) = mock_socket();
        assert!(!socket.repair_active.load(Ordering::Relaxed));

        // First inbound segment calibrates us: SEQ from its ack field, and the
        // pinned acknowledgement from its sequence number.
        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"aaaa")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(socket.seq.load(Ordering::Relaxed), 5000);
        assert_eq!(socket.peer_isn_ack.load(Ordering::Relaxed), 1000);

        // Feed a lot more payload; the pinned value must not budge.
        for i in 0..8u32 {
            tx.send(inbound(
                1004 + i * 4,
                5000,
                tcp::TcpFlags::ACK,
                Some(b"bbbb"),
            ))
            .unwrap();
            buf.clear();
            assert_eq!(socket.recv(&mut buf).await, Some(4));
        }
        assert_eq!(socket.peer_isn_ack.load(Ordering::Relaxed), 1000);

        let frame = socket.build_packet(b"reply").expect("established");
        let (_, _, _, tcp_pkt) = parse_ip_packet(&frame).unwrap();
        assert_eq!(tcp_pkt.get_acknowledgement(), 1000);
        assert_eq!(tcp_pkt.get_sequence(), 5000);
    }

    /// REPAIR path: with our kernel silenced, the ACK field advances with received
    /// data like a real receiver, so a middlebox's forward-window right edge keeps
    /// sliding and large transfers do not fall out-of-window.
    #[tokio::test]
    async fn repair_path_advances_the_acknowledgement_field() {
        // seq (our SND.NXT) = 5000, ack (peer's ISN+1, our RCV.NXT) = 1000.
        let (_tun, _stack, socket, tx) = mock_socket_repair(5000, 1000);

        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"aaaa")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));

        // A segment we build now must acknowledge the 4 bytes we took.
        let frame = socket.build_packet(b"reply").expect("established");
        let (_, _, _, tcp_pkt) = parse_ip_packet(&frame).unwrap();
        assert_eq!(tcp_pkt.get_acknowledgement(), 1004);
        assert_eq!(tcp_pkt.get_sequence(), 5000);

        // Feed more; the ACK keeps climbing.
        tx.send(inbound(1004, 5000, tcp::TcpFlags::ACK, Some(b"bbbbbb")))
            .unwrap();
        buf.clear();
        assert_eq!(socket.recv(&mut buf).await, Some(6));
        let frame = socket.build_packet(b"reply").expect("established");
        let (_, _, _, tcp_pkt) = parse_ip_packet(&frame).unwrap();
        assert_eq!(tcp_pkt.get_acknowledgement(), 1010);
    }

    /// Even on the repair path, a stale or reordered segment behind our cursor
    /// must not drag the ACK backwards.
    #[tokio::test]
    async fn repair_path_ack_never_goes_backwards() {
        let (_tun, _stack, socket, tx) = mock_socket_repair(5000, 1000);

        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"aaaaaa")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(6));
        assert_eq!(socket.ack.load(Ordering::Relaxed), 1006);

        // An old segment (seq 1000) arrives again: its new_ack=1006 equals current,
        // diff==0, rejected; a truly stale one (seq 990) would compute a huge
        // wrapping diff, also rejected.
        tx.send(inbound(990, 5000, tcp::TcpFlags::ACK, Some(b"zz")))
            .unwrap();
        buf.clear();
        assert_eq!(socket.recv(&mut buf).await, Some(2));
        assert_eq!(socket.ack.load(Ordering::Relaxed), 1006);
    }

    /// A connector takes the pinned acknowledgement straight from the kernel's
    /// SYN-ACK, so it is correct before the first byte goes out.
    #[tokio::test]
    async fn connector_pins_acknowledgement_from_syn_ack() {
        let tun = Arc::new(MockTun::default());
        let stack = Stack::new(tun.clone(), None);
        let local: SocketAddr = TEST_LOCAL.parse().unwrap();
        let remote: SocketAddr = TEST_REMOTE.parse().unwrap();
        let socket = stack
            .try_alloc_established_socket(local, remote, State::SynSent, None)
            .expect("fresh stack should allocate");
        let tx = stack
            .shared
            .state
            .read()
            .unwrap()
            .tuples
            .get(&AddrTuple::new(local, remote))
            .expect("tuple registered")
            .clone();

        tx.send(inbound(
            7000,
            9000,
            tcp::TcpFlags::SYN | tcp::TcpFlags::ACK,
            None,
        ))
        .unwrap();

        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(0));
        assert_eq!(socket.seq.load(Ordering::Relaxed), 9000);
        assert_eq!(socket.peer_isn_ack.load(Ordering::Relaxed), 7001);

        let frame = socket.build_packet(b"first").expect("established");
        let (_, _, _, tcp_pkt) = parse_ip_packet(&frame).unwrap();
        assert_eq!(tcp_pkt.get_acknowledgement(), 7001);
        assert_eq!(tcp_pkt.get_sequence(), 9000);
    }

    /// With the acknowledgement field pinned, "has the ACK moved?" can no longer
    /// decide when to emit a bare ACK; received payload has to drive it.
    #[tokio::test]
    async fn bare_ack_is_driven_by_received_payload() {
        let (tun, _stack, socket, tx) = mock_socket();

        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"data")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));

        let before = tun.sent().len();
        socket.send_ack();
        let sent = tun.sent();
        assert_eq!(sent.len(), before + 1, "unacked payload should force an ACK");
        let (_, _, _, tcp_pkt) = parse_ip_packet(sent.last().unwrap()).unwrap();
        assert_eq!(tcp_pkt.get_flags(), tcp::TcpFlags::ACK);
        assert_eq!(tcp_pkt.get_acknowledgement(), 1000);

        // Nothing new arrived, so a second call is a no-op rather than a flood.
        socket.send_ack();
        assert_eq!(tun.sent().len(), before + 1);
    }

    /// The ACK task waits ~40ms after being notified before sending. A data segment
    /// flushed inside that gap already carries the acknowledgement, so it retires the
    /// debt -- but only once it has actually reached the wire. Building a frame must
    /// not retire it, or a queued-then-dropped frame would swallow the ACK entirely.
    #[tokio::test]
    async fn queued_but_unsent_data_does_not_retire_the_ack_debt() {
        let (tun, _stack, socket, tx) = mock_socket();

        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"aaaa")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));

        // Build without flushing: the frame exists but nothing has been sent.
        let frame = socket.build_packet(b"queued").expect("established");
        let before = tun.sent().len();
        socket.send_ack();
        assert_eq!(
            tun.sent().len(),
            before + 1,
            "an unflushed frame must not suppress the bare ACK"
        );

        // Once a frame does go out, the debt is settled and no ACK is owed.
        tx.send(inbound(1004, 5000, tcp::TcpFlags::ACK, Some(b"bbbb")))
            .unwrap();
        buf.clear();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(socket.flush_batch(&[frame]), 1);
        let before = tun.sent().len();
        socket.send_ack();
        assert_eq!(
            tun.sent().len(),
            before,
            "a flushed data segment already acknowledged the inbound data"
        );
    }

    /// `send_ack` and `flush_batch` both retire the ACK debt, and on a multi-thread
    /// runtime they can run at once. Retiring must not read a snapshot and subtract
    /// it after the fact, or both would subtract the same value and wrap the counter
    /// far past zero. Draining it to exactly zero here proves the claim is taken
    /// atomically instead.
    #[tokio::test]
    async fn concurrent_retirement_does_not_underflow_the_ack_debt() {
        let (_tun, _stack, socket, tx) = mock_socket();

        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"aaaa")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(socket.recv_since_ack.load(Ordering::Relaxed), 4);

        // A data frame carries the pinned ACK, so flushing it settles the debt; the
        // bare ACK then finds nothing owed. Whichever order they run in, the counter
        // must land on 0 and never wrap.
        let frame = socket.build_packet(b"reply").expect("established");
        assert_eq!(socket.flush_batch(&[frame]), 1);
        socket.send_ack();
        assert_eq!(
            socket.recv_since_ack.load(Ordering::Relaxed),
            0,
            "double retirement underflowed the counter"
        );
    }

    /// A send that never reaches the wire must not silently swallow the ACK debt:
    /// the swap that claimed it has to be undone so a later attempt still sends.
    #[tokio::test]
    async fn failed_ack_send_returns_the_debt() {
        #[derive(Default)]
        struct DeadTun;
        #[async_trait::async_trait]
        impl Tun for DeadTun {
            async fn recv(&self, _packet: &mut BytesMut) -> Result<usize, io::Error> {
                std::future::pending().await
            }
            fn try_send(&self, _packet: &Bytes) -> Result<(), io::Error> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "no wire"))
            }
            fn driver_type(&self) -> &'static str {
                "dead"
            }
        }

        let tun = Arc::new(DeadTun);
        let stack = Stack::new(tun.clone(), None);
        let local: SocketAddr = TEST_LOCAL.parse().unwrap();
        let remote: SocketAddr = TEST_REMOTE.parse().unwrap();
        let socket = stack
            .try_alloc_established_socket(local, remote, State::Established, None)
            .expect("fresh stack should allocate");
        let tx = stack
            .shared
            .state
            .read()
            .unwrap()
            .tuples
            .get(&AddrTuple::new(local, remote))
            .expect("tuple registered")
            .clone();

        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"data")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(socket.recv_since_ack.load(Ordering::Relaxed), 4);

        // The wire is dead, so the ACK never goes out and the debt must survive.
        socket.send_ack();
        assert_eq!(
            socket.recv_since_ack.load(Ordering::Relaxed),
            4,
            "a failed send must hand the ACK debt back"
        );
    }

    /// RSTs spread across time must not accumulate into a teardown; only a burst
    /// should count. A long-lived tunnel meets the odd stray RST.
    #[tokio::test]
    async fn stray_rsts_outside_the_window_do_not_accumulate() {
        let (_tun, _stack, socket, tx) = mock_socket();

        // Fill the window right up to the threshold.
        for _ in 0..MAX_RST_ALLOWED {
            tx.send(inbound(1000, 0, tcp::TcpFlags::RST, None)).unwrap();
        }
        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"live")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(socket.rst_received.load(Ordering::Relaxed), MAX_RST_ALLOWED);

        // Pretend the burst happened long ago. The next RST opens a fresh window
        // instead of tipping the connection over.
        socket
            .last_rst_time_secs
            .store(0u32.wrapping_sub(RST_WINDOW_SECS + 1), Ordering::Relaxed);
        tx.send(inbound(1004, 0, tcp::TcpFlags::RST, None)).unwrap();
        tx.send(inbound(1004, 5000, tcp::TcpFlags::ACK, Some(b"more")))
            .unwrap();
        buf.clear();
        assert!(
            socket.recv(&mut buf).await.is_some(),
            "a RST outside the window must not close the connection"
        );
        assert_eq!(socket.rst_received.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn absorbs_a_few_rsts_before_giving_up() {
        let (_tun, _stack, socket, tx) = mock_socket();

        // Every RST up to the threshold is swallowed, so a single forged packet
        // cannot tear the connection down. Interleave real data to prove the
        // socket is still usable in between.
        for _ in 0..MAX_RST_ALLOWED {
            tx.send(inbound(1000, 0, tcp::TcpFlags::RST, None)).unwrap();
        }
        tx.send(inbound(1000, 0, tcp::TcpFlags::ACK, Some(b"live")))
            .unwrap();

        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(&buf[..], b"live");

        // One past the threshold ends it.
        tx.send(inbound(1004, 0, tcp::TcpFlags::RST, None)).unwrap();
        buf.clear();
        assert_eq!(socket.recv(&mut buf).await, None);
    }

    #[tokio::test]
    async fn advertised_window_is_jittered_and_zero_on_rst() {
        let (tun, _stack, socket, tx) = mock_socket();

        // Calibrate SEQ so `build_packet` will emit, then send a few segments
        // and check the advertised window moves within its band rather than
        // being pinned to one value.
        tx.send(inbound(1000, 5000, tcp::TcpFlags::ACK, Some(b"x")))
            .unwrap();
        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(1));

        let mut windows = std::collections::HashSet::new();
        for _ in 0..64 {
            let frame = socket.build_packet(b"payload").expect("established");
            let (_, _, _, tcp_pkt) = parse_ip_packet(&frame).unwrap();
            let window = tcp_pkt.get_window();
            assert!(
                (RECV_WINDOW_MAX - RECV_WINDOW_JITTER..=RECV_WINDOW_MAX).contains(&window),
                "window {window} outside advertised band"
            );
            windows.insert(window);
        }
        assert!(
            windows.len() > 1,
            "window should vary across segments, saw only {windows:?}"
        );

        // A bare RST advertises no window, the way a real stack does.
        socket.close();
        let rst = tun
            .sent()
            .into_iter()
            .filter_map(|frame| {
                let (_, _, _, tcp_pkt) = parse_ip_packet(&frame)?;
                (tcp_pkt.get_flags() == tcp::TcpFlags::RST).then(|| tcp_pkt.get_window())
            })
            .next_back()
            .expect("close() should emit a RST");
        assert_eq!(rst, 0);
    }

    #[tokio::test]
    async fn reader_task_closes_sockets_on_tun_recv_error() {
        let tun = Arc::new(FailingTun::default());
        let mut stack = Stack::new(tun.clone(), None);
        let socket = stack
            .try_alloc_established_socket(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 10_000),
                SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 20_000),
                State::Established,
                None,
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
            State::Established,
            None,
        );
        assert!(new_socket.is_none());

        drop(socket);
    }
}
