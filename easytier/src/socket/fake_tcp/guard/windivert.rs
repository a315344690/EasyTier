//! Drops kernel-originated RSTs on hijacked 4-tuples using WinDivert.
//!
//! Windows has no `TCP_REPAIR`, so the decoy socket's stack stays live and will
//! reset the connection once our out-of-sequence segments reach it. A diverting
//! (non-sniffing) handle takes those RSTs out of the stack; never re-injecting
//! them is what makes them disappear.
//!
//! The filter is narrower than the nftables and pf backends -- RSTs only, rather
//! than all kernel egress -- because the decoy socket's own ACKs are harmless here
//! and each handle costs a thread.
//!
//! Note this is a *separate* handle from the data-path one in
//! `netfilter/windivert.rs`, which must stay in sniffing mode so the kernel can
//! still see inbound packets and complete the handshake.

use std::cell::UnsafeCell;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windivert::prelude::{WinDivertFlags, WinDivertShutdownMode};
use windivert::{WinDivert, layer};

/// `recv` needs `&self` while `shutdown`/`close` need `&mut`, and the worker
/// thread holds a shared reference for the handle's whole life. WinDivert handles
/// are safe to use from multiple threads, so hand out interior mutability.
struct WinDivertHandle {
    inner: UnsafeCell<WinDivert<layer::NetworkLayer>>,
}

// SAFETY: `WinDivertShutdown` is explicitly designed to be called from another
// thread to unblock a `WinDivertRecv` in progress, which is exactly how we use it:
// the worker parks in `recv` (`&self`) while `Guard::drop` calls `shutdown`
// (`&mut self` via the UnsafeCell) from a different thread to wake it. Those two DO
// run concurrently; forming `&mut` alongside `&` is UB under Rust's model, but
// neither touches Rust-visible state -- both are thin FFI shims over a C API built
// for this cross-thread shutdown -- so no data race occurs in practice. `close`
// (also `&mut`) is the one operation that must be exclusive, and it is: it runs
// only from `WinDivertHandle::drop`, after `Guard::drop` has joined the worker, so
// no `recv` can be in flight by then.
unsafe impl Send for WinDivertHandle {}
unsafe impl Sync for WinDivertHandle {}

impl WinDivertHandle {
    fn new(handle: WinDivert<layer::NetworkLayer>) -> Self {
        Self {
            inner: UnsafeCell::new(handle),
        }
    }

    fn recv<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> Result<
        windivert::packet::WinDivertPacket<'a, layer::NetworkLayer>,
        windivert::error::WinDivertError,
    > {
        let inner = unsafe { &*self.inner.get() };
        inner.recv(buffer)
    }

    fn shutdown(&self) {
        let inner = unsafe { &mut *self.inner.get() };
        let _ = inner.shutdown(WinDivertShutdownMode::Recv);
    }

    fn close(&self) {
        let inner = unsafe { &mut *self.inner.get() };
        let _ = inner.close(windivert::CloseAction::Nothing);
    }
}

impl Drop for WinDivertHandle {
    fn drop(&mut self) {
        self.close();
    }
}

pub(super) struct Guard {
    handle: Option<Arc<WinDivertHandle>>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Guard {
    pub(super) fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        match Self::try_new(local_addr, remote_addr) {
            Ok(guard) => guard,
            Err(e) => {
                tracing::warn!(
                    ?e,
                    ?local_addr,
                    ?remote_addr,
                    "faketcp: could not install WinDivert RST interceptor, \
                     the kernel may reset this connection"
                );
                Self {
                    handle: None,
                    stop: Arc::new(AtomicBool::new(false)),
                    worker: None,
                }
            }
        }
    }

    fn try_new(local_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
        let filter = build_rst_filter(local_addr, remote_addr)?;
        tracing::debug!(%filter, "faketcp: WinDivert RST filter");

        // Default flags mean divert rather than sniff: matching packets leave the
        // Windows stack and only come back if we re-inject them, which we never do.
        let raw_handle =
            WinDivert::network(&filter, 100, WinDivertFlags::default()).map_err(io::Error::other)?;
        let handle = Arc::new(WinDivertHandle::new(raw_handle));
        let stop = Arc::new(AtomicBool::new(false));

        let worker_handle = handle.clone();
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut buffer = vec![0u8; 65536];
            while !worker_stop.load(Ordering::Relaxed) {
                // Receiving and discarding *is* the drop.
                if worker_handle.recv(Some(&mut buffer)).is_err() {
                    break;
                }
            }
        });

        tracing::debug!(
            ?local_addr,
            ?remote_addr,
            "faketcp: WinDivert RST interceptor active"
        );

        Ok(Self {
            handle: Some(handle),
            stop,
            worker: Some(worker),
        })
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = &self.handle {
            // Unblocks the worker, which is otherwise parked in `recv`.
            handle.shutdown();
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) fn cleanup_all() {
    // Handles are owned by their guards and released when those drop; the driver
    // also tears everything down when the process exits.
}

fn build_rst_filter(local_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<String> {
    if local_addr.is_ipv4() != remote_addr.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "src/dst addr family mismatch",
        ));
    }

    let mut parts = Vec::with_capacity(5);
    parts.push("outbound and tcp.Rst".to_owned());

    // IPv6 literals go in unbracketed, which is what the filter language wants.
    match local_addr {
        SocketAddr::V4(addr) => {
            parts.push(format!("ip.SrcAddr == {}", addr.ip()));
            parts.push(format!("tcp.SrcPort == {}", addr.port()));
        }
        SocketAddr::V6(addr) => {
            parts.push(format!("ipv6.SrcAddr == {}", addr.ip()));
            parts.push(format!("tcp.SrcPort == {}", addr.port()));
        }
    }

    match remote_addr {
        SocketAddr::V4(addr) => {
            parts.push(format!("ip.DstAddr == {}", addr.ip()));
            parts.push(format!("tcp.DstPort == {}", addr.port()));
        }
        SocketAddr::V6(addr) => {
            parts.push(format!("ipv6.DstAddr == {}", addr.ip()));
            parts.push(format!("tcp.DstPort == {}", addr.port()));
        }
    }

    Ok(parts.join(" and "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_matches_outbound_rst_on_the_tuple() {
        let filter = build_rst_filter(
            "192.0.2.1:1111".parse().unwrap(),
            "198.51.100.2:2222".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            filter,
            "outbound and tcp.Rst and ip.SrcAddr == 192.0.2.1 and tcp.SrcPort == 1111 \
             and ip.DstAddr == 198.51.100.2 and tcp.DstPort == 2222"
        );
    }

    #[test]
    fn mismatched_families_are_rejected() {
        assert!(
            build_rst_filter(
                "192.0.2.1:1111".parse().unwrap(),
                "[2001:db8::2]:2222".parse().unwrap(),
            )
            .is_err()
        );
    }
}
