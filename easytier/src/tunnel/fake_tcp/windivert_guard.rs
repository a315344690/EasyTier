use std::cell::UnsafeCell;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windivert::prelude::{WinDivertFlags, WinDivertShutdownMode};
use windivert::{WinDivert, layer};

struct WinDivertHandle {
    inner: UnsafeCell<WinDivert<layer::NetworkLayer>>,
}

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
    ) -> Result<windivert::packet::WinDivertPacket<'a, layer::NetworkLayer>, windivert::error::WinDivertError>
    {
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

pub struct WinDivertGuard {
    handle: Arc<WinDivertHandle>,
    stop: Arc<AtomicBool>,
    _worker: Option<std::thread::JoinHandle<()>>,
}

impl WinDivertGuard {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<Self> {
        let filter = build_rst_filter(local_addr, remote_addr)?;
        tracing::debug!(%filter, "WinDivertGuard created with filter");

        let flags = WinDivertFlags::default();
        let raw_handle =
            WinDivert::network(&filter, 100, flags).map_err(io::Error::other)?;
        let handle = Arc::new(WinDivertHandle::new(raw_handle));
        let stop = Arc::new(AtomicBool::new(false));

        let worker_handle = handle.clone();
        let worker_stop = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut buffer = vec![0u8; 65536];
            while !worker_stop.load(Ordering::Relaxed) {
                match worker_handle.recv(Some(&mut buffer)) {
                    Ok(_) => {
                        // Intercepted RST packet — drop it by not re-injecting
                    }
                    Err(_) => break,
                }
            }
        });

        tracing::debug!(?local_addr, ?remote_addr, "faketcp: WinDivert RST interceptor active");

        Ok(Self {
            handle,
            stop,
            _worker: Some(worker),
        })
    }
}

impl Drop for WinDivertGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.shutdown();
        if let Some(worker) = self._worker.take() {
            let _ = worker.join();
        }
    }
}

fn build_rst_filter(local_addr: SocketAddr, remote_addr: SocketAddr) -> io::Result<String> {
    if local_addr.is_ipv4() != remote_addr.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "src/dst addr family mismatch",
        ));
    }

    let mut parts = Vec::with_capacity(6);
    parts.push("outbound and tcp.Rst".to_owned());

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
