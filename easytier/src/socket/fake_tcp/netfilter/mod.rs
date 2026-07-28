pub mod linux_bpf;

use std::{io, net::SocketAddr, sync::Arc};

/// Creates the raw-capture TUN device used to send and receive FakeTCP segments.
///
/// FakeTCP is Linux-only, so this is a single `AF_PACKET` backend with no
/// cross-platform fallback: if the raw device cannot be created the connection
/// is aborted rather than silently degraded.
pub fn create_tun(
    interface_name: &str,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Arc<dyn super::stack::Tun>> {
    Ok(Arc::new(linux_bpf::LinuxBpfTun::new(
        interface_name,
        src_addr,
        dst_addr,
    )?))
}
