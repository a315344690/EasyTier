//! Keeps the kernel quiet on 4-tuples that FakeTCP has taken over.
//!
//! The kernel socket that performed the handshake is frozen with `TCP_REPAIR`
//! (see `freeze_kernel_socket`), but that only covers the local kernel, and only
//! where the capability is available. These guards add a second line of defence
//! at the packet filter: anything the local kernel still tries to emit on the
//! hijacked 4-tuple is dropped before it reaches the wire, so it cannot collide
//! with the segments we craft ourselves.
//!
//! Every implementation is best-effort. Losing the guard costs throughput -- the
//! peer's kernel answers our segments with corrective ACKs -- but never
//! correctness, so construction never fails the connection.

use std::net::SocketAddr;

cfg_select! {
    target_os = "linux" => {
        mod nft;
        use nft as imp;
    }
    all(target_os = "macos", not(feature = "macos-ne")) => {
        mod pf;
        use pf as imp;
    }
    all(windows, any(target_arch = "x86_64", target_arch = "x86")) => {
        mod windivert;
        use windivert as imp;
    }
    _ => {
        mod noop;
        use noop as imp;
    }
}

/// Suppresses kernel-originated packets on one 4-tuple for as long as it is held.
///
/// Purely a lifetime token: the inner guard installs its rule on construction and
/// withdraws it on drop, so the field is never read.
pub(crate) struct KernelSilencer(#[allow(dead_code)] imp::Guard);

impl KernelSilencer {
    pub(crate) fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self(imp::Guard::new(local_addr, remote_addr))
    }
}

/// Tears down whatever process-wide filter state the guards installed.
///
/// Individual guards clean up after themselves on drop; this exists for the paths
/// that skip destructors. Safe to call more than once, and safe to call when
/// nothing was ever installed.
pub(crate) fn cleanup_all() {
    imp::cleanup_all();
}
