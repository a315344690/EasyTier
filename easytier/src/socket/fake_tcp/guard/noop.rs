//! Fallback for platforms with no packet filter we can drive.
//!
//! FakeTCP still works here: the local kernel is quietened by `TCP_REPAIR` where
//! available, and what leaks costs throughput rather than correctness.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};

static WARNED: AtomicBool = AtomicBool::new(false);

pub(super) struct Guard;

impl Guard {
    pub(super) fn new(_local_addr: SocketAddr, _remote_addr: SocketAddr) -> Self {
        if !WARNED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "faketcp: no packet-filter backend on this platform, \
                 kernel packets may collide with ours"
            );
        }
        Self
    }
}

pub(super) fn cleanup_all() {}
