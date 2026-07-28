//! Drops kernel-originated egress on hijacked 4-tuples using nftables.
//!
//! One table holds a chain on the `output` hook plus two verdict sets keyed by
//! 4-tuple. Adding a connection is a single set element, so the per-connection
//! cost is one short `nft` invocation rather than a rule reload.
//!
//! The `output` hook is the right place: the kernel decoy socket is a real, live
//! connection, and what has to be suppressed is what *it* sends. Our own segments
//! never pass through netfilter -- they go straight out via `AF_PACKET`.

use std::net::SocketAddr;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

const TABLE_NAME: &str = "easytier_faketcp";
const SET_V4: &str = "conns4";
const SET_V6: &str = "conns6";
const CHAIN_NAME: &str = "output";

static INFRA_READY: AtomicBool = AtomicBool::new(false);
static INFRA_LOCK: Mutex<()> = Mutex::new(());

/// Runs `nft` with a whitespace-separated argument string.
///
/// Returns the captured stderr on failure. `nft`'s diagnostics are the only way to
/// tell "binary missing" from "needs CAP_NET_ADMIN" from "nftables not built into
/// this kernel", and an operator cannot act on the failure without them.
fn run_nft(args: &str) -> Result<(), String> {
    let output = Command::new("nft")
        .args(args.split_whitespace())
        .output()
        .map_err(|e| format!("could not run nft: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(if stderr.is_empty() {
        format!("nft exited with {}", output.status)
    } else {
        stderr
    })
}

fn ensure_infra() -> bool {
    if INFRA_READY.load(Ordering::Acquire) {
        return true;
    }

    let _guard = INFRA_LOCK.lock().unwrap();
    if INFRA_READY.load(Ordering::Acquire) {
        return true;
    }

    // A previous run that died without cleaning up leaves the table behind, and
    // with it stale elements for 4-tuples that may since have been reused.
    let _ = run_nft(&format!("delete table inet {TABLE_NAME}"));

    if let Err(e) = run_nft(&format!("add table inet {TABLE_NAME}")) {
        tracing::warn!(
            error = %e,
            "faketcp: could not create nftables table, kernel packets may collide with ours"
        );
        return false;
    }

    let steps = [
        format!(
            "add set inet {TABLE_NAME} {SET_V4} \
             {{ type ipv4_addr . inet_service . ipv4_addr . inet_service ; }}"
        ),
        format!(
            "add set inet {TABLE_NAME} {SET_V6} \
             {{ type ipv6_addr . inet_service . ipv6_addr . inet_service ; }}"
        ),
        format!(
            "add chain inet {TABLE_NAME} {CHAIN_NAME} \
             {{ type filter hook output priority 0 ; policy accept ; }}"
        ),
        format!(
            "add rule inet {TABLE_NAME} {CHAIN_NAME} meta l4proto tcp \
             ip saddr . tcp sport . ip daddr . tcp dport @{SET_V4} drop"
        ),
        format!(
            "add rule inet {TABLE_NAME} {CHAIN_NAME} meta l4proto tcp \
             ip6 saddr . tcp sport . ip6 daddr . tcp dport @{SET_V6} drop"
        ),
    ];

    for step in &steps {
        if let Err(e) = run_nft(step) {
            tracing::warn!(error = %e, step = %step, "faketcp: nftables setup failed, rolling back");
            let _ = run_nft(&format!("delete table inet {TABLE_NAME}"));
            return false;
        }
    }

    INFRA_READY.store(true, Ordering::Release);
    tracing::info!("faketcp: nftables output drop rules initialized");
    true
}

pub(super) fn cleanup_all() {
    if INFRA_READY.swap(false, Ordering::AcqRel) {
        match run_nft(&format!("delete table inet {TABLE_NAME}")) {
            Ok(()) => tracing::info!("faketcp: nftables table cleaned up"),
            Err(e) => tracing::warn!(error = %e, "faketcp: could not remove nftables table"),
        }
    }
}

/// Renders the 4-tuple in the concatenated form the sets are keyed on.
///
/// Order is local-then-remote to match `saddr . sport . daddr . dport` on the
/// `output` hook, where the local address is the source.
fn format_element(local: &SocketAddr, remote: &SocketAddr) -> Option<(String, &'static str)> {
    let set_name = match (local, remote) {
        (SocketAddr::V4(_), SocketAddr::V4(_)) => SET_V4,
        (SocketAddr::V6(_), SocketAddr::V6(_)) => SET_V6,
        _ => return None,
    };
    Some((
        format!(
            "{} . {} . {} . {}",
            local.ip(),
            local.port(),
            remote.ip(),
            remote.port()
        ),
        set_name,
    ))
}

pub(super) struct Guard {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    active: bool,
}

impl Guard {
    pub(super) fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let active = ensure_infra()
            && match format_element(&local_addr, &remote_addr) {
                Some((elem, set_name)) => {
                    match run_nft(&format!(
                        "add element inet {TABLE_NAME} {set_name} {{ {elem} }}"
                    )) {
                        Ok(()) => {
                            tracing::debug!(?local_addr, ?remote_addr, "faketcp: nft drop rule added");
                            true
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                ?local_addr,
                                ?remote_addr,
                                "faketcp: could not add nft drop rule"
                            );
                            false
                        }
                    }
                }
                None => {
                    tracing::warn!(
                        ?local_addr,
                        ?remote_addr,
                        "faketcp: mismatched address families, no nft drop rule"
                    );
                    false
                }
            };

        Self {
            local_addr,
            remote_addr,
            active,
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let Some((elem, set_name)) = format_element(&self.local_addr, &self.remote_addr) else {
            return;
        };
        match run_nft(&format!(
            "delete element inet {TABLE_NAME} {set_name} {{ {elem} }}"
        )) {
            Ok(()) => tracing::debug!(
                local_addr = ?self.local_addr,
                remote_addr = ?self.remote_addr,
                "faketcp: nft drop rule removed"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                local_addr = ?self.local_addr,
                "faketcp: could not remove nft drop rule"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_order_is_local_then_remote() {
        let (elem, set) = format_element(
            &"192.0.2.1:1111".parse().unwrap(),
            &"198.51.100.2:2222".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(elem, "192.0.2.1 . 1111 . 198.51.100.2 . 2222");
        assert_eq!(set, SET_V4);
    }

    #[test]
    fn v6_tuples_use_the_v6_set() {
        let (elem, set) = format_element(
            &"[2001:db8::1]:1111".parse().unwrap(),
            &"[2001:db8::2]:2222".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(elem, "2001:db8::1 . 1111 . 2001:db8::2 . 2222");
        assert_eq!(set, SET_V6);
    }

    /// A v4/v6 pair has no set to go in, so it must be rejected rather than
    /// silently rendered into a malformed element.
    #[test]
    fn mismatched_families_have_no_element() {
        assert!(
            format_element(
                &"192.0.2.1:1111".parse().unwrap(),
                &"[2001:db8::2]:2222".parse().unwrap(),
            )
            .is_none()
        );
    }

    fn set_contains(set_name: &str, elem: &str) -> bool {
        let output = Command::new("nft")
            .args(["list", "set", "inet", TABLE_NAME, set_name])
            .output()
            .expect("nft should be runnable");
        // `nft list` normalises whitespace around the `.` separators, so compare on
        // the pieces rather than the string we fed in.
        let listing = String::from_utf8_lossy(&output.stdout);
        elem.split(" . ").all(|part| listing.contains(part))
    }

    /// Serialised: the whole process shares one table and one `INFRA_READY` flag,
    /// so a concurrent test could tear down the table under this one.
    #[test]
    #[ignore = "requires root and the nft binary"]
    #[serial_test::serial]
    fn guard_installs_and_withdraws_its_element() {
        let local: SocketAddr = "192.0.2.77:11111".parse().unwrap();
        let remote: SocketAddr = "198.51.100.88:22222".parse().unwrap();
        let (elem, set_name) = format_element(&local, &remote).unwrap();

        let guard = Guard::new(local, remote);
        assert!(
            guard.active,
            "guard should install its rule as root; check CAP_NET_ADMIN and nftables support"
        );
        assert!(set_contains(set_name, &elem), "element missing after install");

        drop(guard);
        assert!(
            !set_contains(set_name, &elem),
            "element still present after the guard was dropped"
        );

        cleanup_all();
    }

    /// The table must not survive `cleanup_all`, otherwise a crashed process would
    /// leave stale elements matching 4-tuples that get reused later.
    #[test]
    #[ignore = "requires root and the nft binary"]
    #[serial_test::serial]
    fn cleanup_all_removes_the_table() {
        assert!(ensure_infra(), "infra should come up as root");
        assert!(
            run_nft(&format!("list table inet {TABLE_NAME}")).is_ok(),
            "table should exist once infra is up"
        );

        cleanup_all();
        assert!(
            run_nft(&format!("list table inet {TABLE_NAME}")).is_err(),
            "table should be gone after cleanup"
        );
    }
}
