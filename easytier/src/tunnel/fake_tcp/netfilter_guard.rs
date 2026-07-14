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

fn run_nft(args: &str) -> bool {
    Command::new("nft")
        .args(args.split_whitespace())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn ensure_infra() {
    if INFRA_READY.load(Ordering::Acquire) {
        return;
    }

    let _guard = INFRA_LOCK.lock().unwrap();
    if INFRA_READY.load(Ordering::Acquire) {
        return;
    }

    run_nft(&format!("delete table inet {TABLE_NAME}"));

    if !run_nft(&format!("add table inet {TABLE_NAME}")) {
        tracing::warn!("faketcp: failed to create nftables table, kernel packets may leak");
        return;
    }

    let ok = run_nft(&format!(
        "add set inet {TABLE_NAME} {SET_V4} {{ type ipv4_addr . inet_service . ipv4_addr . inet_service ; }}"
    )) && run_nft(&format!(
        "add set inet {TABLE_NAME} {SET_V6} {{ type ipv6_addr . inet_service . ipv6_addr . inet_service ; }}"
    )) && run_nft(&format!(
        "add chain inet {TABLE_NAME} {CHAIN_NAME} {{ type filter hook output priority 0 ; policy accept ; }}"
    )) && run_nft(&format!(
        "add rule inet {TABLE_NAME} {CHAIN_NAME} meta l4proto tcp ip saddr . tcp sport . ip daddr . tcp dport @{SET_V4} drop"
    )) && run_nft(&format!(
        "add rule inet {TABLE_NAME} {CHAIN_NAME} meta l4proto tcp ip6 saddr . tcp sport . ip6 daddr . tcp dport @{SET_V6} drop"
    ));

    if ok {
        INFRA_READY.store(true, Ordering::Release);
        tracing::info!("faketcp: nftables output drop rules initialized");
    } else {
        run_nft(&format!("delete table inet {TABLE_NAME}"));
        tracing::warn!("faketcp: nftables setup incomplete, cleaned up");
    }
}

pub fn cleanup_all() {
    if INFRA_READY.swap(false, Ordering::AcqRel) {
        run_nft(&format!("delete table inet {TABLE_NAME}"));
        tracing::info!("faketcp: nftables table cleaned up");
    }
}

fn format_element(local: &SocketAddr, remote: &SocketAddr) -> (String, &'static str) {
    let set_name = if local.is_ipv4() { SET_V4 } else { SET_V6 };
    let elem = format!(
        "{} . {} . {} . {}",
        local.ip(),
        local.port(),
        remote.ip(),
        remote.port()
    );
    (elem, set_name)
}

pub struct NftGuard {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    active: bool,
}

impl NftGuard {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        ensure_infra();

        let active = if INFRA_READY.load(Ordering::Relaxed) {
            let (elem, set_name) = format_element(&local_addr, &remote_addr);
            let ok = run_nft(&format!(
                "add element inet {TABLE_NAME} {set_name} {{ {elem} }}"
            ));
            if ok {
                tracing::debug!(?local_addr, ?remote_addr, "faketcp: nft drop rule added");
            } else {
                tracing::warn!(
                    ?local_addr,
                    ?remote_addr,
                    "faketcp: failed to add nft drop rule"
                );
            }
            ok
        } else {
            false
        };

        Self {
            local_addr,
            remote_addr,
            active,
        }
    }
}

impl Drop for NftGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let (elem, set_name) = format_element(&self.local_addr, &self.remote_addr);
        let ok = run_nft(&format!(
            "delete element inet {TABLE_NAME} {set_name} {{ {elem} }}"
        ));
        if ok {
            tracing::debug!(
                ?self.local_addr,
                ?self.remote_addr,
                "faketcp: nft drop rule removed"
            );
        }
    }
}
