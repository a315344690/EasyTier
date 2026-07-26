use std::net::SocketAddr;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const ANCHOR_PREFIX: &str = "com.easytier.faketcp";

static PF_ENABLED: AtomicBool = AtomicBool::new(false);
static PF_INIT_LOCK: Mutex<()> = Mutex::new(());
static CONN_ID: AtomicU64 = AtomicU64::new(0);

fn run_pfctl(args: &[&str]) -> bool {
    Command::new("pfctl")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_pfctl_stdin(args: &[&str], input: &str) -> bool {
    use std::io::Write;
    let child = Command::new("pfctl")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    match child {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input.as_bytes());
            }
            child.wait().map(|s| s.success()).unwrap_or(false)
        }
        Err(_) => false,
    }
}

fn ensure_pf_enabled() {
    if PF_ENABLED.load(Ordering::Acquire) {
        return;
    }

    let _guard = PF_INIT_LOCK.lock().unwrap();
    if PF_ENABLED.load(Ordering::Acquire) {
        return;
    }

    if run_pfctl(&["-E"]) {
        PF_ENABLED.store(true, Ordering::Release);
        tracing::info!("faketcp: pf enabled for RST suppression");
    } else {
        tracing::warn!("faketcp: pfctl -E failed, RST suppression unavailable");
    }
}

pub struct PfGuard {
    anchor: String,
    active: bool,
}

impl PfGuard {
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        ensure_pf_enabled();

        if !PF_ENABLED.load(Ordering::Relaxed) {
            return Self {
                anchor: String::new(),
                active: false,
            };
        }

        let id = CONN_ID.fetch_add(1, Ordering::Relaxed);
        let anchor = format!("{}/{}", ANCHOR_PREFIX, id);

        let (proto, src, dst) = match (local_addr, remote_addr) {
            (SocketAddr::V4(l), SocketAddr::V4(r)) => (
                "inet",
                format!("{} port {}", l.ip(), l.port()),
                format!("{} port {}", r.ip(), r.port()),
            ),
            (SocketAddr::V6(l), SocketAddr::V6(r)) => (
                "inet6",
                format!("{} port {}", l.ip(), l.port()),
                format!("{} port {}", r.ip(), r.port()),
            ),
            _ => {
                tracing::warn!("faketcp pf_guard: mismatched address families");
                return Self {
                    anchor: String::new(),
                    active: false,
                };
            }
        };

        let rule = format!(
            "block drop out quick {} proto tcp from {} to {}\n",
            proto, src, dst
        );

        let active = run_pfctl_stdin(&["-a", &anchor, "-f", "-"], &rule);

        if active {
            tracing::debug!(?local_addr, ?remote_addr, %anchor, "faketcp: pf RST drop rule added");
        } else {
            tracing::warn!(?local_addr, ?remote_addr, "faketcp: failed to add pf RST drop rule");
        }

        Self { anchor, active }
    }
}

impl Drop for PfGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let ok = run_pfctl(&["-a", &self.anchor, "-F", "all"]);
        if ok {
            tracing::debug!(anchor = %self.anchor, "faketcp: pf RST drop rule removed");
        }
    }
}
