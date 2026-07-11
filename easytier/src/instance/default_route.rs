use std::net::{IpAddr, Ipv4Addr};

use crate::common::{
    error::Error,
    ifcfg::{run_shell_cmd, list_routes, route::Route},
};

const VPN_TABLE: u32 = 6846;
const RULE_PRIO_FROM_PHY: u32 = 6839;
const RULE_PRIO_SUPPRESS: u32 = 6840;
const RULE_PRIO_VPN: u32 = 6841;
const RULE_PRIO_BYPASS_MAIN: u32 = 6842;
const RULE_PRIO_BYPASS_DEFAULT: u32 = 6843;

const THROW_CIDRS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
];

struct ActiveState {
    original_ip_forward: String,
    original_src_valid_mark: String,
}

pub struct DefaultRouteManager {
    tun_ifname: String,
    socket_mark: u32,
    state: Option<ActiveState>,
}

impl DefaultRouteManager {
    pub fn new(tun_ifname: String, socket_mark: u32) -> Self {
        Self {
            tun_ifname,
            socket_mark,
            state: None,
        }
    }

    pub async fn cleanup_stale(&self) -> Result<(), Error> {
        for prio in RULE_PRIO_FROM_PHY..=RULE_PRIO_BYPASS_DEFAULT {
            loop {
                if run_shell_cmd(&format!("ip rule del prio {prio}"))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
        let _ = run_shell_cmd(&format!("ip route flush table {VPN_TABLE}")).await;
        Ok(())
    }

    pub async fn activate(&mut self) -> Result<(), Error> {
        if self.state.is_some() {
            return Ok(());
        }

        self.cleanup_stale().await?;

        let original_ip_forward = read_sysctl("net.ipv4.ip_forward");
        let original_src_valid_mark = read_sysctl("net.ipv4.conf.all.src_valid_mark");

        run_shell_cmd("sysctl -w net.ipv4.ip_forward=1").await?;
        run_shell_cmd("sysctl -w net.ipv4.conf.all.src_valid_mark=1").await?;

        for cidr in THROW_CIDRS {
            let _ =
                run_shell_cmd(&format!("ip route add throw {cidr} table {VPN_TABLE}")).await;
        }

        run_shell_cmd(&format!(
            "ip route add default dev {} table {VPN_TABLE}",
            self.tun_ifname
        ))
        .await?;

        // Detect physical IPs and add source-based bypass rules to prevent
        // asymmetric routing for inbound connections (e.g., SSH from WAN).
        let phy_ips = detect_physical_ips(&self.tun_ifname)?;
        for ip in &phy_ips {
            let _ = run_shell_cmd(&format!(
                "ip rule add from {ip} table main prio {RULE_PRIO_FROM_PHY}"
            ))
            .await;
        }

        run_shell_cmd(&format!(
            "ip rule add table main suppress_prefixlength 0 prio {RULE_PRIO_SUPPRESS}"
        ))
        .await?;

        run_shell_cmd(&format!(
            "ip rule add not fwmark {:#x} table {VPN_TABLE} prio {RULE_PRIO_VPN}",
            self.socket_mark
        ))
        .await?;

        run_shell_cmd(&format!(
            "ip rule add fwmark {:#x} table main prio {RULE_PRIO_BYPASS_MAIN}",
            self.socket_mark
        ))
        .await?;

        run_shell_cmd(&format!(
            "ip rule add fwmark {:#x} table default prio {RULE_PRIO_BYPASS_DEFAULT}",
            self.socket_mark
        ))
        .await?;

        self.state = Some(ActiveState {
            original_ip_forward,
            original_src_valid_mark,
        });

        tracing::info!(
            tun = %self.tun_ifname,
            mark = %format!("{:#x}", self.socket_mark),
            table = VPN_TABLE,
            ?phy_ips,
            "default route activated"
        );

        Ok(())
    }

    pub async fn deactivate(&mut self) -> Result<(), Error> {
        let Some(state) = self.state.take() else {
            return Ok(());
        };

        for prio in RULE_PRIO_FROM_PHY..=RULE_PRIO_BYPASS_DEFAULT {
            let _ = run_shell_cmd(&format!("ip rule del prio {prio}")).await;
        }

        let _ = run_shell_cmd(&format!("ip route flush table {VPN_TABLE}")).await;

        let _ = run_shell_cmd(&format!(
            "sysctl -w net.ipv4.ip_forward={}",
            state.original_ip_forward
        ))
        .await;
        let _ = run_shell_cmd(&format!(
            "sysctl -w net.ipv4.conf.all.src_valid_mark={}",
            state.original_src_valid_mark
        ))
        .await;

        tracing::info!("default route deactivated");
        Ok(())
    }

    fn generate_cleanup_script(&self) -> String {
        let mut script = String::new();
        for prio in RULE_PRIO_FROM_PHY..=RULE_PRIO_BYPASS_DEFAULT {
            script.push_str(&format!("ip rule del prio {prio} 2>/dev/null;"));
        }
        script.push_str(&format!("ip route flush table {VPN_TABLE} 2>/dev/null"));
        script
    }

    pub fn is_active(&self) -> bool {
        self.state.is_some()
    }
}

impl Drop for DefaultRouteManager {
    fn drop(&mut self) {
        if self.state.is_some() {
            let script = self.generate_cleanup_script();
            let _ = std::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .output();
            tracing::info!("default route cleaned up via Drop");
        }
    }
}

fn read_sysctl(key: &str) -> String {
    std::process::Command::new("sysctl")
        .arg("-n")
        .arg(key)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Detect IPv4 addresses on physical interfaces by finding which interface
/// carries the current default route, then collecting all IPv4 addrs on it.
fn detect_physical_ips(tun_ifname: &str) -> Result<Vec<Ipv4Addr>, Error> {
    let routes = list_routes()?;
    let mut phy_ifindex = None;

    for msg in &routes {
        let route: Route = msg.clone().into();
        if route.destination == IpAddr::V4(Ipv4Addr::UNSPECIFIED) && route.prefix == 0 {
            if let Some(idx) = route.ifindex {
                let ifname = ifindex_to_name(idx);
                if ifname.as_deref() != Some(tun_ifname) {
                    phy_ifindex = Some(idx);
                    break;
                }
            }
        }
    }

    let Some(phy_idx) = phy_ifindex else {
        return Ok(vec![]);
    };

    let phy_name = ifindex_to_name(phy_idx).unwrap_or_default();
    let addrs = crate::common::ifcfg::list_addresses(&phy_name)?;
    Ok(addrs
        .into_iter()
        .filter_map(|inet| match inet.address() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect())
}

fn ifindex_to_name(index: u32) -> Option<String> {
    use nix::libc;
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(index, buf.as_mut_ptr() as *mut libc::c_char) };
    if ptr.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(ptr) };
    Some(cstr.to_string_lossy().into_owned())
}
