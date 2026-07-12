use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::common::{error::Error, ifcfg::run_shell_cmd};

struct ActiveState {
    original_gateway: String,
    #[allow(dead_code)]
    original_interface: String,
    /// Reference-counted peer host routes: IP -> active connection count
    peer_host_routes: HashMap<Ipv4Addr, usize>,
}

pub struct DefaultRouteManager {
    tun_ifname: String,
    state: Option<ActiveState>,
}

impl DefaultRouteManager {
    pub fn new(tun_ifname: String) -> Self {
        Self {
            tun_ifname,
            state: None,
        }
    }

    /// Activate default route capture.
    /// `initial_peer_ips` are added as host routes BEFORE installing /1 routes
    /// to prevent a window where VPN traffic could be recursively routed.
    pub async fn activate(&mut self, initial_peer_ips: Vec<Ipv4Addr>) -> Result<(), Error> {
        if self.state.is_some() {
            return Ok(());
        }

        let (gateway, interface) = detect_default_route().await?;

        self.state = Some(ActiveState {
            original_gateway: gateway.clone(),
            original_interface: interface.clone(),
            peer_host_routes: HashMap::new(),
        });

        // Step 1: Add host routes for known peers FIRST to prevent routing loop
        for ip in initial_peer_ips {
            let _ = self.add_peer_route(ip).await;
        }

        // Step 2: Add /1 routes to capture all traffic via TUN.
        // These override the default 0/0 route by longest-prefix-match
        // without replacing it, making recovery trivial.
        // When the utun interface disappears (process exit/crash),
        // these routes are automatically invalidated by the kernel.
        run_shell_cmd(&format!(
            "route -n add -net 0.0.0.0/1 -interface {}",
            self.tun_ifname
        ))
        .await?;

        run_shell_cmd(&format!(
            "route -n add -net 128.0.0.0/1 -interface {}",
            self.tun_ifname
        ))
        .await?;

        tracing::info!(
            tun = %self.tun_ifname,
            %gateway,
            %interface,
            "default route activated (macOS)"
        );

        Ok(())
    }

    pub async fn deactivate(&mut self) -> Result<(), Error> {
        let Some(state) = self.state.take() else {
            return Ok(());
        };

        let _ = run_shell_cmd(&format!(
            "route -n delete -net 0.0.0.0/1 -interface {}",
            self.tun_ifname
        ))
        .await;
        let _ = run_shell_cmd(&format!(
            "route -n delete -net 128.0.0.0/1 -interface {}",
            self.tun_ifname
        ))
        .await;

        for peer_ip in state.peer_host_routes.keys() {
            let _ = run_shell_cmd(&format!(
                "route -n delete -host {} {}",
                peer_ip, state.original_gateway
            ))
            .await;
        }

        tracing::info!("default route deactivated (macOS)");
        Ok(())
    }

    /// Add a peer host route (reference-counted).
    /// Multiple connections to the same IP only install one route;
    /// the route is removed only when all connections are gone.
    pub async fn add_peer_route(&mut self, peer_ip: Ipv4Addr) -> Result<(), Error> {
        let Some(state) = self.state.as_mut() else {
            return Ok(());
        };

        let count = state.peer_host_routes.entry(peer_ip).or_insert(0);
        *count += 1;
        if *count == 1 {
            run_shell_cmd(&format!(
                "route -n add -host {} {}",
                peer_ip, state.original_gateway
            ))
            .await?;
            tracing::debug!(%peer_ip, "added peer host route (macOS)");
        }
        Ok(())
    }

    /// Remove a peer host route (reference-counted).
    /// Only actually deletes the route when the last reference is released.
    pub async fn remove_peer_route(&mut self, peer_ip: Ipv4Addr) -> Result<(), Error> {
        let Some(state) = self.state.as_mut() else {
            return Ok(());
        };

        if let Some(count) = state.peer_host_routes.get_mut(&peer_ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.peer_host_routes.remove(&peer_ip);
                let _ = run_shell_cmd(&format!(
                    "route -n delete -host {} {}",
                    peer_ip, state.original_gateway
                ))
                .await;
                tracing::debug!(%peer_ip, "removed peer host route (macOS)");
            }
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.state.is_some()
    }

    fn generate_cleanup_script(&self) -> String {
        let mut script = String::new();
        script.push_str(&format!(
            "route -n delete -net 0.0.0.0/1 -interface {} 2>/dev/null;",
            self.tun_ifname
        ));
        script.push_str(&format!(
            "route -n delete -net 128.0.0.0/1 -interface {} 2>/dev/null;",
            self.tun_ifname
        ));
        if let Some(state) = &self.state {
            for peer_ip in state.peer_host_routes.keys() {
                script.push_str(&format!(
                    "route -n delete -host {} {} 2>/dev/null;",
                    peer_ip, state.original_gateway
                ));
            }
        }
        script
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
            tracing::info!("default route cleaned up via Drop (macOS)");
        }
    }
}

async fn detect_default_route() -> Result<(String, String), Error> {
    let output = tokio::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .await?;

    if !output.status.success() {
        return Err(Error::AnyhowError(anyhow::anyhow!(
            "route -n get default failed"
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gateway = None;
    let mut interface = None;

    for line in stdout.lines() {
        let line = line.trim();
        if let Some(gw) = line.strip_prefix("gateway:") {
            gateway = Some(gw.trim().to_string());
        } else if let Some(iface) = line.strip_prefix("interface:") {
            interface = Some(iface.trim().to_string());
        }
    }

    match (gateway, interface) {
        (Some(gw), Some(iface)) => Ok((gw, iface)),
        _ => Err(Error::AnyhowError(anyhow::anyhow!(
            "failed to parse default route (gateway or interface not found)"
        ))),
    }
}

pub fn extract_ipv4_from_url(url: &url::Url) -> Option<Ipv4Addr> {
    url.host_str()
        .and_then(|h| h.parse::<Ipv4Addr>().ok())
}

pub fn extract_ipv4_from_url_str(url_str: &str) -> Option<Ipv4Addr> {
    url::Url::parse(url_str)
        .ok()
        .and_then(|u| extract_ipv4_from_url(&u))
}
