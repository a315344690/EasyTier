pub mod dns_server;
#[cfg(target_os = "linux")]
pub mod default_route;
#[allow(clippy::module_inception)]
pub mod instance;

pub mod listeners;

mod public_ipv6_provider;

pub mod proxy_cidrs_monitor;

#[cfg(feature = "tun")]
pub mod virtual_nic;

#[cfg(any(windows, test))]
pub(crate) mod windows_udp_broadcast;
