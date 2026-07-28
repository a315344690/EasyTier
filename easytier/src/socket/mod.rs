// FakeTCP relies on TCP_REPAIR (a Linux-only capability) to silence the decoy
// kernel socket; it is deliberately compiled only on Linux.
#[cfg(all(feature = "faketcp", target_os = "linux"))]
pub(crate) mod fake_tcp;
pub(crate) mod tcp;
pub(crate) mod udp;
pub(crate) mod udp_src;
