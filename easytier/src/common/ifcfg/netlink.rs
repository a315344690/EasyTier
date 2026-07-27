#![cfg_attr(
    not(any(feature = "public-ipv6-provider", feature = "tun")),
    allow(dead_code)
)]

use std::{
    collections::BTreeSet,
    ffi::CString,
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::AsRawFd,
};

use anyhow::Context;
use async_trait::async_trait;
use cidr::{IpInet, Ipv4Inet, Ipv6Inet};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
#[cfg(test)]
use nix::libc::SIOCGIFMTU;
use nix::{
    ifaddrs::getifaddrs,
    libc::{self, Ioctl, SIOCGIFFLAGS, SIOCSIFFLAGS, SIOCSIFMTU, ifreq, ioctl},
    net::if_::InterfaceFlags,
    sys::socket::SockaddrLike as _,
};
use pnet::ipnetwork::ip_mask_to_prefix;

use super::{
    Error, IfConfiguerTrait,
    netlink_wire::{
        AddressMessage, MessageBuilder, MessageIter, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP,
        NLM_F_DUMP_INTR, NLM_F_EXCL, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NeighborMessage,
        NetlinkDecode, NetlinkEncode, RTM_DELADDR, RTM_DELNEIGH, RTM_DELROUTE, RTM_GETNEIGH,
        RTM_GETROUTE, RTM_NEWADDR, RTM_NEWNEIGH, RTM_NEWROUTE, RouteMessage, RouteMessageBuilder,
        RouteType, netlink_error_code,
    },
};

pub(crate) fn dummy_socket() -> Result<std::net::UdpSocket, Error> {
    Ok(std::net::UdpSocket::bind("0:0")?)
}

fn build_ifreq(name: &str) -> ifreq {
    let c_str = CString::new(name).unwrap();
    let mut ifr: ifreq = unsafe { std::mem::zeroed() };
    let name_bytes = c_str.as_bytes_with_nul();
    for (i, &b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

fn send_netlink_req(builder: MessageBuilder) -> Result<Socket, Error> {
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let buf = builder.finish()?;
    tracing::debug!(request_len = buf.len(), "sending netlink request");
    socket.send(&buf, 0)?;

    Ok(socket)
}

fn send_netlink_req_and_wait_ack(builder: MessageBuilder) -> Result<(), Error> {
    let socket = send_netlink_req(builder)?;
    loop {
        let (response, _) = socket.recv_from_full()?;
        for frame in MessageIter::new(&response) {
            let (header, payload) = frame?;
            if header.message_type == NLMSG_ERROR {
                return match netlink_error_code(payload)? {
                    0 => Ok(()),
                    errno => Err(std::io::Error::from_raw_os_error(errno.abs()).into()),
                };
            }
            if header.message_type == NLMSG_DONE {
                return Ok(());
            }
        }
    }
}

fn message_request<T: NetlinkEncode>(
    message_type: u16,
    flags: u16,
    message: &T,
) -> Result<MessageBuilder, Error> {
    let mut builder = MessageBuilder::new(message_type, flags);
    let mut message_bytes = Vec::new();
    message.write_to(&mut message_bytes)?;
    builder.append_bytes(&message_bytes);
    Ok(builder)
}

fn receive_netlink_dump<T: NetlinkDecode>(builder: MessageBuilder) -> Result<Vec<T>, Error> {
    let socket = send_netlink_req(builder)?;
    let mut messages = Vec::new();

    loop {
        let (response, _) = socket.recv_from_full()?;
        for frame in MessageIter::new(&response) {
            let (header, payload) = frame?;
            if header.flags & NLM_F_DUMP_INTR != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "netlink dump was interrupted",
                )
                .into());
            }
            if header.message_type == NLMSG_DONE {
                return Ok(messages);
            }
            if header.message_type == NLMSG_ERROR {
                let error = netlink_error_code(payload)?;
                if error == 0 {
                    continue;
                }
                return Err(std::io::Error::from_raw_os_error(error.abs()).into());
            }
            if header.message_type == T::MESSAGE_TYPE {
                messages.push(T::from_bytes(payload)?);
            }
        }
    }
}

fn dump_netlink_messages<T: NetlinkDecode>(
    message_type: u16,
    dump_header: &[u8],
) -> Result<Vec<T>, Error> {
    let mut builder = MessageBuilder::new(message_type, NLM_F_REQUEST | NLM_F_DUMP);
    builder.append_bytes(dump_header);
    receive_netlink_dump(builder)
}

pub struct NetlinkIfConfiger {}

impl NetlinkIfConfiger {
    pub(crate) fn get_interface_index(name: &str) -> Result<u32, Error> {
        let name = CString::new(name).with_context(|| "failed to convert interface name")?;
        match unsafe { libc::if_nametoindex(name.as_ptr()) } {
            0 => Err(std::io::Error::last_os_error().into()),
            n => Ok(n),
        }
    }

    fn get_prefix_len(name: &str, ip: Ipv4Addr) -> Result<u8, Error> {
        let addrs = Self::list_addresses(name)?;
        for addr in addrs {
            if addr.address() == IpAddr::V4(ip) {
                return Ok(addr.network_length());
            }
        }
        Err(Error::NotFound)
    }

    fn remove_one_ip(name: &str, ip: Ipv4Addr, prefix_len: u8) -> Result<(), Error> {
        let message = AddressMessage::new(
            libc::AF_INET as u8,
            Self::get_interface_index(name)?,
            prefix_len,
            IpAddr::V4(ip),
        );
        let request = message_request(RTM_DELADDR, NLM_F_ACK | NLM_F_REQUEST, &message)?;
        send_netlink_req_and_wait_ack(request)
    }

    fn get_prefix_len_ipv6(name: &str, ip: Ipv6Addr) -> Result<u8, Error> {
        let addrs = Self::list_addresses(name)?;
        for addr in addrs {
            if addr.address() == IpAddr::V6(ip) {
                return Ok(addr.network_length());
            }
        }
        Err(Error::NotFound)
    }

    fn remove_one_ipv6(name: &str, ip: Ipv6Addr, prefix_len: u8) -> Result<(), Error> {
        let message = AddressMessage::new(
            libc::AF_INET6 as u8,
            Self::get_interface_index(name)?,
            prefix_len,
            IpAddr::V6(ip),
        );
        let request = message_request(RTM_DELADDR, NLM_F_ACK | NLM_F_REQUEST, &message)?;
        send_netlink_req_and_wait_ack(request)
    }

    pub(crate) fn mtu_op<T: TryInto<Ioctl>>(
        name: &str,
        op: T,
        value: libc::c_int,
    ) -> Result<u32, Error>
    where
        <T as TryInto<Ioctl>>::Error: Debug,
    {
        let dummy_socket = dummy_socket()?;

        let mut ifr: ifreq = build_ifreq(name);

        unsafe {
            ifr.ifr_ifru.ifru_mtu = value;

            // 使用ioctl获取MTU
            if ioctl(dummy_socket.as_raw_fd(), op.try_into().unwrap(), &ifr) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu as u32 })
    }

    #[cfg(test)]
    fn mtu(name: &str) -> Result<u32, Error> {
        Self::mtu_op(name, SIOCGIFMTU, 0)
    }

    pub fn list_addresses(name: &str) -> Result<Vec<IpInet>, Error> {
        let mut result = vec![];

        for interface in getifaddrs()
            .with_context(|| "failed to call getifaddrs")?
            .filter(|x| x.interface_name == name)
        {
            let (Some(address), Some(netmask)) = (interface.address, interface.netmask) else {
                continue;
            };

            use nix::sys::socket::AddressFamily::{Inet, Inet6};

            let (address, netmask) = match (address.family(), netmask.family()) {
                (Some(Inet), Some(Inet)) => (
                    IpAddr::V4(address.as_sockaddr_in().unwrap().ip()),
                    IpAddr::V4(netmask.as_sockaddr_in().unwrap().ip()),
                ),
                (Some(Inet6), Some(Inet6)) => (
                    IpAddr::V6(address.as_sockaddr_in6().unwrap().ip()),
                    IpAddr::V6(netmask.as_sockaddr_in6().unwrap().ip()),
                ),
                (_, _) => continue,
            };

            let prefix = ip_mask_to_prefix(netmask).unwrap();

            result.push(IpInet::new(address, prefix).unwrap());
        }
        Ok(result)
    }

    pub(crate) fn set_flags_op<T: TryInto<Ioctl>>(
        name: &str,
        op: T,
        flags: InterfaceFlags,
    ) -> Result<InterfaceFlags, Error>
    where
        <T as TryInto<Ioctl>>::Error: Debug,
    {
        let mut req = build_ifreq(name);
        req.ifr_ifru.ifru_flags = flags.bits() as _;

        let socket = dummy_socket()?;

        unsafe {
            if ioctl(socket.as_raw_fd(), op.try_into().unwrap(), &req) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(InterfaceFlags::from_bits_truncate(
                req.ifr_ifru.ifru_flags as _,
            ))
        }
    }

    pub(crate) fn set_flags(name: &str, flags: InterfaceFlags) -> Result<InterfaceFlags, Error> {
        Self::set_flags_op(name, SIOCSIFFLAGS, flags)
    }

    pub(crate) fn get_flags(name: &str) -> Result<InterfaceFlags, Error> {
        Self::set_flags_op(name, SIOCGIFFLAGS, InterfaceFlags::empty())
    }

    fn list_route_messages(address_family: u8) -> Result<Vec<RouteMessage>, Error> {
        Ok(
            dump_netlink_messages::<RouteMessage>(RTM_GETROUTE, &RouteMessage::dump_header())?
                .into_iter()
                .filter(|message| message.family() == address_family)
                .collect(),
        )
    }

    pub(crate) fn list_routes() -> Result<Vec<RouteMessage>, Error> {
        Self::list_route_messages(libc::AF_INET as u8)
    }

    pub(crate) fn list_ipv6_route_messages() -> Result<Vec<RouteMessage>, Error> {
        Self::list_route_messages(libc::AF_INET6 as u8)
    }

    /// Resolve the route for `dest` (route get semantics) and return the next-hop IP
    /// (gateway if present, else `dest` itself for on-link) and egress interface index.
    fn route_get(dest: IpAddr) -> Result<(IpAddr, Option<u32>), Error> {
        let (address_family, dst_prefix, dst_addr) = match dest {
            IpAddr::V4(ip) => (AddressFamily::Inet, 32u8, RouteAddress::Inet(ip)),
            IpAddr::V6(ip) => (AddressFamily::Inet6, 128u8, RouteAddress::Inet6(ip)),
        };

        let mut message = RouteMessage::default();
        message.header.address_family = address_family;
        message.header.destination_prefix_length = dst_prefix;
        message
            .attributes
            .push(RouteAttribute::Destination(dst_addr));

        let s = send_netlink_req(RouteNetlinkMessage::GetRoute(message), NLM_F_REQUEST)?;

        let mut resp = Vec::<u8>::new();
        loop {
            if resp.is_empty() {
                let (new_resp, _) = s.recv_from_full()?;
                resp = new_resp;
            }
            let ret = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp)
                .with_context(|| "Failed to deserialize netlink route-get message")?;
            resp = resp.split_off(ret.buffer_len());

            match ret.payload {
                NetlinkPayload::Error(e) => {
                    if e.code == NonZero::new(0) {
                        continue;
                    } else {
                        return Err(e.to_io().into());
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(m)) => {
                    let mut gateway = None;
                    let mut ifindex = None;
                    for attr in m.attributes {
                        match attr {
                            RouteAttribute::Gateway(addr) => gateway = addr_to_ip(addr),
                            RouteAttribute::Oif(i) => ifindex = Some(i),
                            _ => {}
                        }
                    }
                    // Gateway present -> off-link, next hop is the gateway.
                    // Otherwise the destination is directly reachable (on-link).
                    return Ok((gateway.unwrap_or(dest), ifindex));
                }
                NetlinkPayload::Done(_) => break,
                p => {
                    tracing::error!("Unexpected netlink route-get response: {:?}", p);
                    return Err(anyhow::anyhow!("Unexpected netlink route-get response").into());
                }
            }
        }

        Err(anyhow::anyhow!("no route to {dest}").into())
    }

    /// Dump the neighbour (ARP/NDP) cache for `address_family` without the Proxy filter.
    fn dump_neighbours(address_family: AddressFamily) -> Result<Vec<NeighbourMessage>, Error> {
        let mut message = NeighbourMessage::default();
        message.header.family = address_family;

        let s = send_netlink_req(
            RouteNetlinkMessage::GetNeighbour(message),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;

        let mut ret_vec = vec![];
        let mut resp = Vec::<u8>::new();
        loop {
            if resp.is_empty() {
                let (new_resp, _) = s.recv_from_full()?;
                resp = new_resp;
            }
            let ret = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&resp)
                .with_context(|| "Failed to deserialize netlink neighbour message")?;
            resp = resp.split_off(ret.buffer_len());

            match ret.payload {
                NetlinkPayload::Error(e) => {
                    if e.code == NonZero::new(0) {
                        continue;
                    } else {
                        return Err(e.to_io().into());
                    }
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(m)) => {
                    ret_vec.push(m);
                }
                NetlinkPayload::Done(_) => break,
                p => {
                    tracing::error!("Unexpected netlink neighbour response: {:?}", p);
                    return Err(anyhow::anyhow!("Unexpected netlink neighbour response").into());
                }
            }
        }

        Ok(ret_vec)
    }

    /// Look up the link-layer (MAC) address of the next hop toward `dest`.
    ///
    /// After a successful TCP `connect()`, the kernel has already resolved the next hop via
    /// ARP/NDP, so its entry is present in the neighbour cache. Works for both IPv4 and IPv6.
    pub(crate) fn get_next_hop_mac(dest: IpAddr) -> Result<Option<[u8; 6]>, Error> {
        let (next_hop, oif) = Self::route_get(dest)?;
        let address_family = match next_hop {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        };

        for msg in Self::dump_neighbours(address_family)? {
            if let Some(oif) = oif
                && msg.header.ifindex != oif
            {
                continue;
            }
            // Skip entries whose MAC is not resolvable.
            if matches!(
                msg.header.state,
                NeighbourState::Incomplete | NeighbourState::Failed | NeighbourState::None
            ) {
                continue;
            }

            let mut dst_match = false;
            let mut mac: Option<[u8; 6]> = None;
            for attr in &msg.attributes {
                match attr {
                    NeighbourAttribute::Destination(NeighbourAddress::Inet(ip))
                        if IpAddr::V4(*ip) == next_hop =>
                    {
                        dst_match = true;
                    }
                    NeighbourAttribute::Destination(NeighbourAddress::Inet6(ip))
                        if IpAddr::V6(*ip) == next_hop =>
                    {
                        dst_match = true;
                    }
                    NeighbourAttribute::LinkLocalAddress(bytes) if bytes.len() == 6 => {
                        mac = Some([
                            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
                        ]);
                    }
                    _ => {}
                }
            }

            if dst_match {
                if let Some(mac) = mac {
                    return Ok(Some(mac));
                }
            }
        }

        Ok(None)
    }

    fn ipv6_ndp_proxy_message(name: &str, address: Ipv6Addr) -> Result<NeighborMessage, Error> {
        Ok(NeighborMessage::proxy(
            Self::get_interface_index(name)?,
            address,
        ))
    }

    pub(crate) fn add_ipv6_ndp_proxy(name: &str, address: Ipv6Addr) -> Result<(), Error> {
        let message = Self::ipv6_ndp_proxy_message(name, address)?;
        let request = message_request(
            RTM_NEWNEIGH,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST,
            &message,
        )?;
        send_netlink_req_and_wait_ack(request)
    }

    pub(crate) fn remove_ipv6_ndp_proxy(name: &str, address: Ipv6Addr) -> Result<(), Error> {
        let message = Self::ipv6_ndp_proxy_message(name, address)?;
        let request = message_request(RTM_DELNEIGH, NLM_F_ACK | NLM_F_REQUEST, &message)?;
        send_netlink_req_and_wait_ack(request)
    }

    fn list_neighbour_messages(address_family: u8) -> Result<Vec<NeighborMessage>, Error> {
        let mut builder = MessageBuilder::new(RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP);
        builder.append_bytes(&NeighborMessage::proxy_dump_header(address_family));
        receive_netlink_dump(builder)
    }

    pub(crate) fn list_ipv6_ndp_proxy(name: &str) -> Result<BTreeSet<Ipv6Addr>, Error> {
        let ifindex = Self::get_interface_index(name)?;
        Ok(Self::list_neighbour_messages(libc::AF_INET6 as u8)?
            .into_iter()
            .filter(|message| message.ifindex() == ifindex && message.is_proxy())
            .filter_map(|message| match message.destination() {
                Some(IpAddr::V6(address)) => Some(*address),
                _ => None,
            })
            .collect())
    }
}

#[async_trait]
impl IfConfiguerTrait for NetlinkIfConfiger {
    async fn add_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let message = RouteMessageBuilder::new(libc::AF_INET as u8)
            .destination(IpAddr::V4(address), cidr_prefix)
            .oif(Self::get_interface_index(name)?)
            .priority(cost.unwrap_or(65535) as u32)
            .table(libc::RT_TABLE_MAIN.into())
            .static_protocol()
            .universe_scope()
            .route_type(RouteType::Unicast)
            .build();
        let request = message_request(
            RTM_NEWROUTE,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST,
            &message,
        )?;
        send_netlink_req_and_wait_ack(request)
    }

    async fn remove_ipv4_route(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let routes = Self::list_routes()?;
        let ifidx = NetlinkIfConfiger::get_interface_index(name)?;

        for msg in routes {
            let destination = msg
                .destination()
                .copied()
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            if destination == IpAddr::V4(address)
                && msg.dst_len() == cidr_prefix
                && msg.oif() == Some(ifidx)
            {
                let request = message_request(RTM_DELROUTE, NLM_F_ACK | NLM_F_REQUEST, &msg)?;
                send_netlink_req_and_wait_ack(request)?;
                return Ok(());
            }
        }

        Ok(())
    }

    async fn add_ipv4_ip(
        &self,
        name: &str,
        address: Ipv4Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let broadcast = if cidr_prefix == 32 {
            address
        } else {
            let ip_addr = u32::from(address);
            Ipv4Addr::from((0xffff_ffff_u32) >> u32::from(cidr_prefix) | ip_addr)
        };
        let message = AddressMessage::new(
            libc::AF_INET as u8,
            Self::get_interface_index(name)?,
            cidr_prefix,
            IpAddr::V4(address),
        )
        .local(IpAddr::V4(address))
        .broadcast(broadcast);
        let request = message_request(
            RTM_NEWADDR,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST,
            &message,
        )?;
        send_netlink_req_and_wait_ack(request)
    }

    async fn set_link_status(&self, name: &str, up: bool) -> Result<(), Error> {
        let mut flags = Self::get_flags(name)?;
        flags.set(InterfaceFlags::IFF_UP, up);
        Self::set_flags(name, flags)?;
        Ok(())
    }

    async fn remove_ip(&self, name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        if let Some(ip) = ip {
            let prefix_len = Self::get_prefix_len(name, ip.address())?;
            Self::remove_one_ip(name, ip.address(), prefix_len)?;
        } else {
            let addrs = Self::list_addresses(name)?;
            for addr in addrs {
                if let IpAddr::V4(ipv4) = addr.address() {
                    Self::remove_one_ip(name, ipv4, addr.network_length())?;
                }
            }
        }

        Ok(())
    }

    async fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), Error> {
        Self::mtu_op(name, SIOCSIFMTU, mtu as libc::c_int)?;

        Ok(())
    }

    async fn add_ipv6_ip(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let message = AddressMessage::new(
            libc::AF_INET6 as u8,
            Self::get_interface_index(name)?,
            cidr_prefix,
            IpAddr::V6(address),
        );
        let request = message_request(
            RTM_NEWADDR,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST,
            &message,
        )?;
        send_netlink_req_and_wait_ack(request)
    }

    async fn remove_ipv6(&self, name: &str, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        if let Some(ipv6) = ip {
            let prefix_len = Self::get_prefix_len_ipv6(name, ipv6.address())?;
            Self::remove_one_ipv6(name, ipv6.address(), prefix_len)?;
        } else {
            let addrs = Self::list_addresses(name)?;
            for addr in addrs {
                if let IpAddr::V6(ipv6) = addr.address() {
                    let prefix_len = addr.network_length();
                    Self::remove_one_ipv6(name, ipv6, prefix_len)?;
                }
            }
        }

        Ok(())
    }

    async fn add_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let mut builder = RouteMessageBuilder::new(libc::AF_INET6 as u8)
            .oif(Self::get_interface_index(name)?)
            .priority(cost.unwrap_or(65535) as u32)
            .table(libc::RT_TABLE_MAIN.into())
            .static_protocol()
            .universe_scope()
            .route_type(RouteType::Unicast);
        if cidr_prefix != 0 {
            builder = builder.destination(IpAddr::V6(address), cidr_prefix);
        }
        let message = builder.build();
        let request = message_request(
            RTM_NEWROUTE,
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL | NLM_F_REQUEST,
            &message,
        )?;
        send_netlink_req_and_wait_ack(request)
    }

    async fn remove_ipv6_route(
        &self,
        name: &str,
        address: std::net::Ipv6Addr,
        cidr_prefix: u8,
    ) -> Result<(), Error> {
        let routes = Self::list_route_messages(libc::AF_INET6 as u8)?;
        let ifidx = NetlinkIfConfiger::get_interface_index(name)?;

        for msg in routes {
            let destination = msg
                .destination()
                .copied()
                .unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
            if destination == IpAddr::V6(address)
                && msg.dst_len() == cidr_prefix
                && msg.oif() == Some(ifidx)
            {
                let request = message_request(RTM_DELROUTE, NLM_F_ACK | NLM_F_REQUEST, &msg)?;
                send_netlink_req_and_wait_ack(request)?;
                return Ok(());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const DUMMY_IFACE_NAME: &str = "dummy";

    fn run_cmd(cmd: &str) -> String {
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .expect("failed to execute process");
        assert!(
            output.status.success(),
            "command failed: {cmd}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn run_ip(args: &[&str]) {
        let output = Command::new("ip")
            .args(args)
            .output()
            .expect("failed to execute ip process");
        assert!(
            output.status.success(),
            "ip command failed: {:?}\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn test_iface_name(tag: &str) -> String {
        format!("et{}{:x}", tag, std::process::id() & 0xffff)
    }

    struct ScopedDummyLink {
        name: String,
    }

    impl ScopedDummyLink {
        fn new(name: &str) -> Self {
            let _ = Command::new("ip").args(["link", "del", name]).output();
            run_ip(&["link", "add", name, "type", "dummy"]);
            run_ip(&["link", "set", name, "up"]);
            Self {
                name: name.to_string(),
            }
        }
    }

    impl Drop for ScopedDummyLink {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", &self.name])
                .output();
        }
    }

    struct PrepareEnv {}
    impl PrepareEnv {
        fn new() -> Self {
            let _ = Command::new("ip")
                .args(["link", "del", DUMMY_IFACE_NAME])
                .output();
            let _ = run_cmd(&format!("ip link add {} type dummy", DUMMY_IFACE_NAME));
            PrepareEnv {}
        }
    }

    impl Drop for PrepareEnv {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["link", "del", DUMMY_IFACE_NAME])
                .output();
        }
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn addr_test() {
        let _prepare_env = PrepareEnv::new();
        let ifcfg = NetlinkIfConfiger {};
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        ifcfg
            .add_ipv4_ip(DUMMY_IFACE_NAME, "10.44.44.4".parse().unwrap(), 24)
            .await
            .unwrap();

        let addrs = NetlinkIfConfiger::list_addresses(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(
            addrs[0].address(),
            IpAddr::V4("10.44.44.4".parse().unwrap())
        );
        assert_eq!(addrs[0].network_length(), 24);

        NetlinkIfConfiger::remove_one_ip(DUMMY_IFACE_NAME, "10.44.44.4".parse().unwrap(), 24)
            .unwrap();

        let addrs = NetlinkIfConfiger::list_addresses(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(addrs.len(), 0);

        let old_mtu = NetlinkIfConfiger::mtu(DUMMY_IFACE_NAME).unwrap();
        assert_ne!(old_mtu, 0);

        let new_mtu = old_mtu + 1;
        ifcfg.set_mtu(DUMMY_IFACE_NAME, new_mtu).await.unwrap();

        let mtu = NetlinkIfConfiger::mtu(DUMMY_IFACE_NAME).unwrap();
        assert_eq!(mtu, new_mtu);

        ifcfg
            .set_link_status(DUMMY_IFACE_NAME, false)
            .await
            .unwrap();
        ifcfg.set_link_status(DUMMY_IFACE_NAME, true).await.unwrap();
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn route_test() {
        let _prepare_env = PrepareEnv::new();
        let ret = NetlinkIfConfiger::list_routes().unwrap();

        let ifcfg = NetlinkIfConfiger {};
        println!("{:?}", ret);

        ifcfg.set_link_status(DUMMY_IFACE_NAME, true).await.unwrap();

        ifcfg
            .add_ipv4_route(DUMMY_IFACE_NAME, "10.5.5.0".parse().unwrap(), 24, None)
            .await
            .unwrap();

        let routes = NetlinkIfConfiger::list_routes()
            .unwrap()
            .into_iter()
            .filter_map(|route| route.destination().copied())
            .collect::<Vec<_>>();
        assert!(routes.contains(&IpAddr::V4("10.5.5.0".parse().unwrap())));

        ifcfg
            .remove_ipv4_route(DUMMY_IFACE_NAME, "10.5.5.0".parse().unwrap(), 24)
            .await
            .unwrap();
        let routes = NetlinkIfConfiger::list_routes()
            .unwrap()
            .into_iter()
            .filter_map(|route| route.destination().copied())
            .collect::<Vec<_>>();
        assert!(!routes.contains(&IpAddr::V4("10.5.5.0".parse().unwrap())));
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn ipv6_addr_readback_test() {
        let iface = test_iface_name("a");
        let _link = ScopedDummyLink::new(&iface);
        run_ip(&["-6", "addr", "add", "2001:db8:1234::2/64", "dev", &iface]);

        let addrs = NetlinkIfConfiger::list_addresses(&iface).unwrap();
        assert!(addrs.iter().any(|addr| {
            addr.address() == IpAddr::V6("2001:db8:1234::2".parse().unwrap())
                && addr.network_length() == 64
        }));
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn ipv6_route_readback_test() {
        let wan_if = test_iface_name("rw");
        let lan_if = test_iface_name("rl");
        let _wan = ScopedDummyLink::new(&wan_if);
        let _lan = ScopedDummyLink::new(&lan_if);
        run_ip(&[
            "-6",
            "addr",
            "add",
            "2001:db8:100:ffff::2/64",
            "dev",
            &wan_if,
        ]);
        run_ip(&[
            "-6",
            "route",
            "add",
            "default",
            "from",
            "2001:db8:100::/56",
            "dev",
            &wan_if,
        ]);
        run_ip(&["-6", "route", "add", "2001:db8:100::/56", "dev", &lan_if]);

        let wan_ifindex = NetlinkIfConfiger::get_interface_index(&wan_if).unwrap();
        let lan_ifindex = NetlinkIfConfiger::get_interface_index(&lan_if).unwrap();
        let routes = NetlinkIfConfiger::list_ipv6_route_messages().unwrap();

        assert!(routes.iter().any(|route| {
            route.route_type() == RouteType::Unicast
                && route.src_len() == 56
                && route.source()
                    == Some(&IpAddr::V6(
                        "2001:db8:100::".parse::<std::net::Ipv6Addr>().unwrap(),
                    ))
                && route.oif() == Some(wan_ifindex)
                && route.destination().is_none()
        }));

        assert!(routes.iter().any(|route| {
            route.route_type() == RouteType::Unicast
                && route.dst_len() == 56
                && route.destination()
                    == Some(&IpAddr::V6(
                        "2001:db8:100::".parse::<std::net::Ipv6Addr>().unwrap(),
                    ))
                && route.oif() == Some(lan_ifindex)
        }));
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn ipv6_route_remove_test() {
        let iface = test_iface_name("rr");
        let _link = ScopedDummyLink::new(&iface);
        let ifcfg = NetlinkIfConfiger {};
        let route_addr = "2001:db8:200::".parse::<std::net::Ipv6Addr>().unwrap();

        ifcfg
            .add_ipv6_route(&iface, route_addr, 56, None)
            .await
            .unwrap();

        let ifindex = NetlinkIfConfiger::get_interface_index(&iface).unwrap();
        let has_route = |routes: &[RouteMessage]| {
            routes.iter().any(|route| {
                route.dst_len() == 56
                    && route.destination() == Some(&IpAddr::V6(route_addr))
                    && route.oif() == Some(ifindex)
            })
        };

        let routes = NetlinkIfConfiger::list_ipv6_route_messages().unwrap();
        assert!(has_route(&routes));

        ifcfg
            .remove_ipv6_route(&iface, route_addr, 56)
            .await
            .unwrap();

        let routes = NetlinkIfConfiger::list_ipv6_route_messages().unwrap();
        assert!(!has_route(&routes));
    }
}
