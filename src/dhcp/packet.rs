use super::{ClientFqdn, err::IResult};
use super::helpers::{parse_ipv4, parse_mac};
use super::options::{DhcpOption, DhcpOptions};
use nom::bytes::complete::{tag, take};
use nom::multi::many_till;
use nom::number::complete::{be_u16, be_u32, be_u8};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

pub const BROADCAST_FLAG: u16 = 0x8000;

const DHCP_COOKIE: [u8; 4] = [99, 130, 83, 99];

#[derive(Debug)]
pub struct DhcpPacket {
    /// Message op code.
    pub op: u8,

    /// Client sets to zero, optionally used by relay agents
    /// when booting via a relay agent.
    pub hops: u8,

    /// Transaction ID, a random number chosen by the
    /// client, used by the client and server to associate
    /// messages and responses between a client and a
    /// server.
    pub xid: u32,

    /// Filled in by client, seconds elapsed since client
    /// began address acquisition or renewal process.
    pub secs: u16,

    /// Used to indicate if message is unicast or broadcast
    pub flags: u16,

    /// Client IP address; only filled in if client is in
    /// BOUND, RENEW or REBINDING state and can respond
    /// to ARP requests.
    pub ciaddr: Ipv4Addr,

    /// 'your' (client) IP address.
    pub yiaddr: Ipv4Addr,

    /// IP address of next server to use in bootstrap;
    /// returned in DHCPOFFER, DHCPACK by server.
    pub siaddr: Ipv4Addr,

    /// Relay agent IP address, used in booting via a
    /// relay agent.
    pub giaddr: Ipv4Addr,

    /// Client hardware address.
    pub chaddr: MacAddr,

    pub options: Vec<DhcpOption>,
}

pub const BOOT_REQUEST: u8 = 1; // From Client;
pub const BOOT_REPLY: u8 = 2; // From Server;

pub const ETHERNET_TYPE: u8 = 1;

pub const ETHERNET_ADDRESS_LEN: u8 = 6;

pub const DHCP_PACKET_MIN_SIZE: usize = 272;

macro_rules! get_option {
    ($fn:ident, $option:tt, $type:tt) => {
        pub fn $fn(&self) -> Option<$type> {
            for opt in &self.options {
                match opt {
                    DhcpOption::$option(t) => return Some(*t),
                    _ => {}
                }
            }
            return None;
        }
    };
}

macro_rules! get_option_ref {
    ($fn:ident, $option:tt, $type:path) => {
        pub fn $fn(&self) -> Option<&$type> {
            for opt in &self.options {
                match opt {
                    DhcpOption::$option(t) => return Some(t),
                    _ => {}
                }
            }
            return None;
        }
    };
}

macro_rules! add_option {
    ($fn:ident, $option:tt, $type:path) => {
        pub fn $fn(&mut self, val: $type) {
            self.options.push(DhcpOption::$option(val));
        }
    };
}

impl DhcpPacket {
    pub fn new_reply() -> Self {
        let mut p = Self::default();
        p.op = BOOT_REPLY;
        return p;
    }

    pub fn new_request() -> Self {
        let mut p = Self::default();
        p.op = BOOT_REQUEST;
        return p;
    }

    pub fn set_broadcast(&mut self) {
        self.flags = self.flags & BROADCAST_FLAG;
    }

    get_option!(dhcp_msg_type, DhcpMsgType, u8);
    get_option!(dhcp_server_id, DhcpServerId, Ipv4Addr);
    get_option_ref!(hostname, HostName, String);
    get_option_ref!(message, Message, String);
    get_option_ref!(parameter_request_list, ParameterRequestList, Vec<u8>);
    get_option!(requested_ip_address, RequestedIpAddress, Ipv4Addr);

    add_option!(add_broadcast_address, BroadcastAddress, Ipv4Addr);
    add_option!(add_client_fqdn, ClientFqdn, ClientFqdn);
    add_option!(add_dhcp_msg_type, DhcpMsgType, u8);
    add_option!(add_dhcp_server_id, DhcpServerId, Ipv4Addr);
    add_option!(add_domain_name, DomainName, String);
    add_option!(add_domain_server, DomainServer, Vec<Ipv4Addr>);
    add_option!(add_hostname, HostName, String);
    add_option!(add_ip_address_lease_time, IpAddressLeaseTime, u32);
    add_option!(add_message, Message, String);
    add_option!(add_netbios_name_server, NetbiosNameServer, Vec<Ipv4Addr>);
    add_option!(add_parameter_request_list, ParameterRequestList, Vec<u8>);
    add_option!(add_requested_ip_address, RequestedIpAddress, Ipv4Addr);
    add_option!(add_renewal_time, RenewalTime, u32);
    add_option!(add_rebinding_time, RebindingTime, u32);
    add_option!(add_router, Router, Vec<Ipv4Addr>);
    add_option!(add_subnet_mask, SubnetMask, Ipv4Addr);
    add_option!(add_wpad, WPAD, String);

    pub fn build(&self) -> Vec<u8> {
        let mut raw = Vec::new();

        raw.push(self.op);
        raw.push(ETHERNET_TYPE);
        raw.push(ETHERNET_ADDRESS_LEN);
        raw.push(self.hops);
        raw.extend(&self.xid.to_be_bytes());
        raw.extend(&self.secs.to_be_bytes());
        raw.extend(&self.flags.to_be_bytes());
        raw.extend(&self.ciaddr.octets());
        raw.extend(&self.yiaddr.octets());
        raw.extend(&self.siaddr.octets());
        raw.extend(&self.giaddr.octets());
        raw.extend(&self.chaddr.octets());
        raw.extend(&[0; 10]);
        raw.extend(&[0; 64]);
        raw.extend(&[0; 128]);

        raw.extend(&DHCP_COOKIE);

        for opt in &self.options {
            raw.extend(&opt.build());
        }

        raw.push(DhcpOptions::END);

        while raw.len() < DHCP_PACKET_MIN_SIZE {
            raw.push(0);
        }

        return raw;
    }

    pub fn parse(raw: &[u8]) -> IResult<&[u8], Self> {
        let (raw, op) = be_u8(raw)?;
        let (raw, _htype) = be_u8(raw)?;
        let (raw, _hlen) = be_u8(raw)?;
        let (raw, hops) = be_u8(raw)?;
        let (raw, xid) = be_u32(raw)?;
        let (raw, secs) = be_u16(raw)?;
        let (raw, flags) = be_u16(raw)?;
        let (raw, ciaddr) = parse_ipv4(raw)?;
        let (raw, yiaddr) = parse_ipv4(raw)?;
        let (raw, siaddr) = parse_ipv4(raw)?;
        let (raw, giaddr) = parse_ipv4(raw)?;
        let (raw, chaddr) = parse_mac(raw)?;
        let (raw, _chaddr_padding) = take(10u8)(raw)?;

        // Optional server host name, null terminated string.
        let (raw, _sname) = take(64u8)(raw)?;

        // Boot file name, null terminated string; "generic"
        // name or null in DHCPDISCOVER, fully qualified
        // directory-path name in DHCPOFFER.
        let (raw, _file) = take(128u8)(raw)?;

        let (raw, _) = tag(DHCP_COOKIE)(raw)?;

        let (raw, (options, _)) =
            many_till(DhcpOption::parse, tag(&[DhcpOptions::END]))(raw)?;

        return Ok((
            raw,
            Self {
                op,
                hops,
                xid,
                secs,
                flags,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr,
                options,
            },
        ));
    }
}

impl Default for DhcpPacket {
    fn default() -> Self {
        return DhcpPacket {
            op: BOOT_REPLY,
            hops: 0,
            xid: 0,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::from(0),
            yiaddr: Ipv4Addr::from(0),
            siaddr: Ipv4Addr::from(0),
            giaddr: Ipv4Addr::from(0),
            chaddr: MacAddr::new(0, 0, 0, 0, 0, 0),
            options: Vec::new(),
        };
    }
}
