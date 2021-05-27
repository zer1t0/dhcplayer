use super::err::{Error, IResult};
use super::helpers::{parse_ipv4, parse_utf8};
use nom::bytes::complete::take;
use nom::multi::many0;
use nom::number::complete::{be_u32, be_u8};
use std::{fmt::Display, net::Ipv4Addr};

#[derive(PartialEq, Debug)]
pub enum DhcpOption {
    BroadcastAddress(Ipv4Addr),
    ClientFqdn(ClientFqdn),
    DhcpMsgType(u8),
    DhcpServerId(Ipv4Addr),
    DomainName(String),
    DomainServer(Vec<Ipv4Addr>),
    HostName(String),
    IpAddressLeaseTime(u32),
    Message(String),
    NameServer(Vec<Ipv4Addr>),
    NetbiosNameServer(Vec<Ipv4Addr>),
    ParameterRequestList(Vec<u8>),
    RequestedIpAddress(Ipv4Addr),
    RenewalTime(u32),
    RebindingTime(u32),
    Router(Vec<Ipv4Addr>),
    SubnetMask(Ipv4Addr),
    WPAD(String),
    Unrecognized(RawDhcpOption),
}

impl DhcpOption {
    pub fn parse(input: &[u8]) -> IResult<&[u8], DhcpOption> {
        let (input, code) = be_u8(input)?;
        assert!(code != DhcpOptions::END);

        let (input, len) = be_u8(input)?;
        let (input, data) = take(len)(input)?;
        let option = match code {
            DhcpOptions::BROADCAST_ADDRESS => {
                DhcpOption::BroadcastAddress(parse_ipv4(data)?.1)
            }
            DhcpOptions::CLIENT_FQDN => DhcpOption::ClientFqdn(
                ClientFqdn::parse(data).map_err(|e| nom::Err::Error(e))?,
            ),
            DhcpOptions::DHCP_MSG_TYPE => {
                DhcpOption::DhcpMsgType(be_u8(data)?.1)
            }
            DhcpOptions::DHCP_SERVER_ID => {
                DhcpOption::DhcpServerId(parse_ipv4(data)?.1)
            }
            DhcpOptions::DOMAIN_NAME => DhcpOption::DomainName(
                parse_utf8(data).map_err(|e| nom::Err::Error(e))?,
            ),
            DhcpOptions::DOMAIN_SERVER => {
                DhcpOption::DomainServer(many0(parse_ipv4)(data)?.1)
            }
            DhcpOptions::HOSTNAME => DhcpOption::HostName(
                parse_utf8(data).map_err(|e| nom::Err::Error(e))?,
            ),
            DhcpOptions::IP_ADDRESS_LEASE_TIME => {
                DhcpOption::IpAddressLeaseTime(be_u32(data)?.1)
            }
            DhcpOptions::MESSAGE => DhcpOption::Message(
                parse_utf8(data).map_err(|e| nom::Err::Error(e))?,
            ),
            DhcpOptions::NAME_SERVER => {
                DhcpOption::NameServer(many0(parse_ipv4)(data)?.1)
            }
            DhcpOptions::NETBIOS_NAME_SERVER => {
                DhcpOption::NetbiosNameServer(many0(parse_ipv4)(data)?.1)
            }
            DhcpOptions::PARAMETER_REQUEST_LIST => {
                DhcpOption::ParameterRequestList(data.to_vec())
            }
            DhcpOptions::REBINDING_TIME => {
                DhcpOption::RebindingTime(be_u32(data)?.1)
            }
            DhcpOptions::RENEWAL_TIME => {
                DhcpOption::RenewalTime(be_u32(data)?.1)
            }
            DhcpOptions::REQUESTED_IP_ADDRESS => {
                DhcpOption::RequestedIpAddress(parse_ipv4(data)?.1)
            }
            DhcpOptions::ROUTER => {
                DhcpOption::Router(many0(parse_ipv4)(data)?.1)
            }
            DhcpOptions::SUBNET_MASK => {
                DhcpOption::SubnetMask(parse_ipv4(data)?.1)
            }
            DhcpOptions::WPAD => DhcpOption::WPAD(
                parse_utf8(data).map_err(|e| nom::Err::Error(e))?,
            ),
            _ => DhcpOption::Unrecognized(RawDhcpOption {
                code,
                data: data.to_vec(),
            }),
        };
        Ok((input, option))
    }

    pub fn to_raw(&self) -> RawDhcpOption {
        match self {
            Self::BroadcastAddress(addr) => RawDhcpOption {
                code: DhcpOptions::BROADCAST_ADDRESS,
                data: addr.octets().to_vec(),
            },
            Self::ClientFqdn(cf) => RawDhcpOption {
                code: DhcpOptions::CLIENT_FQDN,
                data: cf.build(),
            },
            Self::DhcpMsgType(mtype) => RawDhcpOption {
                code: DhcpOptions::DHCP_MSG_TYPE,
                data: vec![*mtype as u8],
            },
            Self::DhcpServerId(addr) => RawDhcpOption {
                code: DhcpOptions::DHCP_SERVER_ID,
                data: addr.octets().to_vec(),
            },
            Self::DomainName(name) => RawDhcpOption {
                code: DhcpOptions::DOMAIN_NAME,
                data: name.as_bytes().to_vec(),
            },
            Self::DomainServer(addrs) => {
                RawDhcpOption::from_addrs(DhcpOptions::DOMAIN_SERVER, addrs)
            }
            Self::HostName(name) => RawDhcpOption {
                code: DhcpOptions::HOSTNAME,
                data: name.as_bytes().to_vec(),
            },
            Self::IpAddressLeaseTime(secs) => RawDhcpOption {
                code: DhcpOptions::IP_ADDRESS_LEASE_TIME,
                data: secs.to_be_bytes().to_vec(),
            },
            Self::Message(msg) => RawDhcpOption {
                code: DhcpOptions::MESSAGE,
                data: msg.as_bytes().to_vec(),
            },
            Self::NameServer(addrs) => {
                RawDhcpOption::from_addrs(DhcpOptions::NAME_SERVER, addrs)
            }
            Self::NetbiosNameServer(addrs) => RawDhcpOption::from_addrs(
                DhcpOptions::NETBIOS_NAME_SERVER,
                addrs,
            ),
            Self::ParameterRequestList(prl) => RawDhcpOption {
                code: DhcpOptions::PARAMETER_REQUEST_LIST,
                data: prl.clone(),
            },
            Self::RequestedIpAddress(addr) => RawDhcpOption {
                code: DhcpOptions::REQUESTED_IP_ADDRESS,
                data: addr.octets().to_vec(),
            },
            Self::RenewalTime(secs) => RawDhcpOption {
                code: DhcpOptions::RENEWAL_TIME,
                data: secs.to_be_bytes().to_vec(),
            },
            Self::RebindingTime(secs) => RawDhcpOption {
                code: DhcpOptions::REBINDING_TIME,
                data: secs.to_be_bytes().to_vec(),
            },
            Self::Router(addrs) => {
                RawDhcpOption::from_addrs(DhcpOptions::ROUTER, addrs)
            }
            Self::SubnetMask(mask) => RawDhcpOption {
                code: DhcpOptions::SUBNET_MASK,
                data: mask.octets().to_vec(),
            },
            Self::WPAD(url) => RawDhcpOption {
                code: DhcpOptions::WPAD,
                data: url.as_bytes().to_vec(),
            },
            Self::Unrecognized(raw) => raw.clone(),
        }
    }

    pub fn value_str(&self) -> String {
        match self {
            Self::BroadcastAddress(addr) => format!("{}", addr),
            Self::ClientFqdn(cf) => format!("{:?}", cf),
            Self::DhcpMsgType(mtype) => {
                format!(
                    "{} {}",
                    mtype,
                    DhcpMessageTypes::name(*mtype).unwrap_or("Unknown")
                )
            }
            Self::DhcpServerId(addr) => format!("{}", addr),
            Self::DomainName(name) => format!("{}", name),
            Self::DomainServer(addrs) => join(addrs, ","),
            Self::HostName(name) => format!("{}", name),
            Self::IpAddressLeaseTime(secs) => format!("{}", secs),
            Self::Message(msg) => format!("{}", msg),
            Self::NameServer(addrs) => join(addrs, ","),
            Self::NetbiosNameServer(addrs) => join(addrs, ","),
            Self::ParameterRequestList(prl) => join(prl, ","),
            Self::RequestedIpAddress(addr) => format!("{}", addr),
            Self::RenewalTime(secs) => format!("{}", secs),
            Self::RebindingTime(secs) => format!("{}", secs),
            Self::Router(addrs) => join(addrs, ","),
            Self::SubnetMask(mask) => format!("{}", mask),
            Self::WPAD(url) => format!("{}", url),
            Self::Unrecognized(raw) => format!("{:?}", raw.data),
        }
    }

    pub fn code(&self) -> u8 {
        return self.to_raw().code;
    }

    pub fn name(&self) -> Option<&'static str> {
        return DhcpOptions::name(self.code());
    }

    pub fn build(&self) -> Vec<u8> {
        return self.to_raw().build();
    }
}

pub fn join<I: Display>(v: &Vec<I>, separator: &str) -> String {
    v.into_iter()
        .map(|e| e.to_string())
        .collect::<Vec<String>>()
        .join(separator)
}

#[derive(PartialEq, Clone, Debug)]
pub struct RawDhcpOption {
    pub code: u8,
    pub data: Vec<u8>,
}

impl RawDhcpOption {
    pub fn from_addrs(code: u8, addrs: &Vec<Ipv4Addr>) -> Self {
        let mut data = Vec::new();
        for a in addrs {
            data.extend(a.octets().iter());
        }

        return Self { code, data };
    }

    pub fn build(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(self.code);
        raw.push(self.data.len() as u8);
        raw.extend(&self.data);

        return raw;
    }
}

/// Defined in https://datatracker.ietf.org/doc/html/rfc4702
#[derive(PartialEq, Debug, Clone)]
pub struct ClientFqdn {
    pub flags: u8,
    pub aresult: u8,
    pub ptrresult: u8,
    pub name: String,
}

impl ClientFqdn {
    pub fn parse(input: &[u8]) -> Result<Self, Error<&[u8]>> {
        let (input, flags) = be_u8(input)?;
        let (input, aresult) = be_u8(input)?;
        let (input, ptrresult) = be_u8(input)?;

        let name = parse_utf8(input)?;

        return Ok(Self {
            flags,
            aresult,
            ptrresult,
            name,
        });
    }

    pub fn build(&self) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.push(self.flags);
        raw.push(self.aresult);
        raw.push(self.ptrresult);
        raw.extend(self.name.as_bytes());

        return raw;
    }
}

#[allow(non_snake_case)]
pub mod DhcpOptions {

    pub const SUBNET_MASK: u8 = 1;

    pub const ROUTER: u8 = 3;

    pub const NAME_SERVER: u8 = 5;
    pub const DOMAIN_SERVER: u8 = 6;

    pub const HOSTNAME: u8 = 12;

    pub const DOMAIN_NAME: u8 = 15;

    pub const BROADCAST_ADDRESS: u8 = 28;

    pub const NETBIOS_NAME_SERVER: u8 = 44;

    pub const REQUESTED_IP_ADDRESS: u8 = 50;
    pub const IP_ADDRESS_LEASE_TIME: u8 = 51;

    pub const DHCP_MSG_TYPE: u8 = 53;
    pub const DHCP_SERVER_ID: u8 = 54;
    pub const PARAMETER_REQUEST_LIST: u8 = 55;
    pub const MESSAGE: u8 = 56;

    pub const RENEWAL_TIME: u8 = 58;
    pub const REBINDING_TIME: u8 = 59;

    pub const CLIENT_FQDN: u8 = 81;

    pub const WPAD: u8 = 252;

    pub const END: u8 = 255;

    pub fn name(code: u8) -> Option<&'static str> {
        match code {
            SUBNET_MASK => Some("Subnet Mask"),
            ROUTER => Some("Router"),
            DOMAIN_SERVER => Some("Domain Server"),
            HOSTNAME => Some("Hostname"),
            DOMAIN_NAME => Some("Domain Name"),
            BROADCAST_ADDRESS => Some("Broadcast Address"),
            NAME_SERVER => Some("Name Server"),
            NETBIOS_NAME_SERVER => Some("NetBIOS Name Server"),
            REQUESTED_IP_ADDRESS => Some("Requested IP Address"),
            IP_ADDRESS_LEASE_TIME => Some("IP Address Lease Time"),
            DHCP_MSG_TYPE => Some("DHCP Message Type"),
            DHCP_SERVER_ID => Some("DHCP Server ID"),
            PARAMETER_REQUEST_LIST => Some("Parameter Request List"),
            MESSAGE => Some("Message"),
            RENEWAL_TIME => Some("Renewal Time"),
            REBINDING_TIME => Some("Rebinding Time"),
            CLIENT_FQDN => Some("Client FQDN"),
            WPAD => Some("WPAD"),
            _ => None,
        }
    }
}

// DHCP Options;

#[allow(non_snake_case)]
pub mod DhcpMessageTypes {
    /// Client broadcast to locate available servers.
    pub const DISCOVER: u8 = 1;

    /// Server to client in response to DHCPDISCOVER with offer of
    /// configuration parameters.
    pub const OFFER: u8 = 2;

    /// Client message to servers either (a) requesting offered parameters
    /// from one server and
    /// implicitly declining offers from all others, (b) confirming correctness
    /// of previously
    /// allocated address after, e.g., system reboot, or (c) extending the
    /// lease on a particular
    /// network address.
    pub const REQUEST: u8 = 3;

    /// Client to server indicating network address is already in use.
    pub const DECLINE: u8 = 4;

    /// Server to client with configuration parameters, including committed
    /// network address.
    pub const ACK: u8 = 5;

    /// Server to client indicating client's notion of network address is
    /// incorrect (e.g., client
    /// has moved to new subnet) or client's lease as expired.
    pub const NAK: u8 = 6;

    /// Client to server relinquishing network address and cancelling remaining
    /// lease.
    pub const RELEASE: u8 = 7;

    /// Client to server, asking only for local configuration parameters;
    /// client already has
    /// externally configured network address.
    pub const INFORM: u8 = 8;

    pub fn name(msg_type: u8) -> Option<&'static str> {
        match msg_type {
            DISCOVER => Some("Discover"),
            OFFER => Some("Offer"),
            REQUEST => Some("Request"),
            DECLINE => Some("Decline"),
            ACK => Some("Ack"),
            NAK => Some("Nak"),
            RELEASE => Some("Release"),
            INFORM => Some("Inform"),
            _ => None,
        }
    }
}
