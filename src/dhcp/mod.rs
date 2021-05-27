// Adapted from https://github.com/krolaw/dhcp4r

mod err;
mod helpers;
mod options;
mod packet;

pub use packet::DhcpPacket;
pub use options::{ClientFqdn, DhcpMessageTypes, DhcpOption, DhcpOptions};

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;
