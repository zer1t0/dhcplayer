use log::warn;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{self, MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use pnet::{
    datalink::{
        self, Channel, Config, DataLinkReceiver, DataLinkSender,
        NetworkInterface,
    },
    packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
};
use rand::Rng;
use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use crate::dhcp::DhcpPacket;

pub struct TransportChannel {
    tx: Box<dyn DataLinkSender>,
    rx: Box<dyn DataLinkReceiver>,
    timeout: Option<Duration>,
}

impl TransportChannel {
    pub fn new(
        iface: &NetworkInterface,
        timeout: Option<Duration>,
    ) -> Result<Self, String> {
        let mut config = Config::default();
        config.read_timeout = timeout;
        let (tx, rx) = new_ether_channel(iface, config)?;

        return Ok(Self { tx, rx, timeout });
    }

    pub fn build_and_send(
        &mut self,
        src_mac: MacAddr,
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_mac: MacAddr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) -> Option<Result<(), std::io::Error>> {
        let ether_packet = new_udp_stack(
            src_mac, src_ip, src_port, dst_mac, dst_ip, dst_port, payload,
        );
        return self.send(ether_packet.packet());
    }

    pub fn send(
        &mut self,
        packet: &[u8],
    ) -> Option<Result<(), std::io::Error>> {
        return self.tx.send_to(packet, None);
    }

    pub fn recv_dhcp(
        &mut self,
        port: u16,
        msg_types: &[u8],
        transaction_id: Option<u32>,
        server_ips: Option<&Vec<Ipv4Addr>>,
    ) -> Result<(MacAddr, DhcpPacket), String> {
        return recv_next_dhcp_packet(
            &mut self.rx,
            port,
            msg_types,
            transaction_id,
            server_ips,
            self.timeout,
        );
    }
}

pub fn new_ether_channel(
    iface: &NetworkInterface,
    config: Config,
) -> Result<(Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>), String> {
    let (sender, receiver) = match datalink::channel(iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(format!("Error creating channel: Unknown channel type"))
        }
        Err(e) => return Err(format!("Error creating channel: {}", e)),
    };

    return Ok((sender, receiver));
}

pub fn new_udp_stack<'a>(
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_mac: MacAddr,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> EthernetPacket<'a> {
    let udp_packet =
        new_udp_packet(src_ip, dst_ip, src_port, dst_port, payload);
    let ipv4_packet = new_ip_udp_packet(src_ip, dst_ip, udp_packet.packet());
    let ether_packet = new_ether_ipv4(src_mac, dst_mac, &ipv4_packet);

    return ether_packet;
}

pub fn new_ether_ipv4<'a>(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    ipv4_packet: &Ipv4Packet<'a>,
) -> EthernetPacket<'a> {
    let payload = ipv4_packet.packet();
    let buf = vec![0u8; EthernetPacket::minimum_packet_size() + payload.len()];
    let mut ethernet_packet = MutableEthernetPacket::owned(buf).unwrap();

    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_source(src_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);
    ethernet_packet.set_payload(payload);

    return ethernet_packet.consume_to_immutable();
}

pub const IPV4_HEADER_LENGTH: u8 = 20;

pub fn new_ip_udp_packet<'a>(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    payload: &[u8],
) -> Ipv4Packet<'a> {
    let buf = vec![0; IPV4_HEADER_LENGTH as usize + payload.len()];

    let mut ip_packet = MutableIpv4Packet::owned(buf).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(IPV4_HEADER_LENGTH / 4);
    ip_packet.set_dscp(0);
    ip_packet.set_ecn(0);
    ip_packet
        .set_total_length(IPV4_HEADER_LENGTH as u16 + payload.len() as u16);
    ip_packet.set_identification(rand::thread_rng().gen());
    ip_packet.set_flags(0);
    ip_packet.set_fragment_offset(0);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_packet.set_source(src_ip);
    ip_packet.set_destination(dst_ip);
    ip_packet.set_options(&Vec::new());
    ip_packet.set_payload(payload);

    ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

    return ip_packet.consume_to_immutable();
}

pub fn new_udp_packet<'a>(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> UdpPacket<'a> {
    let buf = vec![0; 8 + payload.len()];
    let mut udp_packet = MutableUdpPacket::owned(buf).unwrap();

    udp_packet.set_source(src_port);
    udp_packet.set_destination(dst_port);
    udp_packet.set_length((8 + payload.len()) as u16);
    udp_packet.set_payload(payload);

    udp_packet.set_checksum(udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &src_ip,
        &dst_ip,
    ));
    return udp_packet.consume_to_immutable();
}

pub fn recv_next_dhcp_packet(
    receiver: &mut Box<dyn DataLinkReceiver>,
    port: u16,
    msg_types: &[u8],
    transaction_id: Option<u32>,
    server_ips: Option<&Vec<Ipv4Addr>>,
    timeout: Option<Duration>,
) -> Result<(MacAddr, DhcpPacket), String> {
    let start_time = match timeout {
        Some(_) => Some(Instant::now()),
        None => None,
    };

    loop {
        if let Some(start_time) = start_time {
            let now = Instant::now();
            if now.duration_since(start_time) > timeout.unwrap() {
                return Err(format!("Error receiving packet: Timed out"));
            }
        }

        let buf = receiver
            .next()
            .map_err(|e| format!("Error receiving packets: {}", e))?;

        let ether_packet = match EthernetPacket::new(&buf[..]) {
            Some(ether_packet) => ether_packet,
            None => continue,
        };

        if ether_packet.get_ethertype() != EtherTypes::Ipv4 {
            continue;
        }

        let client_mac = ether_packet.get_source();
        // println!("{:?}", ether_packet);

        let ip_packet = match Ipv4Packet::new(ether_packet.payload()) {
            Some(ip_packet) => ip_packet,
            None => continue,
        };

        if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            continue;
        }

        let udp_packet = match UdpPacket::new(ip_packet.payload()) {
            Some(udp_packet) => udp_packet,
            None => continue,
        };

        if udp_packet.get_destination() != port {
            continue;
        }

        let input = udp_packet.payload();

        match DhcpPacket::parse(input) {
            Ok((_, dhcp_packet)) => {
                if !is_valid_dhcp_packet(
                    &dhcp_packet,
                    msg_types,
                    transaction_id,
                    server_ips,
                ) {
                    continue;
                }
                return Ok((client_mac, dhcp_packet));
            }
            Err(e) => {
                warn!("Error parsing DHCP: {}", e)
            }
        };
    }
}

fn is_valid_dhcp_packet(
    dp: &DhcpPacket,
    msg_types: &[u8],
    transaction_id: Option<u32>,
    server_ips: Option<&Vec<Ipv4Addr>>,
) -> bool {
    if let Some(xid) = transaction_id {
        if dp.xid != xid {
            return false;
        }
    }

    if let Some(servers) = server_ips {
        match dp.dhcp_server_id() {
            None => return false,
            Some(server_id) => {
                if !servers.contains(&server_id) {
                    return false;
                }
            }
        }
    }

    match dp.dhcp_msg_type() {
        None => return false,
        Some(msg_type) => {
            if !msg_types.contains(&msg_type) {
                return false;
            }
        }
    };

    return true;
}
