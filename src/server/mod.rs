mod config;

use crate::dhcp;
use crate::dhcp::{DhcpMessageTypes, DhcpPacket};
use crate::transport::TransportChannel;
use crate::{args, dhcp::DhcpOptions};
use log::info;
use pnet::util::MacAddr;
use socket2::{Domain, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};

use crate::helpers::get_iface_ipv4_network;
use config::{generate_server_config, ServerConfig};

pub fn main(args: args::server::Arguments) -> Result<(), String> {
    let iface = &args.iface;

    let iface_net = get_iface_ipv4_network(iface).ok_or_else(|| {
        format!("Unable to get the network of {} interface", iface.name)
    })?;

    let my_ip = iface_net.ip();
    let my_mac = iface.mac.ok_or_else(|| {
        format!("Unable to get the MAC of {} interface", iface.name)
    })?;

    let mut srv_conf = generate_server_config(&args)?;

    info!("IP pool: {}-{}", srv_conf.start_ip, srv_conf.end_ip);
    info!("Mask: {}", srv_conf.net_mask);
    info!("Broadcast: {}", srv_conf.broadcast);
    info!("DHCP: {}", srv_conf.dhcp_server);
    info!("DNS: {:?}", srv_conf.domain_servers);
    info!("Router: {:?}", srv_conf.routers);

    if let Some(netbios) = &srv_conf.netbios_servers {
        info!("Netbios: {:?}", netbios);
    }

    if let Some(wpad) = &srv_conf.wpad {
        info!("WPAD: {}", wpad);
    }

    if let Some(domain) = &srv_conf.domain {
        info!("Domain: {}", domain);
    }

    let dhcp_port = dhcp::DHCP_SERVER_PORT;
    let _socket = match args.udp_bind {
        true => Some(open_udp_socket(my_ip, dhcp_port)?),
        false => None,
    };

    let mut channel = TransportChannel::new(iface, None)
        .map_err(|e| format!("Unable to create a raw socket: {}", e))?;

    loop {
        let (client_ether_mac, dhcp_packet) = listen(&mut channel, dhcp_port)?;

        let msg_type = dhcp_packet.dhcp_msg_type().unwrap();
        let client_mac = dhcp_packet.chaddr;
        let hostname = dhcp_packet.hostname();

        let (dhcp_reply, client_ip) = match msg_type {
            DhcpMessageTypes::DISCOVER => {
                info!(
                    "DISCOVER from {}{}",
                    client_mac,
                    match hostname {
                        Some(name) => format!(" ({})", name),
                        None => format!(""),
                    }
                );
                match process_discover(&dhcp_packet, &srv_conf) {
                    Some((offer, ip)) => (offer, ip),
                    None => continue,
                }
            }
            DhcpMessageTypes::REQUEST => {
                info!(
                    "REQUEST from {}{}",
                    client_mac,
                    match hostname {
                        Some(name) => format!(" ({})", name),
                        None => format!(""),
                    }
                );
                process_request(&dhcp_packet, &mut srv_conf)
            }
            DhcpMessageTypes::RELEASE => {
                info!(
                    "RELEASE from {}{}",
                    client_mac,
                    match hostname {
                        Some(name) => format!(" ({})", name),
                        None => format!(""),
                    }
                );
                process_release(&dhcp_packet, &mut srv_conf);
                continue;
            }
            DhcpMessageTypes::INFORM => {
                info!(
                    "INFORM from {}{}",
                    client_mac,
                    match hostname {
                        Some(name) => format!(" ({})", name),
                        None => format!(""),
                    }
                );
                match process_inform(&dhcp_packet, &mut srv_conf) {
                    Some((ack, ip)) => (ack, ip),
                    None => continue,
                }
            }
            _ => continue,
        };

        channel
            .build_and_send(
                my_mac,
                my_ip,
                dhcp::DHCP_SERVER_PORT,
                client_ether_mac,
                client_ip,
                dhcp::DHCP_CLIENT_PORT,
                &dhcp_reply.build(),
            )
            .ok_or("Error sending packet")?
            .map_err(|e| format!("Error sending packet: {}", e))?;
    }
}

fn open_udp_socket(ip: Ipv4Addr, port: u16) -> Result<UdpSocket, String> {
    setup_udp_socket(ip, port).map_err(|e| {
        format!("Error binding to UDP port {}:{} : {}", ip, port, e)
    })
}

fn setup_udp_socket(ip: Ipv4Addr, port: u16) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddr::V4(SocketAddrV4::new(ip, port)).into())?;
    return Ok(socket.into());
}

fn listen(
    channel: &mut TransportChannel,
    port: u16,
) -> Result<(MacAddr, DhcpPacket), String> {
    return channel.recv_dhcp(
        port,
        &[
            DhcpMessageTypes::DISCOVER,
            DhcpMessageTypes::REQUEST,
            DhcpMessageTypes::DECLINE,
            DhcpMessageTypes::RELEASE,
            DhcpMessageTypes::INFORM,
        ],
        None,
        None,
    );
}

macro_rules! nak {
    ($msg:expr, $dhcp_r:ident, $srv_conf:ident) => {
        (
            new_dhcp_nak(
                $dhcp_r.xid,
                $dhcp_r.chaddr,
                format!("{}", $msg),
                $srv_conf,
            ),
            Ipv4Addr::BROADCAST,
        )
    };
}

fn process_release(release: &DhcpPacket, srv_conf: &mut ServerConfig) {
    let client_ip = release.ciaddr;
    srv_conf.release_ip(&client_ip);
}

fn process_inform(
    inform: &DhcpPacket,
    srv_conf: &ServerConfig,
) -> Option<(DhcpPacket, Ipv4Addr)> {
    let transaction_id = inform.xid;
    let client_mac = inform.chaddr;
    let client_ip = inform.ciaddr;

    if client_ip == Ipv4Addr::UNSPECIFIED {
        return None;
    }

    let request_list = inform.parameter_request_list()?;

    let ack = new_dhcp_ack_inform(
        transaction_id,
        client_mac,
        client_ip,
        srv_conf.my_ip,
        srv_conf,
        request_list,
    );

    return Some((ack, client_ip));
}

fn process_discover(
    dhcp_discover: &DhcpPacket,
    srv_conf: &ServerConfig,
) -> Option<(DhcpPacket, Ipv4Addr)> {
    let transaction_id = dhcp_discover.xid;
    let client_mac = dhcp_discover.chaddr;

    let request_list = dhcp_discover.parameter_request_list();

    let offer_ip = match srv_conf.get_client_ip(&client_mac) {
        Some(ip) => ip,
        None => match srv_conf.get_available_ip() {
            Some(ip) => ip,
            None => return None,
        },
    };

    info!("Offer {}", offer_ip);
    let dhcp_offer = new_dhcp_offer(
        transaction_id,
        client_mac,
        offer_ip,
        srv_conf.my_ip,
        &srv_conf,
        request_list,
    );

    return Some((dhcp_offer, offer_ip));
}

fn process_request(
    dhcp_request: &DhcpPacket,
    srv_conf: &mut ServerConfig,
) -> (DhcpPacket, Ipv4Addr) {
    let transaction_id = dhcp_request.xid;
    let client_mac = dhcp_request.chaddr;
    let request_list = dhcp_request.parameter_request_list();

    if let Some(ip) = dhcp_request.dhcp_server_id() {
        if ip != srv_conf.dhcp_server {
            return nak!("Wrong server ID", dhcp_request, srv_conf);
        }
    }

    let requested_ip = match dhcp_request.requested_ip_address() {
        Some(ip) => Some(ip),
        None => {
            if dhcp_request.ciaddr == Ipv4Addr::UNSPECIFIED {
                None
            } else {
                Some(dhcp_request.ciaddr)
            }
        }
    };

    let res = match requested_ip {
        Some(requested_ip) => {
            process_new_ip_request(client_mac, requested_ip, srv_conf)
        }
        None => process_renewal(&client_mac, srv_conf),
    };

    let client_ip = match res {
        Ok(client_ip) => client_ip,
        Err(msg) => return nak!(msg, dhcp_request, srv_conf),
    };

    info!("ACK to {} for {}", client_ip, client_mac);
    let dhcp_ack = new_dhcp_ack(
        transaction_id,
        client_mac,
        client_ip,
        srv_conf.my_ip,
        &srv_conf,
        request_list,
    );

    return (dhcp_ack, client_ip);
}

fn process_renewal(
    client_mac: &MacAddr,
    srv_conf: &mut ServerConfig,
) -> Result<Ipv4Addr, &'static str> {
    match srv_conf.get_client_ip(&client_mac) {
        Some(ip) => Ok(ip),
        None => Err("No requested IP"),
    }
}

fn process_new_ip_request(
    client_mac: MacAddr,
    requested_ip: Ipv4Addr,
    srv_conf: &mut ServerConfig,
) -> Result<Ipv4Addr, &'static str> {
    // request new ip
    info!("Requested IP {}", requested_ip);
    match srv_conf.get_client_ip(&client_mac) {
        Some(ip) => {
            if ip != requested_ip {
                // if client ask for a different IP
                // then release the previous one and give the new
                if !srv_conf.is_available_ip(&requested_ip) {
                    return Err("Requested IP not available");
                }

                srv_conf.release_client_ip(&client_mac);
                srv_conf.mark_ip_as_used(client_mac, requested_ip).unwrap();
            }
        }
        None => match srv_conf.mark_ip_as_used(client_mac, requested_ip) {
            Ok(_) => {}
            Err(_) => {
                return Err("Requested IP not available");
            }
        },
    };

    return Ok(requested_ip);
}

fn new_dhcp_ack_inform(
    transaction_id: u32,
    client_mac: MacAddr,
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    server_config: &ServerConfig,
    request_list: &Vec<u8>,
) -> DhcpPacket {
    let mut dhcp_ack = new_dhcp_reply(
        DhcpMessageTypes::ACK,
        transaction_id,
        client_mac,
        client_ip,
        Ipv4Addr::UNSPECIFIED,
        server_ip,
    );

    dhcp_ack.add_dhcp_server_id(server_config.dhcp_server);
    set_dhcp_optional_options(&mut dhcp_ack, server_config, request_list);

    return dhcp_ack;
}

pub fn new_dhcp_offer(
    transaction_id: u32,
    client_mac: MacAddr,
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    server_config: &ServerConfig,
    request_list: Option<&Vec<u8>>,
) -> DhcpPacket {
    let mut dhcp_offer = new_dhcp_reply(
        DhcpMessageTypes::OFFER,
        transaction_id,
        client_mac,
        Ipv4Addr::UNSPECIFIED,
        client_ip,
        server_ip,
    );

    set_dhcp_options(&mut dhcp_offer, server_config, request_list);

    return dhcp_offer;
}

pub fn new_dhcp_ack(
    transaction_id: u32,
    client_mac: MacAddr,
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    server_config: &ServerConfig,
    request_list: Option<&Vec<u8>>,
) -> DhcpPacket {
    let mut dhcp_ack = new_dhcp_reply(
        DhcpMessageTypes::ACK,
        transaction_id,
        client_mac,
        Ipv4Addr::UNSPECIFIED,
        client_ip,
        server_ip,
    );

    set_dhcp_options(&mut dhcp_ack, server_config, request_list);

    return dhcp_ack;
}

pub fn new_dhcp_nak(
    transaction_id: u32,
    client_mac: MacAddr,
    msg: String,
    server_config: &ServerConfig,
) -> DhcpPacket {
    let mut dhcp_nak = new_dhcp_reply(
        DhcpMessageTypes::NAK,
        transaction_id,
        client_mac,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
    );

    dhcp_nak.set_broadcast();
    dhcp_nak.add_dhcp_server_id(server_config.dhcp_server);
    dhcp_nak.add_message(msg);

    return dhcp_nak;
}

pub fn new_dhcp_reply(
    msg_type: u8,
    transaction_id: u32,
    chaddr: MacAddr,
    ciaddr: Ipv4Addr,
    yiaddr: Ipv4Addr,
    siaddr: Ipv4Addr,
) -> DhcpPacket {
    let mut dhcp_msg = DhcpPacket::new_reply();
    dhcp_msg.add_dhcp_msg_type(msg_type);
    dhcp_msg.xid = transaction_id;
    dhcp_msg.yiaddr = yiaddr;
    dhcp_msg.ciaddr = ciaddr;
    dhcp_msg.siaddr = siaddr;
    dhcp_msg.chaddr = chaddr;

    return dhcp_msg;
}

pub fn set_dhcp_options(
    dp: &mut DhcpPacket,
    dsc: &ServerConfig,
    request_list: Option<&Vec<u8>>,
) {
    set_dhcp_mandatory_options(dp, dsc);

    if let Some(request_list) = request_list {
        set_dhcp_optional_options(dp, dsc, request_list);
    }
}

pub fn set_dhcp_mandatory_options(dp: &mut DhcpPacket, dsc: &ServerConfig) {
    dp.add_dhcp_server_id(dsc.dhcp_server);
    dp.add_ip_address_lease_time(dsc.ip_lease_time);
    dp.add_renewal_time(dsc.renewal_time);
    dp.add_rebinding_time(dsc.rebinding_time);
}

pub fn set_dhcp_optional_options(
    dp: &mut DhcpPacket,
    dsc: &ServerConfig,
    request_list: &Vec<u8>,
) {
    if request_list.contains(&DhcpOptions::SUBNET_MASK) {
        dp.add_subnet_mask(dsc.net_mask);
    }

    if request_list.contains(&DhcpOptions::BROADCAST_ADDRESS) {
        dp.add_broadcast_address(dsc.broadcast);
    }

    if request_list.contains(&DhcpOptions::ROUTER) {
        dp.add_router(dsc.routers.clone());
    }

    if request_list.contains(&DhcpOptions::DOMAIN_SERVER) {
        dp.add_domain_server(dsc.domain_servers.clone());
    }

    if request_list.contains(&DhcpOptions::DOMAIN_SERVER) {
        if let Some(domain) = &dsc.domain {
            dp.add_domain_name(domain.clone());
        }
    }

    if request_list.contains(&DhcpOptions::WPAD) {
        if let Some(wpad) = &dsc.wpad {
            dp.add_wpad(wpad.clone());
        }
    }

    if request_list.contains(&DhcpOptions::NETBIOS_NAME_SERVER) {
        if let Some(netbios) = &dsc.netbios_servers {
            dp.add_netbios_name_server(netbios.clone());
        }
    }
}
