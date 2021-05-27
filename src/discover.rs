use std::net::Ipv4Addr;

use crate::dhcp::{ClientFqdn, DhcpMessageTypes, DhcpOption, DhcpPacket};
use crate::{
    args,
    dhcp::{self, DhcpOptions},
};
use crate::{helpers::get_iface_ipv4_network, transport::TransportChannel};
use log::{debug, info};
use pnet::util::MacAddr;
use rand::Rng;

pub enum Action {
    Discover,
    DiscoverAndRequest,
    Inform,
}

pub fn main(args: args::discover::Arguments) -> Result<(), String> {
    let iface = &args.iface;

    let my_mac = iface.mac.ok_or_else(|| {
        format!("Unable to get the MAC of {} interface", iface.name)
    })?;

    let dhcp_mac = match args.mac {
        Some(mac) => mac,
        None => my_mac,
    };

    let ether_mac = match args.keep_ether {
        true => my_mac,
        false => dhcp_mac,
    };

    let request_list = match args.options {
        Some(options) => options,
        None => vec![
            DhcpOptions::SUBNET_MASK,
            DhcpOptions::BROADCAST_ADDRESS,
            DhcpOptions::ROUTER,
            DhcpOptions::DOMAIN_NAME,
            DhcpOptions::DOMAIN_SERVER,
        ],
    };

    let dns_update = args.dns_update;
    let fqdn = args.fqdn.unwrap_or("".to_string());

    let client_fqdn = if dns_update || fqdn.len() != 0 {
        Some(ClientFqdn {
            flags: dns_update as u8,
            aresult: 0,
            ptrresult: 0,
            name: fqdn,
        })
    } else {
        None
    };

    let client_options = ClientOptions {
        request_list,
        hostname: args.hostname,
        client_fqdn,
    };

    let mut channel = TransportChannel::new(iface, Some(args.timeout))
        .map_err(|e| format!("Unable to create a raw socket: {}", e))?;

    match get_action(args.inform, args.send_request) {
        Action::Discover => discover_all(
            &mut channel,
            dhcp_mac,
            ether_mac,
            &client_options,
            args.servers.as_ref(),
        )?,
        Action::DiscoverAndRequest => {
            let resp = discover_and_request(
                &mut channel,
                dhcp_mac,
                ether_mac,
                &client_options,
                args.servers.as_ref(),
            )?;
            print_response(&resp);
        }
        Action::Inform => {
            let my_ip = get_iface_ipv4_network(iface)
                .ok_or_else(|| {
                    format!("Unable to get the IP of {} interface", iface.name)
                })?
                .ip();

            inform_all(
                &mut channel,
                my_ip,
                dhcp_mac,
                ether_mac,
                &client_options,
                args.servers.as_ref(),
            )?;
        }
    };

    return Ok(());
}

fn get_action(inform: bool, send_request: bool) -> Action {
    if inform {
        return Action::Inform;
    }

    if send_request {
        return Action::DiscoverAndRequest;
    }

    return Action::Discover;
}

fn discover_all(
    channel: &mut TransportChannel,
    dhcp_mac: MacAddr,
    ether_mac: MacAddr,
    client_options: &ClientOptions,
    servers: Option<&Vec<Ipv4Addr>>,
) -> Result<(), String> {
    let mut rng = rand::thread_rng();
    let transaction_id: u32 = rng.gen();

    info!("DISCOVER sent - Client MAC {}", dhcp_mac);
    send_discover(
        channel,
        transaction_id,
        dhcp_mac,
        ether_mac,
        client_options,
    )?;

    loop {
        match channel.recv_dhcp(
            dhcp::DHCP_CLIENT_PORT,
            &[DhcpMessageTypes::OFFER],
            Some(transaction_id),
            servers,
        ) {
            Ok((_, offer)) => {
                println!("");
                print_offer(&offer);
            }
            Err(e) => {
                debug!("{}", e);
                break;
            }
        }
    }

    return Ok(());
}

fn inform_all(
    channel: &mut TransportChannel,
    client_ip: Ipv4Addr,
    dhcp_mac: MacAddr,
    ether_mac: MacAddr,
    client_options: &ClientOptions,
    servers: Option<&Vec<Ipv4Addr>>,
) -> Result<(), String> {
    let mut rng = rand::thread_rng();
    let transaction_id: u32 = rng.gen();

    info!("INFORM sent - Client MAC {}", dhcp_mac);

    send_inform(
        channel,
        transaction_id,
        dhcp_mac,
        ether_mac,
        client_options,
        client_ip,
    )?;

    loop {
        match channel.recv_dhcp(
            dhcp::DHCP_CLIENT_PORT,
            &[DhcpMessageTypes::ACK, DhcpMessageTypes::NAK],
            Some(transaction_id),
            servers,
        ) {
            Ok((_, resp)) => {
                println!("");
                print_response(&resp);
            }
            Err(e) => {
                debug!("{}", e);
                break;
            }
        }
    }

    return Ok(());
}

fn print_response(resp: &DhcpPacket) {
    match resp.dhcp_msg_type().unwrap() {
        DhcpMessageTypes::OFFER => {
            print_offer(&resp);
        }
        DhcpMessageTypes::ACK => {
            print_ack(&resp);
        }
        DhcpMessageTypes::NAK => print_nak(&resp),
        _ => unreachable!("Unknown message"),
    }
}

fn print_offer(offer: &DhcpPacket) {
    println!("OFFER received from {}", offer.siaddr);
    println!("Offered IP: {}", offer.yiaddr);
    println!("Client MAC: {}", offer.chaddr);
    println!("DHCP Server: {}", offer.siaddr);
    print_options(offer);
}

fn print_ack(ack: &DhcpPacket) {
    println!("ACK received from {}", ack.siaddr);
    println!("Acquired IP: {}", ack.yiaddr);
    println!("Client MAC: {}", ack.chaddr);
    print_options(ack);
}

fn print_options(dp: &DhcpPacket) {
    println!("Options:");
    for opt in &dp.options {
        if let DhcpOption::DhcpMsgType(_) = opt {
            continue;
        }
        println!(
            "[{}] {}: {}",
            opt.code(),
            opt.name().unwrap_or("Unknow"),
            opt.value_str()
        );
    }
}

fn print_nak(nak: &DhcpPacket) {
    eprintln!("NAK received from {}", nak.siaddr);
    if let Some(msg) = nak.message() {
        eprintln!("Message: {}", msg);
    }
}

fn discover_and_request(
    channel: &mut TransportChannel,
    dhcp_mac: MacAddr,
    ether_mac: MacAddr,
    client_options: &ClientOptions,
    servers: Option<&Vec<Ipv4Addr>>,
) -> Result<DhcpPacket, String> {
    let mut rng = rand::thread_rng();
    let transaction_id: u32 = rng.gen();

    info!("DISCOVER sent - Client MAC {}", dhcp_mac);
    let dhcp_resp = send_recv_discover(
        channel,
        transaction_id,
        dhcp_mac,
        ether_mac,
        client_options,
        servers,
    )?;

    let client_ip = dhcp_resp.yiaddr;
    info!("OFFER received - Offered IP: {}", client_ip);

    let dhcp_server = dhcp_resp
        .dhcp_server_id()
        .ok_or(format!("Unable to get the server ip"))?;

    info!("REQUEST sent - Client MAC: {}", dhcp_mac);
    return send_recv_request(
        channel,
        transaction_id,
        dhcp_mac,
        ether_mac,
        client_options,
        client_ip,
        dhcp_server,
    );
}

fn send_recv_discover(
    channel: &mut TransportChannel,
    transaction_id: u32,
    dhcp_mac: MacAddr,
    ether_mac: MacAddr,
    client_options: &ClientOptions,
    servers: Option<&Vec<Ipv4Addr>>,
) -> Result<DhcpPacket, String> {
    send_discover(
        channel,
        transaction_id,
        dhcp_mac,
        ether_mac,
        client_options,
    )?;

    let (_, dhcp_resp) = channel.recv_dhcp(
        dhcp::DHCP_CLIENT_PORT,
        &[DhcpMessageTypes::OFFER],
        Some(transaction_id),
        servers,
    )?;

    return Ok(dhcp_resp);
}

fn send_discover(
    channel: &mut TransportChannel,
    transaction_id: u32,
    dhcp_mac: MacAddr,
    ether_mac: MacAddr,
    client_options: &ClientOptions,
) -> Result<(), String> {
    let mut dp = DhcpPacket::new_request();
    dp.add_dhcp_msg_type(DhcpMessageTypes::DISCOVER);
    dp.xid = transaction_id;
    dp.chaddr = dhcp_mac;
    set_client_options(&mut dp, client_options);

    channel
        .build_and_send(
            ether_mac,
            Ipv4Addr::UNSPECIFIED,
            dhcp::DHCP_CLIENT_PORT,
            MacAddr::broadcast(),
            Ipv4Addr::BROADCAST,
            dhcp::DHCP_SERVER_PORT,
            &dp.build(),
        )
        .ok_or("Error sending packet")?
        .map_err(|e| format!("Error sending packet: {}", e))?;

    return Ok(());
}

fn send_recv_request(
    channel: &mut TransportChannel,
    transaction_id: u32,
    dhcp_mac: MacAddr,
    ether_mac: MacAddr,
    client_options: &ClientOptions,
    client_ip: Ipv4Addr,
    dhcp_server: Ipv4Addr,
) -> Result<DhcpPacket, String> {
    let mut dp = DhcpPacket::new_request();
    dp.add_dhcp_msg_type(DhcpMessageTypes::REQUEST);
    dp.xid = transaction_id;
    dp.chaddr = dhcp_mac;
    dp.add_requested_ip_address(client_ip);
    dp.add_dhcp_server_id(dhcp_server);

    set_client_options(&mut dp, client_options);

    channel
        .build_and_send(
            ether_mac,
            Ipv4Addr::UNSPECIFIED,
            dhcp::DHCP_CLIENT_PORT,
            MacAddr::broadcast(),
            Ipv4Addr::BROADCAST,
            dhcp::DHCP_SERVER_PORT,
            &dp.build(),
        )
        .ok_or("Error sending packet")?
        .map_err(|e| format!("Error sending packet: {}", e))?;

    let (_, dhcp_resp) = channel.recv_dhcp(
        dhcp::DHCP_CLIENT_PORT,
        &[DhcpMessageTypes::ACK, DhcpMessageTypes::NAK],
        Some(transaction_id),
        Some(&vec![dhcp_server]),
    )?;

    return Ok(dhcp_resp);
}

fn send_inform(
    channel: &mut TransportChannel,
    transaction_id: u32,
    dhcp_mac: MacAddr,
    ether_mac: MacAddr,
    client_options: &ClientOptions,
    client_ip: Ipv4Addr,
) -> Result<(), String> {
    let mut dp = DhcpPacket::new_request();
    dp.add_dhcp_msg_type(DhcpMessageTypes::INFORM);
    dp.xid = transaction_id;
    dp.ciaddr = client_ip;
    dp.chaddr = dhcp_mac;
    set_client_options(&mut dp, client_options);

    channel
        .build_and_send(
            ether_mac,
            client_ip,
            dhcp::DHCP_CLIENT_PORT,
            MacAddr::broadcast(),
            Ipv4Addr::BROADCAST,
            dhcp::DHCP_SERVER_PORT,
            &dp.build(),
        )
        .ok_or("Error sending packet")?
        .map_err(|e| format!("Error sending packet: {}", e))?;

    return Ok(());
}

pub fn set_client_options(dp: &mut DhcpPacket, co: &ClientOptions) {
    dp.add_parameter_request_list(co.request_list.clone());

    if let Some(hostname) = &co.hostname {
        dp.add_hostname(hostname.clone());
    }

    if let Some(client_fqdn) = &co.client_fqdn {
        dp.add_client_fqdn(client_fqdn.clone());
    }
}

pub struct ClientOptions {
    pub request_list: Vec<u8>,
    pub hostname: Option<String>,
    pub client_fqdn: Option<ClientFqdn>,
}
