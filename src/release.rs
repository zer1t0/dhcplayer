use crate::{
    args,
    dhcp::{self, DhcpMessageTypes, DhcpPacket},
    readin::read_inputs,
    transport::TransportChannel,
};
use log::{info, warn};
use pnet::util::MacAddr;
use rand::Rng;
use regex::Regex;
use std::{net::Ipv4Addr, str::FromStr};

pub fn main(args: args::release::Arguments) -> Result<(), String> {
    let iface = &args.iface;

    let my_mac = iface.mac.ok_or_else(|| {
        format!("Unable to get the MAC of {} interface", iface.name)
    })?;

    let server_ip = args.server_ip;

    let mut channel = TransportChannel::new(iface, None)
        .map_err(|e| format!("Unable to create a raw socket: {}", e))?;

    for line in read_inputs(args.addresses, true, true) {
        let (client_ip, client_mac) = match parse_mac_ip_line(&line) {
            Ok((ip, mac)) => (ip, mac.unwrap_or(my_mac)),
            Err(e) => {
                warn!("{}", e);
                continue;
            }
        };

        let ether_mac = match args.keep_ether {
            true => my_mac,
            false => client_mac,
        };

        info!("RELEASE {} {}", client_ip, client_mac);
        send_release(
            &mut channel,
            client_ip,
            server_ip,
            client_mac,
            ether_mac,
        )?;
    }

    return Ok(());
}

fn parse_mac_ip_line(
    line: &str,
) -> Result<(Ipv4Addr, Option<MacAddr>), String> {
    let re = Regex::new(r"-| ").unwrap();
    let parts: Vec<&str> = re.split(&line).collect();

    let ip = Ipv4Addr::from_str(parts[0]).map_err(|_| {
        format!("Invalid value '{}': First part must be an IP", line)
    })?;

    let mac = if parts.len() > 1 {
        let mac = MacAddr::from_str(parts[1]).map_err(|_| {
            format!("Invalid value '{}': Second part must be an MAC", line)
        })?;
        Some(mac)
    } else {
        None
    };

    return Ok((ip, mac));
}

pub fn send_release(
    channel: &mut TransportChannel,
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    server_mac_dhcp: MacAddr,
    server_mac_ether: MacAddr,
) -> Result<(), String> {
    let mut rng = rand::thread_rng();
    let transaction_id: u32 = rng.gen();

    let mut dp = DhcpPacket::new_request();
    dp.add_dhcp_msg_type(DhcpMessageTypes::RELEASE);
    dp.xid = transaction_id;
    dp.ciaddr = client_ip;
    dp.chaddr = server_mac_dhcp;
    dp.add_dhcp_server_id(server_ip);

    channel
        .build_and_send(
            server_mac_ether,
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
