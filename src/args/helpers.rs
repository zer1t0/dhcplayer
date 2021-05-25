use clap::ArgMatches;
use pnet::{
    datalink::{self, NetworkInterface},
    util::MacAddr,
};
use std::{collections::HashMap, str::FromStr};
use std::{net::Ipv4Addr, time::Duration};

use crate::dhcp::DhcpOptions;

pub fn is_u64(v: String) -> Result<(), String> {
    v.parse::<u64>().map_err(|_| {
        format!(
            "Incorrect value '{}' must be an unsigned integer of 64 bits (u64)",
            v
        )
    })?;

    return Ok(());
}

pub fn option_keywords() -> HashMap<&'static str, u8> {
    let mut k = HashMap::new();
    k.insert("broadcast", DhcpOptions::BROADCAST_ADDRESS);
    k.insert("dns", DhcpOptions::DOMAIN_SERVER);
    k.insert("domain", DhcpOptions::DOMAIN_NAME);
    k.insert("mask", DhcpOptions::SUBNET_MASK);
    k.insert("netbios", DhcpOptions::NETBIOS_NAME_SERVER);
    k.insert("router", DhcpOptions::ROUTER);
    k.insert("wins", DhcpOptions::NETBIOS_NAME_SERVER);
    k.insert("wpad", DhcpOptions::WPAD);

    return k;
}

pub fn is_dhcp_option(v: String) -> Result<(), String> {
    let keywords = option_keywords();

    if v == "all" || v == "none" {
        return Ok(());
    }

    if keywords.contains_key(v.as_str()) {
        return Ok(());
    }

    v.parse::<u8>().map_err(|_| {
        format!(
            "Invalid value '{}': Must be an integer between 0 and 255 or value in {:?}",
            v, keywords.keys()
        )
    })?;

    return Ok(());
}

pub fn parse_options(matches: &ArgMatches, name: &str) -> Option<Vec<u8>> {
    match matches.values_of(name) {
        None => None,
        Some(options) => {
            if options.len() == 0 {
                return None;
            }

            let options: Vec<&str> = options.collect();

            if options.contains(&"all") {
                return Some((1..255).collect());
            }

            if options.contains(&"none") {
                return Some(Vec::new());
            }

            let keywords = option_keywords();

            return Some(
                options
                    .into_iter()
                    .map(|opt| match keywords.get(opt) {
                        Some(v) => *v,
                        None => opt.parse::<u8>().unwrap(),
                    })
                    .collect(),
            );
        }
    }
}

pub fn is_mac(v: String) -> Result<(), String> {
    match MacAddr::from_str(&v) {
        Ok(_) => Ok(()),
        Err(_) => Err(format!("'{}' is a valid MAC address", v)),
    }
}

pub fn parse_mac(matches: &ArgMatches, name: &str) -> Option<MacAddr> {
    matches
        .value_of(name)
        .map(|mac| MacAddr::from_str(mac).unwrap())
}

pub fn is_interface(v: String) -> Result<(), String> {
    let iface = lookup_interface(&v);
    if iface.is_none() {
        return Err(format!("Interface '{}' not found in the system", v));
    }

    return Ok(());
}

pub fn lookup_interface(iface_name: &str) -> Option<NetworkInterface> {
    return datalink::interfaces()
        .into_iter()
        .find(|iface| &iface.name == iface_name);
}

pub fn is_ip(v: String) -> Result<(), String> {
    v.parse::<Ipv4Addr>()
        .map_err(|_| format!("'{}' is not a valid IPv4", v))?;
    return Ok(());
}

pub fn parse_ip(matches: &ArgMatches, name: &str) -> Option<Ipv4Addr> {
    matches.value_of(name).map(|ip| ip.parse().unwrap())
}

pub fn parse_ips(matches: &ArgMatches, name: &str) -> Option<Vec<Ipv4Addr>> {
    match matches.values_of(name) {
        None => None,
        Some(ips) => {
            if ips.len() == 0 {
                return None;
            }
            return Some(
                ips.into_iter().map(|ip| ip.parse().unwrap()).collect(),
            );
        }
    }
}

pub fn parse_string(matches: &ArgMatches, name: &str) -> Option<String> {
    matches.value_of(name).map(|s| s.into())
}

pub fn parse_strings(matches: &ArgMatches, name: &str) -> Option<Vec<String>> {
    match matches.values_of(name) {
        None => None,
        Some(ips) => {
            if ips.len() == 0 {
                return None;
            }
            return Some(ips.into_iter().map(|s| s.to_string()).collect());
        }
    }
}

pub fn parse_millis(matches: &ArgMatches, name: &str) -> Option<Duration> {
    matches
        .value_of(name)
        .map(|t| Duration::from_millis(t.parse().unwrap()))
}
