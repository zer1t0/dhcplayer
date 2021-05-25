use std::net::Ipv4Addr;

use super::helpers;
use clap::{App, Arg, ArgMatches, SubCommand};
use pnet::{datalink::NetworkInterface};

pub const COMMAND_NAME: &str = "release";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("DHCP release")
        .arg(
            Arg::with_name("iface")
                .long("iface")
                .short("I")
                .required(true)
                .takes_value(true)
                .validator(helpers::is_interface)
                .help("Interface to send the request"),
        )
        .arg(
            Arg::with_name("address")
                .takes_value(true)
                .value_name("ip-mac")
                .multiple(true)
                .help("Pairs IP/MAC to release"),
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .short("s")
                .required(true)
                .takes_value(true)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("DHCP server IP to send release petitions"),
        )
        .arg(
            Arg::with_name("keep-ether")
                .long("keep-ether")
                .short("k")
                .help("Use the iface MAC in the Ethernet frame"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

pub struct Arguments {
    pub iface: NetworkInterface,
    pub addresses: Vec<String>,
    pub server_ip: Ipv4Addr,
    pub keep_ether: bool,
    pub verbosity: usize,
}

impl<'a> Arguments {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let iface =
            helpers::lookup_interface(matches.value_of("iface").unwrap())
                .unwrap();

        Self {
            iface,
            keep_ether: matches.is_present("keep-ether"),
            addresses: helpers::parse_strings(matches, "address")
                .unwrap_or(Vec::new()),
            server_ip: helpers::parse_ip(matches, "server").unwrap(),
            verbosity: matches.occurrences_of("verbosity") as usize,
        }
    }
}
