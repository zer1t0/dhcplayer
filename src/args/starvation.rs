use super::helpers;
use clap::{App, Arg, ArgMatches, SubCommand};
use pnet::datalink::NetworkInterface;
use std::{net::Ipv4Addr, time::Duration};

pub const COMMAND_NAME: &str = "starv";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("DHCP starvation attack")
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
            Arg::with_name("timeout")
                .long("timeout")
                .short("t")
                .takes_value(true)
                .default_value("5000")
                .value_name("millis")
                .validator(helpers::is_u64)
                .help("Timeout for responses in milliseconds"),
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .short("s")
                .takes_value(true)
                .value_name("ip")
                .use_delimiter(true)
                .validator(helpers::is_ip)
                .help("Target DHCP Server(s) IP. If none, any DHCP server will target"),
        )
        .arg(
            Arg::with_name("keep-ether")
                .long("keep-ether")
                .short("k")
                .help("Use the iface MAC in the Ethernet frame"),
        )
        .arg(
            Arg::with_name("no-release")
                .long("no-release")
                .short("n")
                .help("Do not release IPs after stopping the attack"),
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
    pub timeout: Duration,
    pub keep_ether: bool,
    pub release: bool,
    pub verbosity: usize,
    pub servers: Option<Vec<Ipv4Addr>>,
}

impl<'a> Arguments {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let iface =
            helpers::lookup_interface(matches.value_of("iface").unwrap())
                .unwrap();

        Self {
            iface,
            timeout: helpers::parse_millis(matches, "timeout").unwrap(),
            keep_ether: matches.is_present("keep-ether"),
            release: !matches.is_present("no-release"),
            servers: helpers::parse_ips(matches, "server"),
            verbosity: matches.occurrences_of("verbosity") as usize,
        }
    }
}
