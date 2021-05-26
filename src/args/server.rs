use clap::{App, Arg, ArgMatches, SubCommand};
use pnet::datalink::NetworkInterface;
use std::net::Ipv4Addr;

use super::helpers;

pub const COMMAND_NAME: &str = "server";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("DHCP server")
        .arg(
            Arg::with_name("iface")
                .long("iface")
                .short("I")
                .required(true)
                .takes_value(true)
                .validator(helpers::is_interface)
                .help("Interface to listen requests"),
        )
        .arg(
            Arg::with_name("start-ip")
                .long("start-ip")
                .short("s")
                .takes_value(true)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("Start IP of offered IPs"),
        )
        .arg(
            Arg::with_name("end-ip")
                .long("end-ip")
                .short("e")
                .takes_value(true)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("End IP of offered IPs"),
        )
        .arg(
            Arg::with_name("broadcast")
                .long("broadcast")
                .short("b")
                .takes_value(true)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("End IP of offered IPs"),
        )
        .arg(
            Arg::with_name("mask")
                .long("mask")
                .short("m")
                .takes_value(true)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("Net mask"),
        )
        .arg(
            Arg::with_name("dhcp")
                .long("dhcp")
                .short("i")
                .takes_value(true)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("DHCP server IP. If none, your own IP will be used"),
        )
        .arg(
            Arg::with_name("router")
                .long("router")
                .visible_alias("gateway")
                .short("r")
                .takes_value(true)
                .use_delimiter(true)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("Gateway IP. If none, the DHCP server IP will be used"),
        )
        .arg(
            Arg::with_name("dns")
                .long("dns")
                .short("D")
                .takes_value(true)
                .value_name("ip")
                .use_delimiter(true)
                .validator(helpers::is_ip)
                .help("DNS server IP. If none, the DHCP server IP will be used"),
        )
        .arg(
            Arg::with_name("netbios")
                .long("netbios")
                .visible_alias("wins")
                .short("n")
                .takes_value(true)
                .use_delimiter(true)
                .min_values(0)
                .value_name("ip")
                .validator(helpers::is_ip)
                .help("NetBIOS names server (or WINS server). If present without value, the DHCP server IP will be used"),
        )
        .arg(
            Arg::with_name("wpad")
                .long("wpad")
                .short("w")
                .min_values(0)
                .takes_value(true)
                .value_name("url")
                .help("URL of WPAD file. If present without value, the http://<dhcp-ip>/wpad.dat value will be used"),
        )
        .arg(
            Arg::with_name("domain")
                .long("domain")
                .short("d")
                .takes_value(true)
                .value_name("domain")
                .help("The domain of the network"),
        )
        .arg(
            Arg::with_name("no-bind")
                .long("no-bind")
                .help("Avoid binding to the port in the UDP transport layer to indicate the OS that is going to be used (OS could sent ICMP requests indicating that the port is closed)")
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Increase message verbosity"),
        )
}

pub enum Use<T> {
    Yes(Option<T>),
    No,
}

pub struct Arguments {
    pub iface: NetworkInterface,
    pub start_ip: Option<Ipv4Addr>,
    pub end_ip: Option<Ipv4Addr>,
    pub broadcast: Option<Ipv4Addr>,
    pub net_mask: Option<Ipv4Addr>,
    pub dhcp_server: Option<Ipv4Addr>,
    pub routers: Option<Vec<Ipv4Addr>>,
    pub dns: Option<Vec<Ipv4Addr>>,
    pub udp_bind: bool,
    pub wpad: Use<String>,
    pub domain: Option<String>,
    pub netbios: Use<Vec<Ipv4Addr>>,
    pub verbosity: usize,
}

impl<'a> Arguments {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let iface =
            helpers::lookup_interface(matches.value_of("iface").unwrap())
                .unwrap();

        Self {
            iface,
            start_ip: helpers::parse_ip(matches, "start-ip"),
            end_ip: helpers::parse_ip(matches, "end-ip"),
            broadcast: helpers::parse_ip(matches, "broadcast"),
            net_mask: helpers::parse_ip(matches, "mask"),
            dhcp_server: helpers::parse_ip(matches, "dhcp"),
            routers: helpers::parse_ips(matches, "router"),
            dns: helpers::parse_ips(matches, "dns"),
            wpad: use_string(matches, "wpad"),
            domain: helpers::parse_string(matches, "domain"),
            netbios: use_ips(matches, "netbios"),
            udp_bind: !matches.is_present("no-bind"),
            verbosity: matches.occurrences_of("verbosity") as usize,
        }
    }
}

fn use_string(matches: &ArgMatches, name: &str) -> Use<String> {
    match matches.is_present(name) {
        false => Use::No,
        true => Use::Yes(helpers::parse_string(matches, name)),
    }
}


fn use_ips(matches: &ArgMatches, name: &str) -> Use<Vec<Ipv4Addr>> {
    match matches.is_present(name) {
        false => Use::No,
        true => Use::Yes(helpers::parse_ips(matches, name)),
    }
}


