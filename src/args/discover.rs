use std::{net::Ipv4Addr, time::Duration};

use clap::{App, Arg, ArgMatches, SubCommand};
use pnet::{datalink::NetworkInterface, util::MacAddr};

use super::helpers;

pub const COMMAND_NAME: &str = "discover";

pub fn command() -> App<'static, 'static> {
    SubCommand::with_name(COMMAND_NAME)
        .about("DHCP discover")
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
            Arg::with_name("mac")
                .long("mac")
                .short("m")
                .required(false)
                .takes_value(true)
                .validator(helpers::is_mac)
                .help("MAC to use for requests"),
        )
        .arg(
            Arg::with_name("keep-ether")
                .long("keep-ether")
                .short("k")
                .help("Use the iface MAC in the Ethernet frame"),
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
            Arg::with_name("inform")
                .long("inform")
                .short("i")
                .help("Send an INFORM request")
                .conflicts_with_all(&["no-request"]),
        )
        .arg(
            Arg::with_name("no-request")
                .long("no-request")
                .short("n")
                .help("Just send a DISCOVER message without requesting the IP. It listen for all the OFFERs sent by DHCP servers"),
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .short("s")
                .value_name("ip")
                .takes_value(true)
                .use_delimiter(true)
                .validator(helpers::is_ip)
                .help("DHCP server to request. If none, any server can be used"),
        )
        .arg(
            Arg::with_name("options")
                .long("options")
                .short("o")
                .value_name("option")
                .use_delimiter(true)
                .validator(helpers::is_dhcp_option)
                .help("Indicate the DHCP options, separated by commas, that want to be retrieved, it must be a byte or a value in [all, none, broadcast, dns, domain, mask, netbios, router, wins, wpad]"),
        )
        .arg(
            Arg::with_name("fqdn")
                .long("fqdn")
                .takes_value(true)
                .help("Fully Qualified Domain Name of the client (the hostname with the domain)")
        )
        .arg(
            Arg::with_name("dns-update")
                .long("dns-update")
                .help("Requests creation of DNS record using the given FQDN or hostname. If none of them are given, can be used to delete the DNS record.")
        )
        .arg(
            Arg::with_name("hostname")
                .long("hostname")
                .short("H")
                .takes_value(true)
                .help("Hostname to send in the petition")
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
    pub mac: Option<MacAddr>,
    pub keep_ether: bool,
    pub inform: bool,
    pub send_request: bool,
    pub options: Option<Vec<u8>>,
    pub servers: Option<Vec<Ipv4Addr>>,
    pub hostname: Option<String>,
    pub fqdn: Option<String>,
    pub dns_update: bool,
    pub verbosity: usize,
}

impl<'a> Arguments {
    pub fn parse(matches: &'a ArgMatches) -> Arguments {
        let iface =
            helpers::lookup_interface(matches.value_of("iface").unwrap())
                .unwrap();

        Self {
            iface,
            timeout: Duration::from_millis(
                matches.value_of("timeout").unwrap().parse().unwrap(),
            ),
            mac: helpers::parse_mac(matches, "mac"),
            keep_ether: matches.is_present("keep-ether"),
            options: helpers::parse_options(matches, "options"),
            inform: matches.is_present("inform"),
            send_request: !matches.is_present("no-request"),
            servers: helpers::parse_ips(matches, "server"),
            hostname: helpers::parse_string(matches, "hostname"),
            fqdn: helpers::parse_string(matches, "fqdn"),
            dns_update: matches.is_present("dns-update"),
            verbosity: matches.occurrences_of("verbosity") as usize,
        }
    }
}
