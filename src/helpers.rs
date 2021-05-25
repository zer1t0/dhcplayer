use pnet::{datalink::NetworkInterface, ipnetwork::{IpNetwork, Ipv4Network}};




pub fn get_iface_ipv4_network(
    iface: &NetworkInterface,
) -> Option<&Ipv4Network> {
    iface.ips.iter().find(|ip| ip.is_ipv4()).map(|ip| match ip {
        IpNetwork::V4(net) => net,
        _ => unreachable!(),
    })
}
