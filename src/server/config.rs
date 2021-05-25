use crate::args;
use crate::args::server::Use;
use crate::helpers::get_iface_ipv4_network;
use pnet::util::MacAddr;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

pub fn generate_server_config(
    args: &args::server::Arguments,
) -> Result<ServerConfig, String> {
    let iface = &args.iface;
    let iface_net = get_iface_ipv4_network(&iface).ok_or_else(|| {
        format!("Unable to get the network of {} interface", iface.name)
    })?;

    let my_ip = iface_net.ip();

    let start_ip_int: u32 = match args.start_ip {
        Some(ip) => ip,
        None => iface_net.network(),
    }
    .into();
    let start_ip = Ipv4Addr::from(start_ip_int + 1);

    let end_ip_int: u32 = match args.end_ip {
        Some(ip) => ip,
        None => iface_net.broadcast(),
    }
    .into();
    let end_ip = Ipv4Addr::from(end_ip_int - 1);

    let broadcast = match args.broadcast {
        Some(ip) => ip,
        None => Ipv4Addr::from(end_ip_int),
    };

    let net_mask = match args.net_mask {
        Some(ip) => ip,
        None => iface_net.mask(),
    };

    let dhcp_server = match args.dhcp_server {
        Some(ip) => ip,
        None => my_ip,
    };

    let routers = match &args.routers {
        Some(ips) => ips.clone(),
        None => vec![dhcp_server],
    };

    let domain_servers = match &args.dns {
        Some(ips) => ips.clone(),
        None => vec![dhcp_server],
    };

    let netbios_servers = match &args.netbios {
        Use::No => None,
        Use::Yes(nbss) => Some(match nbss {
            Some(nbss) => nbss.clone(),
            None => vec![dhcp_server],
        })
    };

    let wpad = match &args.wpad {
        Use::No => None,
        Use::Yes(wpad) => Some(match wpad {
            Some(wpad) => wpad.clone(),
            None => format!("http://{}/wpad.dat", dhcp_server),
        }),
    };

    let domain = args.domain.clone();

    let dhcp_config = ServerConfig {
        ip_lease_time: 3600,
        renewal_time: 1800,
        rebinding_time: 3150,
        ips_pool: IpsPool::new(start_ip, end_ip),
        start_ip,
        end_ip,
        net_mask,
        broadcast,
        my_ip,
        dhcp_server,
        routers,
        domain_servers,
        netbios_servers,
        domain,
        wpad,
    };

    return Ok(dhcp_config);
}

pub struct ServerConfig {
    pub ip_lease_time: u32,
    pub renewal_time: u32,
    pub rebinding_time: u32,

    pub ips_pool: IpsPool,
    pub start_ip: Ipv4Addr,
    pub end_ip: Ipv4Addr,
    pub net_mask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    pub my_ip: Ipv4Addr,

    pub dhcp_server: Ipv4Addr,
    pub routers: Vec<Ipv4Addr>,
    pub domain_servers: Vec<Ipv4Addr>,
    pub netbios_servers: Option<Vec<Ipv4Addr>>,

    pub domain: Option<String>,
    pub wpad: Option<String>,
}

impl ServerConfig {
    pub fn is_available_ip(&self, ip: &Ipv4Addr) -> bool {
        return self.ips_pool.is_available_ip(ip);
    }
    pub fn get_available_ip(&self) -> Option<Ipv4Addr> {
        return self.ips_pool.get_available_ip();
    }

    pub fn get_client_ip(&self, client_mac: &MacAddr) -> Option<Ipv4Addr> {
        return self.ips_pool.get_client_ip(client_mac);
    }

    pub fn mark_ip_as_used(
        &mut self,
        client_mac: MacAddr,
        ip: Ipv4Addr,
    ) -> Result<(), String> {
        return self.ips_pool.mark_ip_as_used(client_mac, ip);
    }

    pub fn release_client_ip(&mut self, client_mac: &MacAddr) {
        return self.ips_pool.release_client_ip(client_mac);
    }

    pub fn release_ip(&mut self, ip: &Ipv4Addr) {
        return self.ips_pool.release_ip(ip);
    }
}

pub struct IpsPool {
    available_ips: HashSet<Ipv4Addr>,
    in_use_ips: HashMap<MacAddr, Ipv4Addr>,
}

impl IpsPool {
    pub fn new(start_ip: Ipv4Addr, end_ip: Ipv4Addr) -> Self {
        let mut ips = HashSet::new();

        let end_ip_int: u32 = end_ip.into();
        let mut ip_int: u32 = start_ip.into();
        while ip_int <= end_ip_int {
            ips.insert(Ipv4Addr::from(ip_int));
            ip_int += 1;
        }

        return Self {
            available_ips: ips,
            in_use_ips: HashMap::new(),
        };
    }

    pub fn is_available_ip(&self, ip: &Ipv4Addr) -> bool {
        return self.available_ips.contains(ip);
    }

    pub fn get_available_ip(&self) -> Option<Ipv4Addr> {
        return self.available_ips.iter().next().map(|ip| *ip);
    }

    pub fn get_client_ip(&self, client_mac: &MacAddr) -> Option<Ipv4Addr> {
        return self.in_use_ips.get(client_mac).map(|ip| *ip);
    }

    pub fn mark_ip_as_used(
        &mut self,
        client_mac: MacAddr,
        ip: Ipv4Addr,
    ) -> Result<(), String> {
        if !self.available_ips.remove(&ip) {
            return Err(format!("IP {} is not available", ip));
        }

        self.in_use_ips.insert(client_mac, ip);

        return Ok(());
    }

    pub fn release_client_ip(&mut self, client_mac: &MacAddr) {
        match self.in_use_ips.remove(client_mac) {
            Some(client_ip) => {
                self.available_ips.insert(client_ip);
            }
            None => {}
        };
    }

    pub fn release_ip(&mut self, ip: &Ipv4Addr) {
        let keys: Vec<MacAddr> = self.in_use_ips.keys().map(|k| *k).collect();
        for k in keys {
            let current_ip = *self.in_use_ips.get(&k).unwrap();
            if current_ip == *ip {
                self.in_use_ips.remove(&k);
                self.available_ips.insert(current_ip);
            }
        }
    }
}
