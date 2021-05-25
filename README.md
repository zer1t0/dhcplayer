# DHCPlayer

[![Crates.io](https://img.shields.io/crates/v/dhcplayer)](https://crates.io/crates/dhcplayer)
[![Language Rust](https://img.shields.io/badge/Language-Rust-blue)](https://www.rust-lang.org/)


dhcplayer is a tool to perform several actions using the DHCP protocol, both as client or server. It allows you to perform simple DHCP requests but also perform some known attacks like DHCP starvation or setting a sogue DHCP server.


In order to run dhcplayer, you need `root` privileges to be able to create raw sockets.


## Installation

To install:
```
$ cargo install dhcplayer
```

## DHCP Server

You can create a DHCP server with the `server` command. In the server you can use the parameters to configure the following options:

- Available IP Range
- Broadcast Address
- Network Mask
- Router/Gateway IP (by default yours IP)
- DNS server IP(s) (by default yours IP)
- WPAD file (disabled by default)
- NetBIOS/WINS name server (disabled by default)

```bash
$ sudo dhcplayer server -I eth0 -v --dns 192.168.122.5 --wpad http://wpadserver.local/wpad.dat --netbios 192.168.122.4 --start-ip 192.168.122.60 --end-ip 192.168.122.70
INFO - IP pool: 192.168.122.61-192.168.122.69
INFO - Mask: 255.255.255.0
INFO - Broadcast: 192.168.122.70
INFO - DHCP: 192.168.122.81
INFO - DNS: [192.168.122.5]
INFO - Router: [192.168.122.81]
INFO - Netbios: [192.168.122.4]
INFO - WPAD: http://wpadserver.local/wpad.dat
INFO - DISCOVER from 52:54:00:97:9a:b7
INFO - Offer 192.168.122.69
INFO - REQUEST from 52:54:00:97:9a:b7
INFO - Requested IP 192.168.122.69
INFO - ACK to 192.168.122.69 for 52:54:00:97:9a:b7

```

## Starvation Attack

You can launch a DHCP Starvation attack against DHCP servers by using the `starv` command.

The `starv` command will request all the available IP addresses offered by the DHCP servers in the network. If you want to just target specific servers, you can use the `servers` parameter.

```bash
$ sudo dhcplayer starv -I eth0 --server 192.168.122.1
192.168.122.80 90:25:4f:b0:51:04
192.168.122.118 eb:a3:fd:f4:26:d5
192.168.122.134 c6:f3:bd:ae:d9:ae
...
```

To stop the attack you need to press Ctrl-C. When the attack is stopped, by default, all the acquired IPs will be released. In case you don't want to release them, you can use the `-n/--no-release` flag.


## Discover

The discover command allows you to discover an request the IPs available from a DHCP server.

In the most basic use the command will request an IP from any DHCP server. If you want to request an specific server, you can use the `server` parameter.

```bash
$ sudo dhcplayer discover -I eth0
ACK received from 192.168.122.81
Acquired IP: 192.168.122.67
Client MAC: 52:54:00:97:9a:b7
Options:
[54] DHCP Server ID: 192.168.122.81
[51] IP Address Lease Time: 3600
[58] Renewal Time: 1800
[59] Rebinding Time: 3150
[1] Subnet Mask: 255.255.255.0
[28] Broadcast Address: 192.168.122.70
[3] Router: 192.168.122.81
[6] Domain Server: 192.168.122.5

```

### Discover DHCP servers

Moreover, you can send DISCOVER messages without requesting the IP addresses. You can do this with the `-n/--no-request` flag. In that case, dhcplayer will listen for all the offers made by all the DHCP servers, if there are more than one in the network. 

It can be useful to specify `--options all` to request all the information from a DHCP server.

```bash
$ sudo dhcplayer discover -I eth0 -n --options all

OFFER received from 192.168.122.1
Offered IP: 192.168.122.82
Client MAC: 52:54:00:97:9a:b7
DHCP Server: 192.168.122.1
Options:
[54] DHCP Server ID: 192.168.122.1
[51] IP Address Lease Time: 3600
[58] Renewal Time: 1800
[59] Rebinding Time: 3150
[1] Subnet Mask: 255.255.255.0
[28] Broadcast Address: 192.168.122.255
[3] Router: 192.168.122.1
[6] Domain Server: 192.168.122.1

```

### Inform

Additionally, you can send an INFORM petition instead of DISCOVER by using the `-i/--inform` flag of the `discover` command.

```bash
$ sudo dhcplayer discover -I eth0 -i --options wpad,dns --server 192.168.122.1 -v
INFO - INFORM sent - Client MAC 52:54:00:97:9a:b7

ACK received from 192.168.122.1
Acquired IP: 0.0.0.0
Client MAC: 52:54:00:97:9a:b7
Options:
[54] DHCP Server ID: 192.168.122.1
[1] Subnet Mask: 255.255.255.0
[28] Broadcast Address: 192.168.122.255
[6] Domain Server: 192.168.122.1

```

## Release

You can use the release `command` to release IPs that were acquired by you or other peer. For this you need to specify the IP and the MAC address of the client you want to release.

You can specify the pairs IP/MAC with the format `<ip>-<mac>`. You can indicate the pairs in the command line, or pass them through a file or stdin.

```bash
$ sudo dhcplayer release -I eth2 --server 192.168.100.2 192.168.100.5-ca:2b:d1:21:17:86 192.168.100.7-fe:38:4e:46:95:d6 -v
INFO - RELEASE 192.168.100.5 ca:2b:d1:21:17:86
INFO - RELEASE 192.168.100.7 fe:38:4e:46:95:d6
```


You can also combine this command with an ARP scan to release the IPs of legit clients. The release clients probably continue using its IPs, but those are free to be assigned to other peer, which may cause some problems in the network.

```
$ sudo arplayer scan -I eth2 -w 10 | sudo dhcplayer release -I eth2 --server 192.168.100.2 -v
INFO - RELEASE 192.168.100.1 52:54:00:5b:49:5d
INFO - RELEASE 192.168.100.2 52:54:00:0b:75:57
INFO - RELEASE 192.168.100.7 52:54:00:a4:8c:f2
INFO - RELEASE 192.168.100.5 52:54:00:76:87:bb
```

# Disclaimer

Please, don't use this tool for bad things. I won't assume any responsibility for your actions with this tool.
