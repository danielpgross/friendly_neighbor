# Friendly Neighbor

[![friendly-neighbor](https://snapcraft.io/friendly-neighbor/badge.svg)](https://snapcraft.io/friendly-neighbor)

<img src="logo.jpg" alt="Cartoon showing waving computer in doorway of house" width="200" height="200" align="right" />

Friendly Neighbor is a network server that responds to ARP and NDP requests on behalf of other LAN devices. Think of it as applying a set of static IP-to-MAC address mappings for all devices on your LAN.

Its main use-case is enabling network packets to be sent to sleeping machines so that they can be woken up on demand using wake-on-unicast. [This blog post](https://dgross.ca/blog/linux-home-server-auto-sleep/) explains the technique in detail.

## Features
* Super lightweight and performant, built with Zig
* Built with libpcap for efficient, low-overhead packet filtering
* Supports different CPU architectures, including x86_64 and Raspberry Pi (ARM64)
* Distributed as a universal [Snap package](https://snapcraft.io/) for easy installation on many Linux distros
* Can respond on behalf of multiple machines at once
* IPv4 and IPv6 support

## Prerequisites
* Linux (any distro supporting Snap packages, kernel version 2.6.27+)
* Wired Ethernet network interface

## Installation

[![Get it from the Snap Store](https://snapcraft.io/static/images/badges/en/snap-store-black.svg)](https://snapcraft.io/friendly-neighbor)

```
sudo snap install friendly-neighbor
sudo snap connect friendly-neighbor:hardware-observe
sudo snap connect friendly-neighbor:network-control
# Replace the values for "mac-ip-mappings" and "interface-name" below with your real ones:
sudo snap set friendly-neighbor mac-ip-mappings=AA:BB:CC:DD:EE:FF,10.0.8.3 interface-name=eth0
sudo snap restart friendly-neighbor
```

The Snap package is configured to run automatically Friendly Neighbor as a network service (daemon). After performing the steps above, the service should be running and should automatically start on subsequent system startups.

## Usage

The following usage details are only relevant when running the service directly. If using the Snap package, service parameters are set using `snap set friendly-neighbor ...`

```
USAGE
    friendly_neighbor [-hv] [-i <IFACE>] [-m <MAPPING>...] [--mappings <MAPPINGS>]

OPTIONS
    -i, --interface <IFACE>
            Name of network interface on which to listen and send packets

    -m, --mapping <MAPPING>...
            One or more MAC to IP (v4 or v6) address mappings, each in the
            format <MAC address>,<IP address>

        --mappings <MAPPINGS>
            A single string containing one or more mappings in the format <MAC
            address>,<IP address> with mappings separated by a space

    -h, --help
            Display this help and exit

    -v, --version
            Print program version and exit

EXAMPLES
    friendly_neighbor -i eth0 \
        -m 11:22:33:44:55:66,192.168.1.2 \
        -m 11:22:33:44:55:66,fd12:3456:789a:1::1

    friendly_neighbor -i eno1 --mappings \
        "AA:BB:CC:DD:EE:FF,10.0.8.3 AA:BB:CC:DD:EE:FF,fd9a:bc83:57e4:2::1"
```

## Contributing
Contributions are welcome, pull requests and issues can be created at https://github.com/danielpgross/friendly_neighbor

## License
MIT

Happy networking, and remember to be a friendly neighbor! 🌐💻