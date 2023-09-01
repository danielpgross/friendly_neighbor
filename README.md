# Friendly Neighbor

<img src="logo.jpg" alt="Cartoon showing waving computer in doorway of house" width="200" height="200" align="right" />

Friendly Neighbor is a network server that responds to ARP and NDP requests on behalf of other LAN devices. Think of it as applying a set of static IP-to-MAC address mappings for all devices on your LAN.

Its main use-case is enabling network packets to be sent to sleeping machines so that they can be woken up on demand using wake-on-unicast. [This blog post](https://dgross.ca/blog/linux-home-server-auto-sleep/) explains the technique in detail.

## Features
* Super lightweight and performant, built with Zig
* Built with libpcap for efficient, low-overhead packet filtering
* Compiled statically as a single binary without dependencies
* Supports different CPU architectures, including x86 and Raspberry Pi (ARM)
* Supports any flavor of Linux
* Can respond on behalf of multiple machines at once
* IPv4 and IPv6 support

## Prerequisites
* Linux (any distro, kernel version 2.0+)
* Wired Ethernet network interface

## Installation
Coming soon...

## Usage
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