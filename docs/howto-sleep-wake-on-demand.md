# How-To: Automatic sleep and wake-on-demand for Linux
{:.no_toc}

Say you've got a Linux server that's used intermittently by other devices on the network, e.g. for backups or serving media. Wouldn't it be nice if it could sleep when idle and automatically wake up whenever it's needed again?

In the past, this was achieved using wake-on-LAN with magic packets: any device accessing the server would need to first send a magic packet to ensure the server is awake to answer requests. This solution was inconvenient because it required manual action (e.g. running a command to send a magic packet) *every time* the server was being accessed. Though it could sometimes be automated using scripts or special configuration, doing so was cumbersome.

Here you'll find a straightforward and reliable technique to achieve this goal *without* manual action or special configuration on devices accessing the server. It uses wake-on-unicast (a variant of traditional wake-on-LAN) combined with a "friendly neighbor" device that keeps the server reachable while it sleeps. If you're curious to understand more about how it works, check out the [original blog post](https://dgross.ca/blog/linux-home-server-auto-sleep/).

## Contents
{:.no_toc}

* TOC
{:toc}

## Overview

This guide deals with the example of a server used to host macOS Time Machine backups using [Netatalk](https://en.wikipedia.org/wiki/Netatalk) and the [AFP protocol](https://en.wikipedia.org/wiki/Apple_Filing_Protocol). **The steps below work for other network services and protocols too**, not just AFP and Netatalk.

<img src="./overview-diagram.svg" style="display: block; margin: 0 auto; width: 100%; max-width: 750px" />

### Outcome
* Server suspends to RAM when idle
* Server wakes when needed by *anything* else on the network, including SSH, Time Machine backups, etc.

### What you'll need
* An always-on Linux device on the same network as your server, e.g. a Raspberry Pi
* A wired network interface device for your server that supports wake-on-LAN with unicast packets
* To prevent unwanted wake-ups, you'll need to ensure no device on the network is sending extraneous packets to the server

## Steps

*These specific instructions were written for Ubuntu Linux 22.04, but should be easily adaptable to other Ubuntu versions and other `systemd`-based Linux distributions.*

### 1. On the server
* Enable wake-on-LAN with unicast packets (not just magic packets) and make it persistent

```shell
sudo ethtool -s eno1 wol ug
sudo tee /etc/networkd-dispatcher/configuring.d/wol << EOF
#!/usr/bin/env bash

ethtool -s eno1 wol ug || true
EOF
sudo chmod 755 /etc/networkd-dispatcher/configuring.d/wol
```

* Set up a cron job to sleep on idle (replace `/home/ubuntu` with your desired script location)
  * The script checks connections to port 548, which is used by AFP. If you're using a different protocol, change the port number accordingly.

```shell
tee /home/ubuntu/auto-sleep.sh << EOF
#!/bin/bash
logged_in_count=$(who | wc -l)
# We expect 2 lines of output from `lsof -i:548` at idle: one for output headers, another for the 
# server listening for connections. More than 2 lines indicates inbound connection(s).
afp_connection_count=$(lsof -i:548 | wc -l)
if [[ $logged_in_count < 1 && $afp_connection_count < 3 ]]; then
  systemctl suspend
else
  echo "Not suspending, logged in users: $logged_in_count, connection count: $afp_connection_count"
fi
EOF
chmod +x /home/ubuntu/auto-sleep.sh
sudo crontab -e
# In the editor, add the following line:
*/10 * * * * /home/ubuntu/auto-sleep.sh | logger -t autosuspend
```

* *Optional:* Configure network services (e.g. Netatalk) to stop before sleep, ensuring that existing connections are closed before the machine goes to sleep.
  * If this step is skipped, the server might wake up prematurely due to activity from unclosed network connections.
  * This step is only needed for services that keep persistent network connections.
  * If you are using a different service than Netatalk, replace the below references to Netatalk with the relevant service name.

``` shell
sudo tee /etc/systemd/system/netatalk-sleep.service << EOF
[Unit]
Description=Netatalk sleep hook
Before=sleep.target
StopWhenUnneeded=yes

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=-/usr/bin/systemctl stop netatalk
ExecStop=-/usr/bin/systemctl start netatalk

[Install]
WantedBy=sleep.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable netatalk-sleep.service
```

### 2. On the LAN router (or other DHCP server)
* Set up a DHCP reservation (sometimes called "Static DHCP Lease", "Fixed DHCP Assignment", or "Persistent DHCP Lease") for the server to ensure it's always assigned the same network address(es) on the LAN.
  * Make a note of the IP and MAC addresses, as they will be used below.
  * If your LAN uses both IPv4 and IPv6, ensure that the reservation includes both an IPv4 and IPv6 address.
  * The exact steps here will vary depending on your router model, but this is a common procedure that should be described in your device's documentation.

### 3. On the always-on device
* Install [Friendly Neighbor](https://github.com/danielpgross/friendly_neighbor), a lightweight network service that responds to ARP (IPv4) and NDP (IPv6) requests on behalf of another machine.

```shell
sudo snap install friendly-neighbor
sudo snap connect friendly-neighbor:hardware-observe
sudo snap connect friendly-neighbor:network-control
# Replace the values for "mac-ip-mappings" and "interface-name" below with your real ones.
# The mapping(s) should be the MAC and IP address(es) used for the DHCP reservation(s) in the previous step.
# Each mapping is in the format [MAC address],[IP address]
# Multiple mappings are separated by a single space character.
# If the server only has an IPv4 address, simply leave out the second mapping.
sudo snap set friendly-neighbor mac-ip-mappings="AA:BB:CC:DD:EE:FF,10.0.1.2 AA:BB:CC:DD:EE:FF,fd9a:bc83:57e4:2::1" interface-name=eth0
sudo snap restart friendly-neighbor
```

* *Optional:* Configure Avahi to advertise network services on behalf of the server when it's sleeping.
  * This step is only necessary if Apple devices on the network will be using the Bonjour protocol (mDNS, specifically) to resolve the server's hostname. Time Machine, for example, relies on this mechanism.

```shell
sudo apt install avahi-daemon
sudo tee /etc/systemd/system/avahi-publish.service << EOF
[Unit]
Description=Publish custom Avahi records
After=network.target avahi-daemon.service
Requires=avahi-daemon.service

[Service]
ExecStart=/usr/bin/avahi-publish -s homeserver _afpovertcp._tcp 548 -H homeserver.local

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable avahi-publish.service --now
systemctl status avahi-publish.service
```

# FAQ

#### Why bother setting up automatic sleeping and waking when I can just use a low-power device (e.g. Raspberry Pi) and keep it on all the time?

Low-power devices like Raspberry Pi are great, but they might not be an option for the server in question. For example, the server might need to perform heavy-duty workloads that require more powerful and more energy-consuming hardware. Or, maybe you just have an older, more energy-consuming machine sitting around and want to put it to use, rather than buying new hardware. This approach helps you make the most of the hardware you already have.

#### I can just enable wake-on-LAN and then send a magic packet to my server to wake it up. Why are all these other steps necessary?

Yes, you could. The thing with using magic packets is that the device trying to access your server *needs to know how to wake it up* using a magic packet. If you have multiple devices accessing your server, *each one will need to be set up with custom logic to wake up the server before trying to access it*.

The advantage with this approach is that the server awakens with any ordinary packet it receives. The accessing device (client) doesn't need to know anything about waking the server &mdash; in fact, it doesn't even need to know that the server might be asleep. This approach involves a bit more setup on the server, but makes it unnecessary to do any setup on client devices.

#### Why is the Friendly Neighbor service necessary? Can't I just send unicast packets directly to the server?

Yes, and it would work, but only for a very short time (a few minutes) after the server goes to sleep. Why only for a few minutes? Because that's how long ARP/NDP responses remain cached. After that, devices accessing the server fail to resolve the server's IP address to its MAC address. Without knowing its MAC address, they can't send it unicast packets, and the server remains in blissful slumber. Friendly Neighbor allows the server's MAC address to be resolved while it's asleep, thereby enabling other devices to send unicast packets to it.

#### Why not just set up static ARP entries instead of using the Friendly Neighbor service?

This is a legitimate alternative to using Friendly Neighbor, but it requires the extra work of maintaining a static ARP entry on *every device that will access the server*. With Friendly Neighbor, any device can access the server while it's sleeping, without any prior setup.

#### How long does it take for the machine to wake up and respond to requests?

This is heavily dependent on the server's hardware. On an example late-2010s PC server with a spinning hard disk, it takes 10-15 seconds from when the sleeping server receives a unicast packet until it's awake and responding to network requests.

#### Will all the sleep/wake cycles wear down my hard drive?

It's true that spinning magnetic platter hard disk drives (HDDs) are slowly worn down by repeated on/off cycles that stress their moving components. Solid state drives (SSDs), on the other hand, don't have this concern because they have no moving parts.

If your server uses an HDD, consider the sleep/wake patterns you expect your server to have. Desktop-grade drives are typically rated for ~500,000 on/off cycles before failure. If your server will only wake once a day (e.g. to perform a backup), there's no concern: it should take 500+ years to reach the rated maximum cycle count. If your server will wake many times per day, however, you might instead choose an SSD or opt to keep your server awake all the time.

#### Is this setup reliable? Will it stop working every time I update my OS?

It has proven to be reliable across multiple system updates in the original author's experience, over the span of months. There have been a few minor annoyances, like needing to restart twice after a major system update for wake-on-unicast to become active. If you find any improvements through your own use, you're strongly encouraged to contribute them back to this guide by submitting a pull request.

# Getting help

**If you're having trouble with automatic sleep and wake-on-demand:**
* Check the [Q&A category of the **Discussions** section in this repository](https://github.com/danielpgross/friendly_neighbor/discussions/categories/q-a) to see if any existing discussions address your issue
* If no existing discussions address it, [start a new discussion](https://github.com/danielpgross/friendly_neighbor/discussions/new?category=q-a)

**If you've found an issue with the Friendly Neighbor network service itself:**
* Do a quick search in the [**Issues** section of this repository](https://github.com/danielpgross/friendly_neighbor/issues) to see if it has already been reported
* If it hasn't been reported, [create a new issue](https://github.com/danielpgross/friendly_neighbor/issues/new)

Keep in mind that this is a community project maintained by volunteers. There are no guarantees of a timely response or resolution to your issue. Remember to be nice!