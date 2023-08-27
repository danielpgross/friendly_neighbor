const c = @cImport({
    @cInclude("pcap.h");
});
const std = @import("std");
const main = @import("main.zig");
const capture = @import("capture.zig");

const log = main.log;
const MacIpAddressPair = main.MacIpAddressPair;

const EthernetArpFrame = packed struct {
    eth_dst_addr: u48,
    eth_src_addr: u48,
    payload_type: u16,
    hardware_type: u16,
    protocol_type: u16,
    hardware_addr_len: u8,
    protocol_addr_len: u8,
    operation: u16,
    sender_hardware_addr: u48,
    sender_protocol_addr: u32,
    target_hardware_addr: u48,
    target_protocol_addr: u32,
};

fn sendArpReply(pcap_handle: *c.pcap_t, my_mac: u48, src_ip: u32, src_mac: u48, dst_ip: u32, dst_mac: u48) void {
    log.debug("Matched, sending ARP reply.", .{});

    const packet = EthernetArpFrame{
        .eth_dst_addr = dst_mac,
        .eth_src_addr = my_mac,
        .payload_type = std.mem.nativeToBig(u16, 0x0806),
        .hardware_type = std.mem.nativeToBig(u16, 1),
        .protocol_type = std.mem.nativeToBig(u16, 0x0800),
        .hardware_addr_len = 6,
        .protocol_addr_len = 4,
        .operation = std.mem.nativeToBig(u16, 2),
        .sender_hardware_addr = src_mac,
        .sender_protocol_addr = src_ip,
        .target_hardware_addr = dst_mac,
        .target_protocol_addr = dst_ip,
    };

    _ = c.pcap_inject(pcap_handle, &packet, @bitSizeOf(EthernetArpFrame) / 8);
}

pub fn handleIp4Packet(pcap_handle: *c.pcap_t, packet: []const u8, mappings: []const MacIpAddressPair, my_mac_addr: [6]u8) !void {
    log.debug("Handling IP4 packet", .{});

    const arp_frame = @as(*align(1) const EthernetArpFrame, @ptrCast(packet));
    const target_ip_bytes = @as(*const [4]u8, @ptrCast(&arp_frame.target_protocol_addr));
    log.debug("Target MAC: {x}", .{arp_frame.target_hardware_addr});
    log.debug(", Target IP: {d}.{d}.{d}.{d}", .{ target_ip_bytes[0], target_ip_bytes[1], target_ip_bytes[2], target_ip_bytes[3] });

    const target_addr = std.net.Address.initIp4(target_ip_bytes.*, 0);
    const matched_mapping = try capture.findMatchingMacIpMapping(mappings, target_addr);

    sendArpReply(pcap_handle, @as(u48, @bitCast(my_mac_addr)), arp_frame.target_protocol_addr, @as(u48, @bitCast(matched_mapping.mac)), arp_frame.sender_protocol_addr, arp_frame.sender_hardware_addr);
}
