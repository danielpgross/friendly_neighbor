const c = @cImport({
    @cInclude("pcap.h");
});
const std = @import("std");
const main = @import("main.zig");
const ip4 = @import("ip4.zig");
const ip6 = @import("ip6.zig");
const log = main.log;
const MacIpAddressPair = main.MacIpAddressPair;

const PACKET_LENGTH = 78;
const ETHERNET_ARP_PAYLOAD_TYPE = 0x0806;
const ETHERNET_IP6_PAYLOAD_TYPE = 0x86dd;

const CaptureContext = struct {
    handle: *c.pcap_t,
    ip4_mappings: []const MacIpAddressPair,
    ip6_mappings: []const MacIpAddressPair,
    my_mac_addr: [6]u8,
};

pub const EthernetHeader = packed struct {
    eth_dst_addr: u48,
    eth_src_addr: u48,
    payload_type: u16,
};

pub fn beginCapture(interface_name: []const u8, ip4_mappings: []const MacIpAddressPair, ip6_mappings: []const MacIpAddressPair, my_mac_addr: [6]u8, filter_exp: []const u8) !void {
    var error_buffer: [c.PCAP_ERRBUF_SIZE:0]u8 = undefined;
    error_buffer[0] = '\x00';

    const handle: *c.pcap_t = c.pcap_open_live(@as([*c]const u8, @ptrCast(interface_name)), PACKET_LENGTH, 1, 1, &error_buffer) orelse {
        log.err("Failed to open packet capture handle: {s}", .{@as([*:0]const u8, &error_buffer)});
        return error.OpenLiveFailure;
    };
    defer c.pcap_close(handle);

    // Even if pcap_open_live didn't fail outright, a warning might have been written to the error buffer
    if (error_buffer[0] != '\x00') {
        log.warn("While opening packet capture handle: {s}", .{@as([*:0]const u8, &error_buffer)});
    }

    const capture_context = CaptureContext{
        .handle = handle,
        .ip4_mappings = ip4_mappings,
        .ip6_mappings = ip6_mappings,
        .my_mac_addr = my_mac_addr,
    };

    var filter: c.bpf_program = undefined;
    if (c.pcap_compile(handle, &filter, @as([*c]const u8, @ptrCast(filter_exp)), 0, c.PCAP_NETMASK_UNKNOWN) == -1) {
        c.pcap_perror(handle, "pcap");
        return error.FilterCompileFailure;
    }
    if (c.pcap_setfilter(handle, &filter) == -1) {
        c.pcap_perror(handle, "pcap");
        return error.FilterSetFailure;
    }

    log.info("Listening on interface {s}...", .{interface_name});

    if (std.io.getStdErr().isTty()) {
        log.info("Press Ctrl+C to stop...", .{});
    }

    if (c.pcap_loop(handle, 0, packetHandler, @as([*c]u8, @ptrCast(@constCast(&capture_context)))) == -1) {
        c.pcap_perror(handle, "pcap");
        return error.LoopFailure;
    }
}

export fn packetHandler(user: [*c]u8, packet_header: [*c]const c.pcap_pkthdr, raw_packet: [*c]const u8) void {
    log.debug("Handling packet. Timestamp: {d}, length: {d}", .{ packet_header.*.ts.tv_sec, packet_header.*.len });
    const packet = raw_packet[0..packet_header.*.len];
    const capture_context = @as(*align(1) CaptureContext, @ptrCast(user));
    const ethernet_header = @as(*align(1) const EthernetHeader, @ptrCast(packet));

    switch (std.mem.bigToNative(u16, ethernet_header.payload_type)) {
        ETHERNET_ARP_PAYLOAD_TYPE => ip4.handleIp4Packet(capture_context.handle, packet, capture_context.ip4_mappings, capture_context.my_mac_addr) catch
            log.err("Error while handling ARP packet.", .{}),
        ETHERNET_IP6_PAYLOAD_TYPE => ip6.handleIp6Packet(capture_context.handle, packet, capture_context.ip6_mappings, capture_context.my_mac_addr) catch
            log.err("Error while handling NDP packet.", .{}),
        else => log.err("Received packet with unknown type: {d}", .{std.mem.bigToNative(u16, ethernet_header.payload_type)}),
    }
}

pub fn findMatchingMacIpMapping(mappings: []const MacIpAddressPair, target_addr: std.net.Address) !MacIpAddressPair {
    var matched_mapping: ?MacIpAddressPair = null;
    for (mappings) |mapping| {
        const mapping_addr = mapping.ip;
        log.debug("Compare: {}, {}", .{ target_addr, mapping_addr });
        if (std.net.Address.eql(target_addr, mapping_addr)) {
            matched_mapping = mapping;
        }
    }

    if (matched_mapping == null) {
        log.err("No mapping found for packet target IP address: {}", .{target_addr});
        return error.NoMatch;
    }

    return matched_mapping.?;
}
