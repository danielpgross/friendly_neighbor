const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});

// **********
// Constants
// **********
const PACKET_LENGTH = 78;
const ETHERNET_ARP_PAYLOAD_TYPE = 0x0806;
const ETHERNET_IP6_PAYLOAD_TYPE = 0x86dd;

// **********
// Structs
// **********
const MacIpAddressPair = struct {
    mac: [6]u8,
    ip: std.net.Address,
};

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

const EthernetNdpFrame = packed struct {
    eth_dst_addr: u48,
    eth_src_addr: u48,
    payload_type: u16 = std.mem.nativeToBig(u16, 0x86dd),
    // Version, traffic class, and flow label are stored in a single field
    // Storing `version` as a u4 on its own is gnarly because it's less than a byte, so needs special treatment
    ip_version_traffic_class_flow_label: u32 = std.mem.nativeToBig(u32, 0x60000000),
    ip_payload_len: u16,
    ip_next_header: u8 = 58, // ICMPv6
    ip_hop_limit: u8 = 255,
    ip_src_addr: u128,
    ip_dst_addr: u128,
    icmp_type: u8,
    icmp_code: u8,
    icmp_checksum: u16,
    icmp_flags: u32,
    ndp_target_addr: u128,
    ndp_option_type: u8,
    ndp_option_len: u8,
    ndp_option_eth_addr: u48,
};

const Ip6PseudoHeader = packed struct {
    ip_src_addr: u128,
    ip_dst_addr: u128,
    icmpv6_len: u32,
    padding: u24 = 0,
    next_header: u8 = 58,
};

const EthernetHeader = packed struct {
    eth_dst_addr: u48,
    eth_src_addr: u48,
    payload_type: u16,
};

const CaptureContext = struct {
    handle: *c.pcap_t,
    ip4_mappings: []MacIpAddressPair,
    ip6_mappings: []MacIpAddressPair,
    my_mac_addr: [6]u8,
};

// **********
// Functions
// **********
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const args = try std.process.argsAlloc(gpa.allocator());
    defer std.process.argsFree(gpa.allocator(), args);

    // Parse args into IP:MAC mappings
    const mappings = try parseArgs(gpa.allocator(), args);
    const ip4_mappings = mappings[0];
    defer gpa.allocator().free(ip4_mappings);
    const ip6_mappings = mappings[1];
    defer gpa.allocator().free(ip6_mappings);

    // Generate pcap filter string
    const pcap_filter_exp = try generateCaptureFilterExpression(gpa.allocator(), ip4_mappings, ip6_mappings);
    defer gpa.allocator().free(pcap_filter_exp);

    // Get my MAC address
    const my_mac_addr = try getMyMacAddress();

    // Begin capture
    try beginCapture(ip4_mappings, ip6_mappings, my_mac_addr, pcap_filter_exp);
}

fn parseArgs(alloc: std.mem.Allocator, args: [][:0]const u8) ![2][]MacIpAddressPair {
    var ip4_mappings = std.ArrayList(MacIpAddressPair).init(alloc);
    var ip6_mappings = std.ArrayList(MacIpAddressPair).init(alloc);

    for (args[1..]) |arg| {
        std.debug.print("Arg: {s}\n", .{arg});

        var it = std.mem.tokenizeScalar(u8, arg, '|');
        const mac_addr_slice = it.next() orelse return error.InvalidArgument;
        var mac_addr: [6]u8 = undefined;
        var mac_addr_iter = std.mem.tokenizeScalar(u8, mac_addr_slice, ':');
        var i: usize = 0;
        while (mac_addr_iter.next()) |hexpair| {
            _ = try std.fmt.hexToBytes(mac_addr[i .. i + 1], hexpair);
            i += 1;
        }
        if (it.next()) |nextVal| {
            if (std.net.Address.parseIp4(nextVal, 0)) |ip4| {
                try ip4_mappings.append(MacIpAddressPair{
                    .mac = mac_addr,
                    .ip = ip4,
                });
            } else |_| {}
            if (std.net.Address.parseIp6(nextVal, 0)) |ip6| {
                try ip6_mappings.append(MacIpAddressPair{
                    .mac = mac_addr,
                    .ip = ip6,
                });
            } else |_| {}
        }
    }

    for (ip4_mappings.items) |ip4Mapping| {
        std.debug.print("ip4Mapping: {}, {}\n", .{ std.fmt.fmtSliceHexLower(&ip4Mapping.mac), ip4Mapping.ip });
    }
    for (ip6_mappings.items) |ip6Mapping| {
        std.debug.print("ip6Mapping: {}, {}\n", .{ std.fmt.fmtSliceHexLower(&ip6Mapping.mac), ip6Mapping.ip });
    }

    return [_][]MacIpAddressPair{ try ip4_mappings.toOwnedSlice(), try ip6_mappings.toOwnedSlice() };
}

fn generateCaptureFilterExpression(alloc: std.mem.Allocator, ip4_mappings: []MacIpAddressPair, ip6_mappings: []MacIpAddressPair) ![]u8 {
    var pcap_filter_str = std.ArrayList(u8).init(alloc);
    var pcap_filter_writer = pcap_filter_str.writer();

    // IPv4 addresses
    if (ip4_mappings.len > 0) {
        try pcap_filter_writer.print("(arp and arp[6:2] == 1 and (", .{});
        for (ip4_mappings, 0..) |ip4_mapping, i| {
            if (i > 0) {
                try pcap_filter_writer.print(" or ", .{});
            }
            const bytes = @as(*const [4]u8, @ptrCast(&ip4_mapping.ip.in.sa.addr));
            try pcap_filter_writer.print("arp[24:4] == 0x{}", .{std.fmt.fmtSliceHexLower(bytes)});
        }
        try pcap_filter_writer.print("))", .{});
    }

    if (ip4_mappings.len > 0 and ip6_mappings.len > 0) {
        try pcap_filter_writer.print(" or ", .{});
    }

    // IPv6 addresses
    if (ip6_mappings.len > 0) {
        try pcap_filter_writer.print("(icmp6 and ip6[40] == 135 and (", .{});
        for (ip6_mappings, 0..) |ip6_mapping, i| {
            if (i > 0) {
                try pcap_filter_writer.print(" or ", .{});
            }
            const bytes = @as(*const [16]u8, @ptrCast(&ip6_mapping.ip.in6.sa.addr));
            try pcap_filter_writer.print("(ip6[48:4] == 0x{} and ip6[52:4] == 0x{} and ip6[56:4] == 0x{} and ip6[60:4] == 0x{})", .{
                std.fmt.fmtSliceHexLower(bytes[0..4]),
                std.fmt.fmtSliceHexLower(bytes[4..8]),
                std.fmt.fmtSliceHexLower(bytes[8..12]),
                std.fmt.fmtSliceHexLower(bytes[12..16]),
            });
        }
        try pcap_filter_writer.print("))", .{});
    }
    // Null-terminate the filter string
    try pcap_filter_str.append('\x00');

    std.debug.print("PCAP filter: {s}\n", .{pcap_filter_str.items});

    return pcap_filter_str.toOwnedSlice();
}

// TODO: add support for macOS and Windows
fn getMyMacAddress() ![6]u8 {
    var sysfs_mac_addr_file = try std.fs.openFileAbsoluteZ("/sys/class/net/eth0/address", .{});
    defer sysfs_mac_addr_file.close();

    var sysfs_mac_addr_file_contents: [17]u8 = undefined;
    _ = try sysfs_mac_addr_file.read(&sysfs_mac_addr_file_contents);
    var my_mac_addr: [6]u8 = undefined;
    var sysfs_mac_addr_file_contents_iter = std.mem.tokenizeScalar(u8, &sysfs_mac_addr_file_contents, ':');
    var i: usize = 0;
    while (sysfs_mac_addr_file_contents_iter.next()) |hexpair| {
        _ = try std.fmt.hexToBytes(my_mac_addr[i .. i + 1], hexpair);
        i += 1;
    }
    std.debug.print("My MAC: {}\n", .{std.fmt.fmtSliceHexLower(&my_mac_addr)});

    return my_mac_addr;
}

fn beginCapture(ip4_mappings: []MacIpAddressPair, ip6_mappings: []MacIpAddressPair, my_mac_addr: [6]u8, filter_exp: []u8) !void {
    var error_buffer: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const device = c.pcap_lookupdev(&error_buffer);
    std.debug.print("Device: {s}\n", .{device});

    const handle: *c.pcap_t = c.pcap_open_live(device, PACKET_LENGTH, 1, 1, &error_buffer) orelse return error.OpenLiveFailure;
    defer c.pcap_close(handle);

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
        return error.FilterSetFailure;
    }

    if (c.pcap_loop(handle, 0, packetHandler, @as([*c]u8, @ptrCast(@constCast(&capture_context)))) == -1) {
        return error.LoopFailure;
    }
}

export fn packetHandler(user: [*c]u8, packet_header: [*c]const c.pcap_pkthdr, raw_packet: [*c]const u8) void {
    std.debug.print("Handling packet. Timestamp: {d}, length: {d}\n", .{ packet_header.*.ts.tv_sec, packet_header.*.len });
    const packet = raw_packet[0..packet_header.*.len];
    const capture_context = @as(*align(1) CaptureContext, @ptrCast(user));
    const ethernet_header = @as(*align(1) const EthernetHeader, @ptrCast(packet));

    // TODO: handle errors
    switch (std.mem.bigToNative(u16, ethernet_header.payload_type)) {
        ETHERNET_ARP_PAYLOAD_TYPE => handleIp4Packet(capture_context.handle, packet, capture_context.ip4_mappings, capture_context.my_mac_addr) catch return,
        ETHERNET_IP6_PAYLOAD_TYPE => handleIp6Packet(capture_context.handle, packet, capture_context.ip6_mappings, capture_context.my_mac_addr) catch return,
        else => {
            std.debug.print("Unkown packet type: {d}\n", .{std.mem.bigToNative(u16, ethernet_header.payload_type)});
            return;
        },
    }
}

fn handleIp4Packet(pcap_handle: *c.pcap_t, packet: []const u8, mappings: []MacIpAddressPair, my_mac_addr: [6]u8) !void {
    std.debug.print("Handling IP4 packet\n", .{});

    const arp_frame = @as(*align(1) const EthernetArpFrame, @ptrCast(packet));
    const target_ip_bytes = @as(*const [4]u8, @ptrCast(&arp_frame.target_protocol_addr));
    std.debug.print("Target MAC: {x}", .{arp_frame.target_hardware_addr});
    std.debug.print(", Target IP: {d}.{d}.{d}.{d}\n", .{ target_ip_bytes[0], target_ip_bytes[1], target_ip_bytes[2], target_ip_bytes[3] });

    const target_addr = std.net.Address.initIp4(target_ip_bytes.*, 0);

    var matched_mapping: ?MacIpAddressPair = null;
    for (mappings) |mapping| {
        const mapping_addr = mapping.ip;
        std.debug.print("Compare: {}, {}\n", .{ target_addr, mapping_addr });
        if (std.net.Address.eql(target_addr, mapping_addr)) {
            matched_mapping = mapping;
        }
    }

    const matched_mapping_val = matched_mapping orelse return error.NoMatch;

    sendArpReply(pcap_handle, @as(u48, @bitCast(my_mac_addr)), arp_frame.target_protocol_addr, @as(u48, @bitCast(matched_mapping_val.mac)), arp_frame.sender_protocol_addr, arp_frame.sender_hardware_addr);
}

fn handleIp6Packet(pcap_handle: *c.pcap_t, packet: []const u8, mappings: []MacIpAddressPair, my_mac_addr: [6]u8) !void {
    std.debug.print("Handling IP6 packet\n", .{});

    const ndp_frame = @as(*align(1) const EthernetNdpFrame, @ptrCast(packet));
    const target_ip_bytes = @as(*const [16]u8, @ptrCast(&ndp_frame.ndp_target_addr));

    const target_addr = std.net.Address.initIp6(target_ip_bytes.*, 0, 0, 0);

    var matched_mapping: ?MacIpAddressPair = null;
    for (mappings) |mapping| {
        const mapping_addr = mapping.ip;
        std.debug.print("Compare: {}, {}\n", .{ target_addr, mapping_addr });
        if (std.net.Address.eql(target_addr, mapping_addr)) {
            matched_mapping = mapping;
        }
    }

    const matched_mapping_val = matched_mapping orelse return error.NoMatch;

    sendNdpReply(pcap_handle, @as(u48, @bitCast(my_mac_addr)), ndp_frame.ndp_target_addr, @as(u48, @bitCast(matched_mapping_val.mac)), ndp_frame.ip_src_addr, ndp_frame.eth_src_addr);
}

fn sendArpReply(pcap_handle: *c.pcap_t, my_mac: u48, src_ip: u32, src_mac: u48, dst_ip: u32, dst_mac: u48) void {
    std.debug.print("Matched, sending reply.\n", .{});

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

fn sendNdpReply(pcap_handle: *c.pcap_t, my_mac: u48, src_ip: u128, src_mac: u48, dst_ip: u128, dst_mac: u48) void {
    std.debug.print("Matched, sending reply.\n", .{});

    var packet = EthernetNdpFrame{
        .eth_dst_addr = dst_mac,
        .eth_src_addr = my_mac,
        .ip_payload_len = std.mem.nativeToBig(u16, 32),
        .ip_src_addr = src_ip,
        .ip_dst_addr = dst_ip,
        .icmp_type = 136, // Neighbor advertisement
        .icmp_code = 0,
        .icmp_checksum = 0,
        .icmp_flags = std.mem.nativeToBig(u32, 0x40000000), // Solicited
        .ndp_target_addr = src_ip,
        .ndp_option_type = 2,
        .ndp_option_len = 1,
        .ndp_option_eth_addr = src_mac,
    };

    std.debug.print("Src IP: {x}\n", .{std.mem.bigToNative(u128, src_ip)});
    std.debug.print("Dst IP: {x}\n", .{std.mem.bigToNative(u128, dst_ip)});

    const icmp_checksum = calculateIcmp6Checksum(packet);
    packet.icmp_checksum = std.mem.nativeToBig(u16, icmp_checksum);

    _ = c.pcap_inject(pcap_handle, &packet, @bitSizeOf(EthernetNdpFrame) / 8);
}

fn calculateIcmp6Checksum(ndp_frame: EthernetNdpFrame) u16 {
    const icmpv6_len = std.mem.nativeToBig(u32, std.mem.bigToNative(u16, ndp_frame.ip_payload_len));

    const pseudo_header = Ip6PseudoHeader{
        .ip_src_addr = ndp_frame.ip_src_addr,
        .ip_dst_addr = ndp_frame.ip_dst_addr,
        .icmpv6_len = icmpv6_len,
    };

    const ndp_frame_len = @bitSizeOf(EthernetNdpFrame) / 8;
    const ndp_frame_bytes = @as(*const [ndp_frame_len]u8, @ptrCast(&ndp_frame));
    const target_ndp_frame_bytes = ndp_frame_bytes[@offsetOf(EthernetNdpFrame, "icmp_type")..ndp_frame_len];
    const pseudo_header_len = @bitSizeOf(Ip6PseudoHeader) / 8;
    const pseudo_header_bytes = @as(*const [pseudo_header_len]u8, @ptrCast(&pseudo_header));

    var checksum_target: [pseudo_header_len + target_ndp_frame_bytes.len]u8 = undefined;
    @memcpy(checksum_target[0..pseudo_header_len], pseudo_header_bytes);
    @memcpy(checksum_target[pseudo_header_len..checksum_target.len], target_ndp_frame_bytes);

    var sum: u32 = 0;
    const checksum_target_words = @as(*align(1) const [checksum_target.len / 2]u16, @ptrCast(&checksum_target));
    std.debug.print("Words: ", .{});
    for (checksum_target_words) |word| {
        const native_word = std.mem.bigToNative(u16, word);
        std.debug.print("{X:0>4}", .{native_word});
        sum += native_word;
    }
    std.debug.print("\n", .{});

    // Fold the 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum + (sum >> 16);
    var folded_sum: u16 = @intCast(sum);

    return ~folded_sum;
}

// **********
// Tests
// **********
//test "icmpv6 checksum" {
//     const dst_mac = std.mem.nativeToBig(u48, 0x222222222222);
//     const my_mac = std.mem.nativeToBig(u48, 0xaaaaaaaaaaaa);
//     const src_mac = std.mem.nativeToBig(u48, 0x111111111111);
//     const src_ip = std.mem.nativeToBig(u128, 0x2001db8333344445555666677778888);
//     const dst_ip = std.mem.nativeToBig(u128, 0x2001db833334444CCCCDDDDEEEEFFFF);

//     const packet = EthernetNdpFrame{
//         .eth_dst_addr = dst_mac,
//         .eth_src_addr = my_mac,
//         .payload_type = std.mem.nativeToBig(u16, 0x86dd), // IPv6
//         .ip_payload_len = std.mem.nativeToBig(u16, 32),
//         .ip_next_header = 58, // ICMPv6
//         .ip_hop_limit = 255,
//         .ip_src_addr = src_ip,
//         .ip_dst_addr = dst_ip,
//         .icmp_type = 136, // Neighbor advertisement
//         .icmp_code = 0,
//         .icmp_checksum = 0,
//         .icmp_flags = std.mem.nativeToBig(u32, 0x40000000), // Solicited
//         .ndp_target_addr = src_ip,
//         .ndp_option_type = 2,
//         .ndp_option_len = 1,
//         .ndp_option_eth_addr = src_mac,
//     };

//     std.debug.print("align of EthernetNdpFrame: {d}\n", .{@alignOf(EthernetNdpFrame)});

//     const result = calculateIcmp6Checksum(packet);
//     std.debug.print("checksum: {d}", .{result});
// }

test "expect correctly parsed mappings with 1 IPv4 mapping arg" {
    const alloc = std.testing.allocator;
    var args = [_][:0]const u8{ "friendly_neighbor", "11:22:33:44:55:66|192.168.1.1" };

    const mappings = try parseArgs(alloc, &args);
    const ip4_mappings = mappings[0];
    defer alloc.free(ip4_mappings);
    const ip6_mappings = mappings[1];
    defer alloc.free(ip6_mappings);

    try std.testing.expect(ip4_mappings.len == 1);
    try std.testing.expect(ip6_mappings.len == 0);
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip4_mappings[0].mac));
    const expectedAddr = try std.net.Address.parseIp4("192.168.1.1", 0);
    try std.testing.expect(std.net.Address.eql(expectedAddr, ip4_mappings[0].ip));
}
