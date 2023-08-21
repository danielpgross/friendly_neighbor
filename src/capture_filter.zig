const std = @import("std");
const MacIpAddressPair = @import("main.zig").MacIpAddressPair;

pub fn generateCaptureFilterExpression(alloc: std.mem.Allocator, ip4_mappings: []const MacIpAddressPair, ip6_mappings: []const MacIpAddressPair) ![]const u8 {
    var pcap_filter_str = std.ArrayList(u8).init(alloc);
    var pcap_filter_writer = pcap_filter_str.writer();

    if (ip4_mappings.len > 0) {
        try generateIp4CaptureFilterExpression(pcap_filter_writer, ip4_mappings);
    }

    if (ip4_mappings.len > 0 and ip6_mappings.len > 0) {
        try pcap_filter_writer.print(" or ", .{});
    }

    if (ip6_mappings.len > 0) {
        try generateIp6CaptureFilterExpression(pcap_filter_writer, ip6_mappings);
    }

    // Null-terminate the filter string
    try pcap_filter_str.append('\x00');

    std.log.debug("PCAP filter: {s}", .{pcap_filter_str.items});

    return pcap_filter_str.toOwnedSlice();
}

fn generateIp4CaptureFilterExpression(pcap_filter_writer: anytype, ip4_mappings: []const MacIpAddressPair) !void {
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

fn generateIp6CaptureFilterExpression(pcap_filter_writer: anytype, ip6_mappings: []const MacIpAddressPair) !void {
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

test "expect correct filter expression with 1 IPv4 mapping" {
    const ip4_mapping = MacIpAddressPair{
        .ip = try std.net.Address.parseIp4("192.168.1.1", 0),
        .mac = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
    };

    const filter_exp = try generateCaptureFilterExpression(std.testing.allocator, &[_]MacIpAddressPair{ip4_mapping}, &[_]MacIpAddressPair{});
    defer std.testing.allocator.free(filter_exp);

    try std.testing.expect(std.mem.eql(u8, "(arp and arp[6:2] == 1 and (arp[24:4] == 0xc0a80101))\x00", filter_exp));
}
