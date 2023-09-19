const c = @cImport({
    @cInclude("pcap.h");
});
const std = @import("std");
const main = @import("main.zig");
const capture = @import("capture.zig");

const log = main.log;
const MacIpAddressPair = main.MacIpAddressPair;

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

pub fn handleIp6Packet(pcap_handle: *c.pcap_t, packet: []const u8, mappings: []const MacIpAddressPair, my_mac_addr: [6]u8) !void {
    log.debug("Handling IP6 packet", .{});

    const ndp_frame = @as(*align(1) const EthernetNdpFrame, @ptrCast(packet));
    const target_ip_bytes = @as(*const [16]u8, @ptrCast(&ndp_frame.ndp_target_addr));

    const target_addr = std.net.Address.initIp6(target_ip_bytes.*, 0, 0, 0);
    const matched_mapping = try capture.findMatchingMacIpMapping(mappings, target_addr);

    sendNdpReply(pcap_handle, @as(u48, @bitCast(my_mac_addr)), ndp_frame.ndp_target_addr, @as(u48, @bitCast(matched_mapping.mac)), ndp_frame.ip_src_addr, ndp_frame.eth_src_addr);
}

fn sendNdpReply(pcap_handle: *c.pcap_t, my_mac: u48, src_ip: u128, src_mac: u48, dst_ip: u128, dst_mac: u48) void {
    log.debug("Matched, sending NDP reply.", .{});

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

    log.debug("Src IP: {x}", .{std.mem.bigToNative(u128, src_ip)});
    log.debug("Dst IP: {x}", .{std.mem.bigToNative(u128, dst_ip)});

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
    log.debug("Words: ", .{});
    for (checksum_target_words) |word| {
        const native_word = std.mem.bigToNative(u16, word);
        log.debug("{X:0>4}", .{native_word});
        sum += native_word;
    }
    log.debug("\n", .{});

    // Fold the 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum + (sum >> 16);
    var folded_sum: u16 = @intCast(sum);

    return ~folded_sum;
}
