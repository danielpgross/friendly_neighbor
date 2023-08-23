const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});
const clap = @import("clap");

const parseArgs = @import("parse_args.zig").parseArgs;
const generateCaptureFilterExpression = @import("capture_filter.zig").generateCaptureFilterExpression;

pub const log = std.log.scoped(.friendly_neighbor);

// **********
// Constants
// **********
const PACKET_LENGTH = 78;
const ETHERNET_ARP_PAYLOAD_TYPE = 0x0806;
const ETHERNET_IP6_PAYLOAD_TYPE = 0x86dd;

// **********
// Structs
// **********
pub const ExecutionOptions = struct {
    interface_name: []const u8,
    ip4_mappings: []const MacIpAddressPair,
    ip6_mappings: []const MacIpAddressPair,
};

pub const MacIpAddressPair = struct {
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
    ip4_mappings: []const MacIpAddressPair,
    ip6_mappings: []const MacIpAddressPair,
    my_mac_addr: [6]u8,
};

// **********
// Functions
// **********
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    // Parse CLI args
    const exec_opts = parseArgs(gpa.allocator()) catch |err| {
        if (err == error.CliArgsHelpRequested) return else return handleFatalErr(error.ArgParseFailure);
    };
    defer gpa.allocator().free(exec_opts.ip4_mappings);
    defer gpa.allocator().free(exec_opts.ip6_mappings);

    // Get my MAC address
    validateInterface(exec_opts.interface_name) catch
        return handleFatalErr(error.InvalidInterfaceType);
    const my_mac_addr = getMacAddress(exec_opts.interface_name) catch
        return handleFatalErr(error.GetInterfaceMacFailure);

    // Generate pcap filter string
    const pcap_filter_exp = generateCaptureFilterExpression(gpa.allocator(), exec_opts.ip4_mappings, exec_opts.ip6_mappings) catch
        return handleFatalErr(error.GenerateCaptureFilterFailure);
    defer gpa.allocator().free(pcap_filter_exp);

    // Begin capture
    beginCapture(exec_opts.interface_name, exec_opts.ip4_mappings, exec_opts.ip6_mappings, my_mac_addr, pcap_filter_exp) catch
        return handleFatalErr(error.PacketCaptureFailure);
}

fn handleFatalErr(err: anyerror) !void {
    _ = switch (err) {
        error.ArgParseFailure => log.err("Failed to parse command line arguments.", .{}),
        error.GenerateCaptureFilterFailure => log.err("Failed to generate packet capture filter.", .{}),
        error.GetInterfaceMacFailure => log.err("Failed to determine MAC address for specified network interface.", .{}),
        error.PacketCaptureFailure => log.err("Failed to start network packet capture.", .{}),
        error.InvalidInterfaceType => log.err("Specified network interface is invalid or not supported, use a wired Ethernet interface instead.", .{}),
        else => {},
    };

    return err;
}

fn validateInterface(interface_name: []const u8) !void {
    const sysfs_path_template = "/sys/class/net/{s}/wireless";
    var sysfs_path_buffer = [_]u8{undefined} ** (sysfs_path_template.len - 3 + 16); // 16 is maximum length of a Linux network interface name
    const sysfs_path = try std.fmt.bufPrint(&sysfs_path_buffer, sysfs_path_template, .{interface_name});
    std.fs.accessAbsolute(sysfs_path, .{}) catch return;

    log.err("Interface {s} appears to be wireless.", .{interface_name});
    return error.InterfaceIsWireless;
}

// TODO: add support for macOS and Windows
fn getMacAddress(interface_name: []const u8) ![6]u8 {
    const sysfs_path_template = "/sys/class/net/{s}/address";
    var sysfs_path_buffer = [_]u8{undefined} ** (sysfs_path_template.len - 3 + 16); // 16 is maximum length of a Linux network interface name
    const sysfs_path = try std.fmt.bufPrint(&sysfs_path_buffer, sysfs_path_template, .{interface_name});
    var sysfs_mac_addr_file = try std.fs.openFileAbsolute(sysfs_path, .{});
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
    log.debug("My MAC: {}", .{std.fmt.fmtSliceHexLower(&my_mac_addr)});

    return my_mac_addr;
}

fn beginCapture(interface_name: []const u8, ip4_mappings: []const MacIpAddressPair, ip6_mappings: []const MacIpAddressPair, my_mac_addr: [6]u8, filter_exp: []const u8) !void {
    var error_buffer: [c.PCAP_ERRBUF_SIZE:0]u8 = undefined;
    error_buffer[0] = '\x00';

    const handle: *c.pcap_t = c.pcap_open_live(@as([*c]const u8, @ptrCast(interface_name)), PACKET_LENGTH, 1, 1, &error_buffer) orelse {
        log.err("Failed to open packet capture handle: {s}", .{@as([*:0]const u8, &error_buffer)});
        return error.OpenLiveFailure;
    };
    defer c.pcap_close(handle);

    // Even if pcap_open_live doesn't fail outright, PCAP can store a warning in the error buffer
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

    if (c.pcap_loop(handle, 0, packetHandler, @as([*c]u8, @ptrCast(@constCast(&capture_context)))) == -1) {
        c.pcap_perror(handle, "pcap");
        return error.LoopFailure;
    }
}

export fn packetHandler(user: [*c]u8, packet_header: [*c]const c.pcap_pkthdr, raw_packet: [*c]const u8) void {
    log.debug("Handling packet. Timestamp: {d}, length: {d}\n", .{ packet_header.*.ts.tv_sec, packet_header.*.len });
    const packet = raw_packet[0..packet_header.*.len];
    const capture_context = @as(*align(1) CaptureContext, @ptrCast(user));
    const ethernet_header = @as(*align(1) const EthernetHeader, @ptrCast(packet));

    // TODO: handle errors
    switch (std.mem.bigToNative(u16, ethernet_header.payload_type)) {
        ETHERNET_ARP_PAYLOAD_TYPE => handleIp4Packet(capture_context.handle, packet, capture_context.ip4_mappings, capture_context.my_mac_addr) catch return,
        ETHERNET_IP6_PAYLOAD_TYPE => handleIp6Packet(capture_context.handle, packet, capture_context.ip6_mappings, capture_context.my_mac_addr) catch return,
        else => {
            log.err("Unknown packet type: {d}\n", .{std.mem.bigToNative(u16, ethernet_header.payload_type)});
            return;
        },
    }
}

fn handleIp4Packet(pcap_handle: *c.pcap_t, packet: []const u8, mappings: []const MacIpAddressPair, my_mac_addr: [6]u8) !void {
    log.debug("Handling IP4 packet\n", .{});

    const arp_frame = @as(*align(1) const EthernetArpFrame, @ptrCast(packet));
    const target_ip_bytes = @as(*const [4]u8, @ptrCast(&arp_frame.target_protocol_addr));
    log.debug("Target MAC: {x}", .{arp_frame.target_hardware_addr});
    log.debug(", Target IP: {d}.{d}.{d}.{d}\n", .{ target_ip_bytes[0], target_ip_bytes[1], target_ip_bytes[2], target_ip_bytes[3] });

    const target_addr = std.net.Address.initIp4(target_ip_bytes.*, 0);

    var matched_mapping: ?MacIpAddressPair = null;
    for (mappings) |mapping| {
        const mapping_addr = mapping.ip;
        log.debug("Compare: {}, {}\n", .{ target_addr, mapping_addr });
        if (std.net.Address.eql(target_addr, mapping_addr)) {
            matched_mapping = mapping;
        }
    }

    const matched_mapping_val = matched_mapping orelse return error.NoMatch;

    sendArpReply(pcap_handle, @as(u48, @bitCast(my_mac_addr)), arp_frame.target_protocol_addr, @as(u48, @bitCast(matched_mapping_val.mac)), arp_frame.sender_protocol_addr, arp_frame.sender_hardware_addr);
}

fn handleIp6Packet(pcap_handle: *c.pcap_t, packet: []const u8, mappings: []const MacIpAddressPair, my_mac_addr: [6]u8) !void {
    log.debug("Handling IP6 packet\n", .{});

    const ndp_frame = @as(*align(1) const EthernetNdpFrame, @ptrCast(packet));
    const target_ip_bytes = @as(*const [16]u8, @ptrCast(&ndp_frame.ndp_target_addr));

    const target_addr = std.net.Address.initIp6(target_ip_bytes.*, 0, 0, 0);

    var matched_mapping: ?MacIpAddressPair = null;
    for (mappings) |mapping| {
        const mapping_addr = mapping.ip;
        log.debug("Compare: {}, {}\n", .{ target_addr, mapping_addr });
        if (std.net.Address.eql(target_addr, mapping_addr)) {
            matched_mapping = mapping;
        }
    }

    const matched_mapping_val = matched_mapping orelse return error.NoMatch;

    sendNdpReply(pcap_handle, @as(u48, @bitCast(my_mac_addr)), ndp_frame.ndp_target_addr, @as(u48, @bitCast(matched_mapping_val.mac)), ndp_frame.ip_src_addr, ndp_frame.eth_src_addr);
}

fn sendArpReply(pcap_handle: *c.pcap_t, my_mac: u48, src_ip: u32, src_mac: u48, dst_ip: u32, dst_mac: u48) void {
    log.debug("Matched, sending reply.\n", .{});

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
    log.debug("Matched, sending reply.\n", .{});

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

    log.debug("Src IP: {x}\n", .{std.mem.bigToNative(u128, src_ip)});
    log.debug("Dst IP: {x}\n", .{std.mem.bigToNative(u128, dst_ip)});

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

//     log.debug("align of EthernetNdpFrame: {d}\n", .{@alignOf(EthernetNdpFrame)});

//     const result = calculateIcmp6Checksum(packet);
//     log.debug("checksum: {d}", .{result});
// }

test {
    _ = @import("parse_args.zig");
    _ = @import("capture_filter.zig");
}
