const std = @import("std");
const clap = @import("clap");

const main = @import("main.zig");
const log = main.log;
const ExecutionOptions = main.ExecutionOptions;
const MacIpAddressPair = main.MacIpAddressPair;

pub fn parseArgs(alloc: std.mem.Allocator) !ExecutionOptions {
    const params = comptime clap.parseParamsComptime(
        \\-h, --help Display this help and exit
        \\-i, --interface <IFACE> Network interface name on which to listen and send packets
        \\-m, --mapping <MAPPING>... One or more MAC to IP (v4 or v6) address mappings, each one in the format <MAC address>,<IP address>
        \\    --mappings <MAPPINGS> A single string containing one or more mappings in the format <MAC address>,<IP address> with mappings separated by a space
        \\
    );
    const parsers = comptime .{
        .IFACE = clap.parsers.string,
        .MAPPING = clap.parsers.string,
        .MAPPINGS = clap.parsers.string,
    };
    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
        return error.CliArgsHelpRequested;
    }

    var execution_options = ExecutionOptions{
        .interface_name = res.args.interface orelse {
            log.err("Network interface name is required, but was not provided.", .{});
            return error.InterfaceRequired;
        },
        .ip4_mappings = undefined,
        .ip6_mappings = undefined,
    };

    log.debug("Interface: {?s}", .{res.args.interface});

    const mappings = try parseMacIpMappings(alloc, res.args.mapping, res.args.mappings);
    execution_options.ip4_mappings = mappings[0];
    execution_options.ip6_mappings = mappings[1];

    return execution_options;
}

fn parseMacIpMappings(alloc: std.mem.Allocator, mapping_args: []const []const u8, mapping_str_arg: ?[]const u8) ![2][]const MacIpAddressPair {
    var ip4_mappings = std.ArrayList(MacIpAddressPair).init(alloc);
    var ip6_mappings = std.ArrayList(MacIpAddressPair).init(alloc);

    for (mapping_args) |arg| {
        try parseMacIpMapping(arg, &ip4_mappings, &ip6_mappings);
    }

    if (mapping_str_arg != null) {
        var mapping_str_arg_iter = std.mem.tokenizeScalar(u8, mapping_str_arg.?, ' ');
        while (mapping_str_arg_iter.next()) |arg| {
            try parseMacIpMapping(arg, &ip4_mappings, &ip6_mappings);
        }
    }

    for (ip4_mappings.items) |ip4Mapping| {
        log.debug("ip4Mapping: {}, {}", .{ std.fmt.fmtSliceHexLower(&ip4Mapping.mac), ip4Mapping.ip });
    }
    for (ip6_mappings.items) |ip6Mapping| {
        log.debug("ip6Mapping: {}, {}", .{ std.fmt.fmtSliceHexLower(&ip6Mapping.mac), ip6Mapping.ip });
    }

    return [_][]MacIpAddressPair{ try ip4_mappings.toOwnedSlice(), try ip6_mappings.toOwnedSlice() };
}

fn parseMacIpMapping(mapping_arg: []const u8, ip4_mappings: *std.ArrayListAligned(MacIpAddressPair, null), ip6_mappings: *std.ArrayListAligned(MacIpAddressPair, null)) !void {
    log.debug("Mapping arg: {s}", .{mapping_arg});
    parseMacIpMappingContent(mapping_arg, ip4_mappings, ip6_mappings) catch {
        log.err("Failed to parse mapping argument: {s}. Mapping should be a MAC address, followed by a comma, followed by an IP address (no spaces)", .{mapping_arg});
        return error.InvalidMappingArgument;
    };
}

fn parseMacIpMappingContent(mapping_arg: []const u8, ip4_mappings: *std.ArrayListAligned(MacIpAddressPair, null), ip6_mappings: *std.ArrayListAligned(MacIpAddressPair, null)) !void {
    var mapping_arg_iter = std.mem.tokenizeScalar(u8, mapping_arg, ',');
    const mac_addr_slice = mapping_arg_iter.next() orelse unreachable; // mapping_arg is expected not to be empty

    if (mac_addr_slice.len != 17) {
        log.err("First part of mapping does not look like a MAC address: {s}. Use format AA:BB:CC:DD:EE:FF.", .{mac_addr_slice});
        return error.InvalidMacAddr;
    }

    var mac_addr: [6]u8 = undefined;
    var mac_addr_iter = std.mem.tokenizeScalar(u8, mac_addr_slice, ':');
    var i: usize = 0;
    while (mac_addr_iter.next()) |hexpair| {
        _ = std.fmt.hexToBytes(mac_addr[i .. i + 1], hexpair) catch {
            log.err("Failed to parse MAC address: {s}", .{mac_addr_slice});
            return error.InvalidMacAddr;
        };
        i += 1;
    }

    const ip_addr_slice = mapping_arg_iter.next() orelse {
        return error.IncompleteMappingArgument;
    };

    if (mapping_arg_iter.next() != null) {
        log.err("Mapping should only have one comma.", .{});
        return error.InvalidMappingArgument;
    }

    if (std.net.Address.parseIp4(ip_addr_slice, 0)) |ip4| {
        return ip4_mappings.append(MacIpAddressPair{
            .mac = mac_addr,
            .ip = ip4,
        });
    } else |_| {}
    if (std.net.Address.parseIp6(ip_addr_slice, 0)) |ip6| {
        return ip6_mappings.append(MacIpAddressPair{
            .mac = mac_addr,
            .ip = ip6,
        });
    } else |_| {}

    log.err("Failed to parse IP address as IPv4 or IPv6: .{s}", .{ip_addr_slice});
    return error.InvalidIpAddr;
}

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

test "expect correctly parsed mappings with 1 IPv6 mapping arg" {
    const alloc = std.testing.allocator;
    var args = [_][:0]const u8{ "friendly_neighbor", "11:22:33:44:55:66|2001:0db8:3333:4444:5555:6666:7777:8888" };

    const mappings = try parseArgs(alloc, &args);
    const ip4_mappings = mappings[0];
    defer alloc.free(ip4_mappings);
    const ip6_mappings = mappings[1];
    defer alloc.free(ip6_mappings);

    try std.testing.expect(ip4_mappings.len == 0);
    try std.testing.expect(ip6_mappings.len == 1);
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip6_mappings[0].mac));
    const expectedAddr = try std.net.Address.parseIp6("2001:0db8:3333:4444:5555:6666:7777:8888", 0);
    try std.testing.expect(std.net.Address.eql(expectedAddr, ip6_mappings[0].ip));
}

test "expect correctly parsed mappings with 1 IPv6 mapping arg in compressed representation" {
    const alloc = std.testing.allocator;
    var args = [_][:0]const u8{ "friendly_neighbor", "11:22:33:44:55:66|2001:db8:3333:4444::8888" };

    const mappings = try parseArgs(alloc, &args);
    const ip4_mappings = mappings[0];
    defer alloc.free(ip4_mappings);
    const ip6_mappings = mappings[1];
    defer alloc.free(ip6_mappings);

    try std.testing.expect(ip4_mappings.len == 0);
    try std.testing.expect(ip6_mappings.len == 1);
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip6_mappings[0].mac));
    const expectedAddr = try std.net.Address.parseIp6("2001:0db8:3333:4444:0000:0000:0000:8888", 0);
    try std.testing.expect(std.net.Address.eql(expectedAddr, ip6_mappings[0].ip));
}

test "expect correctly parsed mappings with 1 IPv4 mapping arg and 1 IPv6 mapping arg" {
    const alloc = std.testing.allocator;
    var args = [_][:0]const u8{ "friendly_neighbor", "11:22:33:44:55:66|192.168.1.1", "11:22:33:44:55:66|2001:db8:3333:4444::8888" };

    const mappings = try parseArgs(alloc, &args);
    const ip4_mappings = mappings[0];
    defer alloc.free(ip4_mappings);
    const ip6_mappings = mappings[1];
    defer alloc.free(ip6_mappings);

    try std.testing.expect(ip4_mappings.len == 1);
    try std.testing.expect(ip6_mappings.len == 1);
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip4_mappings[0].mac));
    const expectedIp4Addr = try std.net.Address.parseIp4("192.168.1.1", 0);
    try std.testing.expect(std.net.Address.eql(expectedIp4Addr, ip4_mappings[0].ip));
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip6_mappings[0].mac));
    const expectedIp6Addr = try std.net.Address.parseIp6("2001:0db8:3333:4444:0000:0000:0000:8888", 0);
    try std.testing.expect(std.net.Address.eql(expectedIp6Addr, ip6_mappings[0].ip));
}

test "expect correctly parsed mappings with 2 IPv4 mapping args and 2 IPv6 mapping args" {
    const alloc = std.testing.allocator;
    var args = [_][:0]const u8{ "friendly_neighbor", "11:22:33:44:55:66|192.168.1.1", "11:22:33:44:55:66|2001:db8:3333:4444::8888", "22:22:33:44:55:66|192.168.1.254", "22:22:33:44:55:66|FD04:AFA8:33E6::1" };

    const mappings = try parseArgs(alloc, &args);
    const ip4_mappings = mappings[0];
    defer alloc.free(ip4_mappings);
    const ip6_mappings = mappings[1];
    defer alloc.free(ip6_mappings);

    try std.testing.expect(ip4_mappings.len == 2);
    try std.testing.expect(ip6_mappings.len == 2);
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip4_mappings[0].mac));
    try std.testing.expect(std.net.Address.eql(try std.net.Address.parseIp4("192.168.1.1", 0), ip4_mappings[0].ip));
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x22, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip4_mappings[1].mac));
    try std.testing.expect(std.net.Address.eql(try std.net.Address.parseIp4("192.168.1.254", 0), ip4_mappings[1].ip));
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip6_mappings[0].mac));
    try std.testing.expect(std.net.Address.eql(try std.net.Address.parseIp6("2001:0db8:3333:4444:0000:0000:0000:8888", 0), ip6_mappings[0].ip));
    try std.testing.expect(std.mem.eql(u8, &[_]u8{ 0x22, 0x22, 0x33, 0x44, 0x55, 0x66 }, &ip6_mappings[1].mac));
    try std.testing.expect(std.net.Address.eql(try std.net.Address.parseIp6("fd04:afa8:33e6:0000:0000:0000:0000:0001", 0), ip6_mappings[1].ip));
}
