const std = @import("std");
const clap = @import("clap");

const main = @import("main.zig");
const log = main.log;
const ExecutionOptions = main.ExecutionOptions;
const MacIpAddressPair = main.MacIpAddressPair;

const CLI_PARAMS = clap.parseParamsComptime(
    \\-i, --interface <IFACE> Name of network interface on which to listen and send packets
    \\-m, --mapping <MAPPING>... One or more MAC to IP (v4 or v6) address mappings, each in the format <MAC address>,<IP address>
    \\    --mappings <MAPPINGS> A single string containing one or more mappings in the format <MAC address>,<IP address> with mappings separated by a space
    \\-h, --help Display this help and exit
    \\-v, --version Print program version and exit
    \\
);

const CLI_PARSERS = .{
    .IFACE = clap.parsers.string,
    .MAPPING = clap.parsers.string,
    .MAPPINGS = clap.parsers.string,
};

const VERSION = "0.1.0-dev";

pub fn parseArgs(alloc: std.mem.Allocator) !ExecutionOptions {
    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &CLI_PARAMS, CLI_PARSERS, .{
        .diagnostic = &diag,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try printHelp();
        return error.CliArgsHelpRequested;
    }

    if (res.args.version != 0) {
        try printVersion();
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

    if (execution_options.ip4_mappings.len == 0 and execution_options.ip6_mappings.len == 0) {
        log.err("At least 1 MAC to IP address mapping must be provided.", .{});
        return error.MissingArgument;
    }

    return execution_options;
}

fn getExecutableName() []const u8 {
    var args_iter = std.process.args();
    return args_iter.next() orelse unreachable;
}

fn printHelp() !void {
    const stderr = std.io.getStdErr().writer();
    try stderr.print(
        \\Friendly Neighbor (v{s})
        \\    Respond to ARP and NDP requests on behalf of neighboring machines
        \\
        \\USAGE
        \\    
    , .{VERSION});
    try printUsage(false);
    try stderr.print("\nOPTIONS\n", .{});
    try clap.help(stderr, clap.Help, &CLI_PARAMS, .{ .max_width = 80 });
    try stderr.print(
        \\EXAMPLES
        \\    {s} -i eth0 \
        \\        -m 11:22:33:44:55:66,192.168.1.2 \
        \\        -m 11:22:33:44:55:66,fd12:3456:789a:1::1
        \\
        \\    {s} -i eno1 --mappings \
        \\        "AA:BB:CC:DD:EE:FF,10.0.8.3 AA:BB:CC:DD:EE:FF,fd9a:bc83:57e4:2::1"
        \\
        \\
    , .{ getExecutableName(), getExecutableName() });
    try stderr.print(
        \\FEEDBACK
        \\    Feedback and bug reports are welcome at:
        \\    https://github.com/danielpgross/friendly_neighbor
        \\
    , .{});
}

pub fn printUsage(include_label: bool) !void {
    const stderr = std.io.getStdErr().writer();
    if (include_label) try stderr.print("Usage: ", .{});
    try stderr.print("{s} ", .{getExecutableName()});
    try clap.usage(stderr, clap.Help, &CLI_PARAMS);
    try stderr.print("\n", .{});
}

fn printVersion() !void {
    const stderr = std.io.getStdErr().writer();
    try stderr.print("{s}\n", .{VERSION});
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
        log.err("Failed to parse mapping argument: {s}. Mapping should be a MAC address, followed by a comma, followed by an IP address (no spaces).", .{mapping_arg});
        return error.InvalidMappingArgument;
    };
}

fn parseMacIpMappingContent(mapping_arg: []const u8, ip4_mappings: *std.ArrayListAligned(MacIpAddressPair, null), ip6_mappings: *std.ArrayListAligned(MacIpAddressPair, null)) !void {
    var mapping_arg_iter = std.mem.tokenizeScalar(u8, mapping_arg, ',');
    const mac_addr_slice = mapping_arg_iter.next() orelse unreachable; // mapping_arg is expected not to be empty

    if (mac_addr_slice.len != 17) {
        log.err("Failed to parse mapping MAC address: {s}. Use format AA:BB:CC:DD:EE:FF.", .{mac_addr_slice});
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
        log.err("Mapping is missing IP address.", .{});
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

    log.err("Failed to parse IP address as IPv4 or IPv6: {s}", .{ip_addr_slice});
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
