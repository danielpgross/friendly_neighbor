const std = @import("std");
const c = @cImport({
    @cInclude("pcap.h");
});
const clap = @import("clap");

const cli = @import("cli.zig");
const capture_filter = @import("capture_filter.zig");
const network_interface = @import("network_interface.zig");
const capture = @import("capture.zig");

pub const log = std.log;

pub const std_options = struct {
    pub const log_level = .info;
    pub const logFn = customLogger;
};

pub const ExecutionOptions = struct {
    interface_name: []const u8,
    ip4_mappings: []const MacIpAddressPair,
    ip6_mappings: []const MacIpAddressPair,
};

pub const MacIpAddressPair = struct {
    mac: [6]u8,
    ip: std.net.Address,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    log.info("Starting Friendly Neighbor v{s}...", .{cli.getVersion()});

    // Parse CLI args
    const exec_opts = cli.parseArgs(gpa.allocator()) catch |err| {
        if (err == error.CliArgsHelpRequested) return else return handleFatalErr(error.ArgParseFailure);
    };
    defer gpa.allocator().free(exec_opts.ip4_mappings);
    defer gpa.allocator().free(exec_opts.ip6_mappings);

    // Get my MAC address
    network_interface.validateInterface(exec_opts.interface_name) catch
        return handleFatalErr(error.InvalidInterfaceType);
    const my_mac_addr = network_interface.getMacAddress(exec_opts.interface_name) catch
        return handleFatalErr(error.GetInterfaceMacFailure);

    // Generate pcap filter string
    const pcap_filter_exp = capture_filter.generateCaptureFilterExpression(gpa.allocator(), exec_opts.ip4_mappings, exec_opts.ip6_mappings) catch
        return handleFatalErr(error.GenerateCaptureFilterFailure);
    defer gpa.allocator().free(pcap_filter_exp);

    // Begin capture
    capture.beginCapture(exec_opts.interface_name, exec_opts.ip4_mappings, exec_opts.ip6_mappings, my_mac_addr, pcap_filter_exp) catch
        return handleFatalErr(error.PacketCaptureFailure);
}

pub fn customLogger(comptime level: std.log.Level, comptime scope: @TypeOf(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    _ = scope;
    const level_text = switch (level) {
        .err => "ERR ",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DBG ",
    };
    const prefix = "[" ++ comptime level_text ++ "] ";

    // Print the message to stderr, silently ignoring any errors
    std.debug.getStderrMutex().lock();
    defer std.debug.getStderrMutex().unlock();
    const stderr = std.io.getStdErr().writer();
    nosuspend stderr.print(prefix ++ format ++ "\n", args) catch return;
}

fn handleFatalErr(err: anyerror) !void {
    _ = switch (err) {
        error.ArgParseFailure => {
            try cli.printUsage(true);
            std.os.exit(1);
        },
        error.GenerateCaptureFilterFailure => log.err("Failed to generate packet capture filter.", .{}),
        error.GetInterfaceMacFailure => log.err("Failed to determine MAC address for specified network interface.", .{}),
        error.PacketCaptureFailure => log.err("Failed to start network packet capture.", .{}),
        error.InvalidInterfaceType => log.err("Specified network interface is invalid or not supported, use a wired Ethernet interface instead.", .{}),
        else => {},
    };

    return err;
}

test {
    _ = @import("cli.zig");
    _ = @import("capture_filter.zig");
}
