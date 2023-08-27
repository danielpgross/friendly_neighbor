const std = @import("std");
const log = @import("main.zig").log;

pub fn validateInterface(interface_name: []const u8) !void {
    const sysfs_path_template = "/sys/class/net/{s}/wireless";
    var sysfs_path_buffer = [_]u8{undefined} ** (sysfs_path_template.len - 3 + 16); // 16 is maximum length of a Linux network interface name
    const sysfs_path = try std.fmt.bufPrint(&sysfs_path_buffer, sysfs_path_template, .{interface_name});
    std.fs.accessAbsolute(sysfs_path, .{}) catch return;

    log.err("Interface {s} appears to be wireless.", .{interface_name});
    return error.InterfaceIsWireless;
}

// TODO: add support for macOS and Windows
pub fn getMacAddress(interface_name: []const u8) ![6]u8 {
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
