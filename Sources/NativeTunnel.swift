// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import CryptoKit
import Darwin

struct NativeTunnelObservation {
    let status: VendorStatus
    let gatewayName: String?
}

/// Version-specific adapter for the installed vendor's JSON datagram protocol.
/// Only actions 8 (query) and 6 (session start) are exposed. There is no stop,
/// restart, credential login, arbitrary command or raw-response output method.
enum NativeTunnelProtocol {
    static let statusRequest = Data(#"{"error":0,"message":"get vpn status","data":{"action":8}}"#.utf8)
    static func observation(_ bytes: Data) throws -> NativeTunnelObservation {
        guard bytes.count < 65_536,
              let root = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              let error = root["error"] as? Int, error == 0,
              let data = root["data"] as? [String: Any], data["action"] as? Int == 8,
              let value = data["status"] as? Int, let status = VendorStatus(rawValue: value) else { throw HeadlessFailure.nativeProtocol }
        let name = (data["site"] as? [String: Any])?["name"] as? String
        return NativeTunnelObservation(status: status, gatewayName: name)
    }
    static func startRequest(_ session: HeadlessSession, pid: Int32) throws -> Data {
        try session.requireFresh()
        guard session.cookie.utf8.count < 4016, session.cookie.range(of: #"^ANsession[0-9]*=[!-~]+$"#, options: .regularExpression) != nil,
              !session.cookie.contains(";"), !session.cookie.contains("\\") else { throw HeadlessFailure.sessionMissing }
        // The cookie branch of the vendor's ConnectWithCookie uses these
        // placeholders. The IPC receives the authenticated cookie, never pwd/OTP.
        let site: [String: Any] = ["name": GuardIdentity.host, "host": GuardIdentity.host,
            "domain": GuardIdentity.host, "server_type": 2, "port": 443, "sslproto": 0, "alias": "", "method": "radius",
            "username": "nouser", "password": "nopass", "clientid": "", "session": session.cookie,
            "validcode": "", "certpath": "", "certpassword": "", "reconncount": 0,
            "reconntime": 0, "reconninterval": 0, "proxyhost": "", "proxyport": 0,
            "proxydomain": "", "proxyusername": "", "proxypassword": "", "pid": pid, "tunneltype": 1]
        // vpnd reads site.domain with Json::Value::asCString(). It must be
        // present as a string before the daemon can start the session.
        return try JSONSerialization.data(withJSONObject: ["error": 0, "message": "start vpn", "data": ["action": 6, "site": site]])
    }
}

final class NativeTunnel {
    struct Identity: Equatable { let pid: Int32; let port: UInt16 }
    private static let hashes = [
        "vpnd": "53c41975b721136c9cce39add8301d197f791e673a1eb0e8bb9cea374eb61d97",
        "vl3vpn.dylib": "3dd7f4884831249b9fb7c16fe39f31d41650fc6ecf22106c69a0855cb10f8b1d"
    ]
    static func identity() throws -> Identity {
        for (name, hash) in hashes {
            let path = "/usr/local/motionpro/" + name
            var metadata = stat()
            guard lstat(path, &metadata) == 0, metadata.st_uid == 0,
                  (metadata.st_mode & S_IFMT) == S_IFREG, (metadata.st_mode & 0o022) == 0,
                  let bytes = try? Data(contentsOf: URL(fileURLWithPath: path)),
                  SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == hash else { throw HeadlessFailure.nativeChanged }
        }
        return try serviceIdentity()
    }
    private static func serviceIdentity() throws -> Identity {
        let portPath = "/var/log/MotionPro/com.arraynetworks.vpn.port"
        var metadata = stat()
        guard lstat(portPath, &metadata) == 0, metadata.st_uid == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG, (metadata.st_mode & 0o022) == 0,
              metadata.st_size > 0 && metadata.st_size <= 6,
              let string = try? String(contentsOfFile: portPath),
              let port = UInt16(string.trimmingCharacters(in: .whitespacesAndNewlines)), port > 1024 else { throw HeadlessFailure.nativeUnavailable }
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-axo", "pid=,uid=,comm="]
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        let lines = String(decoding: data, as: UTF8.self).split(separator: "\n")
        let matches = lines.compactMap { line -> Int32? in
            let fields = line.split(maxSplits: 2, whereSeparator: { $0.isWhitespace })
            guard fields.count == 3, fields[1] == "0", fields[2] == "/usr/local/motionpro/vpnd" else { return nil }
            return Int32(fields[0])
        }
        guard process.terminationStatus == 0, matches.count == 1 else { throw HeadlessFailure.nativeUnavailable }
        return Identity(pid: matches[0], port: port)
    }
    private let expected: Identity
    init() throws { expected = try Self.identity() }
    func requireSameService() throws {
        guard try Self.identity() == expected else { throw HeadlessFailure.nativeChanged }
    }
    private func socket() throws -> Int32 {
        let fd = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { throw HeadlessFailure.nativeUnavailable }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        address.sin_port = expected.port.bigEndian; address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
        let connected = withUnsafePointer(to: &address) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard connected == 0 else { close(fd); throw HeadlessFailure.nativeUnavailable }
        var timeout = timeval(tv_sec: 2, tv_usec: 0)
        guard setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size)) == 0 else { close(fd); throw HeadlessFailure.nativeUnavailable }
        return fd
    }
    private func send(_ bytes: Data, fd: Int32) throws {
        let count = bytes.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
        guard count == bytes.count else { throw HeadlessFailure.nativeUnavailable }
    }
    private func query(fd: Int32) throws -> NativeTunnelObservation {
        try send(NativeTunnelProtocol.statusRequest, fd: fd)
        var bytes = [UInt8](repeating: 0, count: 65_536)
        let count = recv(fd, &bytes, bytes.count, 0)
        guard count > 0 && count < bytes.count else { throw HeadlessFailure.nativeUnavailable }
        return try NativeTunnelProtocol.observation(Data(bytes.prefix(count)))
    }
    func status() throws -> NativeTunnelObservation {
        guard try Self.serviceIdentity() == expected else { throw HeadlessFailure.nativeRestarted }
        let fd = try socket(); defer { close(fd) }
        return try query(fd: fd)
    }
    func start(_ session: HeadlessSession) throws {
        try requireSameService(); try session.requireFresh()
        let bytes = try NativeTunnelProtocol.startRequest(session, pid: getpid())
        let fd = try socket(); defer { close(fd) }
        // Recheck immediately on the same UDP socket before the single start.
        try RecoveryFlow.requireDisconnected(try query(fd: fd).status)
        try send(bytes, fd: fd)
        // send() proves delivery to the socket, not authentication or a tunnel.
    }
}
