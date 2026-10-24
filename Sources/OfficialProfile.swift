// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import Darwin

/// The official client reads its saved static password and a freshly encrypted
/// second password. No Guard Keychain item or OTP window is used by this path.
enum OfficialProfile {
    static let backend = "official_profile"
    static var root: URL {
        GuardIdentity.support.appendingPathComponent("official-connector")
    }
    static var pendingURL: URL { root.appendingPathComponent("pending.json") }
    static var backupURL: URL { URL(fileURLWithPath: VendorProfile.url.path + ".motionproguard-oss.bak") }

    static func requireIdle(status: VendorStatus?, clientRunning: Bool) throws {
        try RecoveryFlow.requireDisconnected(status)
        guard !clientRunning else { throw GuardFailure.message("MotionPro 尚未完全退出；保留配置，未提交登录") }
    }

    struct Context {
        let ini: INIFile
        let bytes: Data
        let prefix: String
        let username: String
        let token: OfflineOTP.Token
        let sourcePath: String
        let cipher: VendorCipher
    }

    /// A private journal retains only the fields required to restore this attempt.
    struct Transaction: Codable {
        let ini_path: String
        let prefix: String
        let originals: [String: String?]
        let injected: [String: String]
        let sections: [String: String]
        let created: Double
        let phase: String

        func restored(_ input: INIFile, cipher: VendorCipher) throws -> INIFile {
            guard ini_path == VendorProfile.url.path,
                  sections.keys.allSatisfy({ ["password", "password2", "autoconnect", "reconn_sess_invalid"].contains($0) }),
                  Set(sections.keys) == Set(injected.keys),
                  Set(sections.keys) == Set(originals.keys),
                  prefix.hasPrefix("data\\"), prefix.hasSuffix("\\") else {
                throw GuardFailure.message("恢复记录无效；保留事务和备份")
            }
            var output = input
            for (key, section) in sections {
                guard section == (key == "autoconnect" ? "global" : "profiles") else {
                    throw GuardFailure.message("恢复记录的字段不匹配；保留事务和备份")
                }
                let actual = section == "profiles" ? prefix + key : key
                let current = input.raw(section: section, key: actual)
                let original = originals[key] ?? nil
                let equivalent = (key == "password" || key == "password2") &&
                    Self.sameSecret(current, injected[key], cipher: cipher)
                if current == injected[key] || equivalent {
                    output.set(section: section, key: actual, raw: original)
                } else if (key == "autoconnect" && injected[key] == "true" && current == "false") ||
                          (key == "reconn_sess_invalid" && injected[key] == "0" && current == "1") {
                    // Preserve later changes to the client connection controls.
                    // Clearing a temporary OTP must not revert current preferences.
                    continue
                } else if current != original {
                    throw GuardFailure.message("客户端配置已改变；保留恢复记录，未提交登录")
                }
            }
            return output
        }

        private static func sameSecret(_ a: String?, _ b: String?, cipher: VendorCipher) -> Bool {
            func unquote(_ value: String) -> String {
                value.hasPrefix("\"") && value.hasSuffix("\"") ? String(value.dropFirst().dropLast()) : value
            }
            guard let a, let b, let first = try? cipher.decrypt(unquote(a)),
                  let second = try? cipher.decrypt(unquote(b)) else { return false }
            return first == second
        }
    }

    static func load() throws -> Context {
        let configURL = root.appendingPathComponent("config.json")
        guard let config = try JSONSerialization.jsonObject(with: Data(contentsOf: configURL)) as? [String: Any] else {
            throw GuardFailure.message("请在管理页选择官方 OTP 数据源")
        }
        return try load(configuration: config)
    }

    /// Select an existing official binding without importing a seed or password.
    /// This explicit setup action does not change the client or submit a login.
    static func configure(source: URL) throws {
        let ini = try VendorProfile.read(), prefix = try VendorProfile.prefix(ini)
        guard let portText = ini.value(section: "profiles", key: prefix + "port"),
              let port = Int(portText), (1...65535).contains(port) else {
            throw GuardFailure.message("官方站点端口无效；未保存数据源")
        }
        let config: [String: Any] = ["host": GuardIdentity.host, "port": port, "vsite_path": source.path]
        _ = try load(configuration: config)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        guard let lease = OfficialProfileLease() else {
            throw GuardFailure.message("另一连接操作尚未结束；未保存数据源")
        }
        try privateWrite(JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]),
                         to: root.appendingPathComponent("config.json"))
        withExtendedLifetime(lease) { }
    }

    private static func load(configuration config: [String: Any]) throws -> Context {
        guard config["host"] as? String == GuardIdentity.host,
              let source = config["vsite_path"] as? String, !source.isEmpty else {
            throw GuardFailure.message("自动登录配置缺少官方 OTP 数据源")
        }
        let bytes = try OfflineOTP.sourceData(path: VendorProfile.url.path)
        guard let text = String(data: bytes, encoding: .utf8) else { throw GuardFailure.invalidCredentials }
        let ini = INIFile(text: text), prefix = try VendorProfile.prefix(ini), cipher = try VendorCipher()
        guard let username = ini.value(section: "profiles", key: prefix + "username"), !username.isEmpty,
              let password = ini.value(section: "profiles", key: prefix + "password"),
              ini.value(section: "global", key: "default_profile") == ini.value(section: "profiles", key: prefix + "name"),
              ini.value(section: "profiles", key: prefix + "port") == String(config["port"] as? Int ?? 443) else {
            throw GuardFailure.message("官方客户端的账号、默认站点或端口未就绪")
        }
        _ = try cipher.decrypt(password)
        let sourcePath = (source as NSString).expandingTildeInPath
        let token = try OfflineOTP.candidate(data: OfflineOTP.sourceData(path: sourcePath), username: username)
        guard Double(token.period) - 2 * token.clockUncertainty >= 20 else {
            throw GuardFailure.message("官方令牌的时钟偏差过大；未提交登录")
        }
        return Context(ini: ini, bytes: bytes, prefix: prefix, username: username,
                       token: token, sourcePath: sourcePath, cipher: cipher)
    }

    static func journal(context: Context, code: String) throws -> Transaction {
        guard code.range(of: #"^[0-9]{6}$"#, options: .regularExpression) != nil else { throw GuardFailure.noOTP }
        let p = context.prefix
        return Transaction(ini_path: VendorProfile.url.path, prefix: p,
            originals: ["password2": context.ini.raw(section: "profiles", key: p + "password2"),
                        "autoconnect": context.ini.raw(section: "global", key: "autoconnect"),
                        "reconn_sess_invalid": context.ini.raw(section: "profiles", key: p + "reconn_sess_invalid")],
            injected: ["password2": "\"" + (try context.cipher.encrypt(code)) + "\"",
                       "autoconnect": "true", "reconn_sess_invalid": "0"],
            sections: ["password2": "profiles", "autoconnect": "global", "reconn_sess_invalid": "profiles"],
            created: Date().timeIntervalSince1970, phase: "prepared")
    }

    /// Caller holds operation.lock and has just confirmed status 0/7 and no GUI.
    static func prepare(_ context: Context, code: String) throws {
        guard !FileManager.default.fileExists(atPath: pendingURL.path),
              !FileManager.default.fileExists(atPath: backupURL.path),
              try Data(contentsOf: VendorProfile.url) == context.bytes else {
            throw GuardFailure.message("配置或恢复记录已变化；未提交登录")
        }
        let transaction = try journal(context: context, code: code)
        try privateWrite(JSONEncoder().encode(transaction), to: pendingURL)
        let fd = open(backupURL.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw GuardFailure.message("无法创建配置恢复备份；未提交登录") }
        let backup = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try backup.write(contentsOf: context.bytes); try backup.synchronize(); try backup.close()
        var ini = context.ini
        for (key, section) in transaction.sections {
            ini.set(section: section, key: section == "profiles" ? context.prefix + key : key,
                    raw: transaction.injected[key])
        }
        // The saved static password is deliberately kept byte-for-byte.
        try VendorProfile.write(ini)
    }

    /// Caller holds operation.lock and has just confirmed status 0/7 and no GUI.
    static func restore() throws {
        guard FileManager.default.fileExists(atPath: pendingURL.path) else {
            guard !FileManager.default.fileExists(atPath: backupURL.path) else {
                throw GuardFailure.message("发现无对应事务的备份；保留现场，未提交登录")
            }
            return
        }
        let transaction = try JSONDecoder().decode(Transaction.self, from: Data(contentsOf: pendingURL))
        let restored = try transaction.restored(VendorProfile.read(), cipher: VendorCipher())
        try VendorProfile.write(restored)
        // Remove the backup before the journal so an interrupted cleanup can be repeated.
        if FileManager.default.fileExists(atPath: backupURL.path) { try FileManager.default.removeItem(at: backupURL) }
        try FileManager.default.removeItem(at: pendingURL)
    }

    static func privateWrite(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}

final class OfficialProfileLease {
    private let descriptor: Int32
    init?() {
        let fd = open(OfficialProfile.root.appendingPathComponent("operation.lock").path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { return nil }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { close(fd); return nil }
        descriptor = fd
    }
    deinit { _ = flock(descriptor, LOCK_UN); close(descriptor) }
}
