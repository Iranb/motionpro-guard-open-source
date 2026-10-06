// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import Security
import CryptoKit
import CommonCrypto
import LocalAuthentication

struct Credentials: Codable {
    var host: String
    var username: String
    var password: String
}

enum Vault {
    static let service = GuardIdentity.bundle + ".credentials"
    private static let interactionLock = NSRecursiveLock()

    /// LAContext alone does not suppress prompts from the legacy file keychain.
    /// Scope the legacy process flag too; this never changes the item's ACL.
    /// Background callers must also return promptly during an explicit prompt.
    /// Compatibility workaround also documented in Chromium's
    /// crypto/apple/scoped_keychain_user_interaction_allowed.cc (FB16959400).
    static func withInteraction<T>(_ interactive: Bool = false, _ operation: () throws -> T) throws -> T {
        if interactive { interactionLock.lock() }
        else if !interactionLock.try() { throw GuardFailure.message("钥匙串正在等待用户授权") }
        defer { interactionLock.unlock() }
        var previous: DarwinBoolean = false
        let readStatus = SecKeychainGetUserInteractionAllowed(&previous)
        guard readStatus == errSecSuccess else { throw GuardFailure.message("无法安全检查钥匙串交互状态（\(readStatus)）") }
        let setStatus = SecKeychainSetUserInteractionAllowed(interactive)
        guard setStatus == errSecSuccess else { throw GuardFailure.message("无法安全设置钥匙串交互状态（\(setStatus)）") }
        defer { _ = SecKeychainSetUserInteractionAllowed(previous.boolValue) }
        return try operation()
    }
    static func query(_ account: String, interactive: Bool = false) -> [String: Any] {
        var result: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: account, kSecAttrSynchronizable as String: false]
        if !interactive {
            // Fail promptly when authorization is required, including writes and
            // rollback deletion. Never wait for a dialog behind the lock screen.
            let context = LAContext(); context.interactionNotAllowed = true
            result[kSecUseAuthenticationContext as String] = context
        }
        return result
    }
    static func put(_ data: Data, account: String, interactive: Bool = false) throws {
        try withInteraction(interactive) {
            let q = query(account, interactive: interactive)
            let status = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
            if status == errSecItemNotFound {
                var add = q; add[kSecValueData as String] = data
                add[kSecAttrLabel as String] = "MotionPro Guard — " + account
                let result = SecItemAdd(add as CFDictionary, nil)
                guard result == errSecSuccess else { throw GuardFailure.message("钥匙串保存失败（\(result)）") }
            } else if status != errSecSuccess { throw GuardFailure.message("钥匙串更新失败（\(status)）") }
        }
    }
    static func get(_ account: String, interactive: Bool = false) throws -> Data? {
        try withInteraction(interactive) {
            var q = query(account, interactive: interactive); q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
            var item: CFTypeRef?
            let status = SecItemCopyMatching(q as CFDictionary, &item)
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess else { throw GuardFailure.message("钥匙串暂不可访问（\(status)）") }
            return item as? Data
        }
    }
    static func remove(_ account: String) throws {
        try withInteraction {
            let status = SecItemDelete(query(account) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw GuardFailure.message("钥匙串清理需要授权（\(status)）")
            }
        }
    }
    static func credentials(interactive: Bool = false) throws -> Credentials? {
        guard let data = try get(GuardIdentity.host, interactive: interactive) else { return nil }
        let value = try JSONDecoder().decode(Credentials.self, from: data)
        guard value.host == GuardIdentity.host, !value.username.isEmpty, !value.password.isEmpty else {
            throw GuardFailure.invalidCredentials
        }
        return value
    }

    /// Prepare the OS-supported password-verified partition migration.
    /// /usr/bin/security reads the password directly from the user's terminal.
    /// No secret input is handled by Guard. Never called by the timer/recovery.
    @discardableResult static func repairAccess(scriptRoot: URL? = nil, openTerminal: Bool = true) throws -> Bool {
        try withInteraction {
            let partition = try KeychainPartition.currentSignedGuard()
            let keychainPath = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Keychains/login.keychain-db").path
            var keychain: SecKeychain?
            try KeychainPartition.requireSuccess(SecKeychainOpen(keychainPath, &keychain), "打开登录钥匙串")
            guard let keychain else { throw GuardFailure.message("登录钥匙串不可用") }
            func quote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
            var commands: [String] = []
            for account in [GuardIdentity.host, "pending-login", "offline-otp.v1"] {
                var item: SecKeychainItem?
                let status = service.withCString { s in account.withCString { a in
                    SecKeychainFindGenericPassword(keychain, UInt32(service.utf8.count), s,
                        UInt32(account.utf8.count), a, nil, nil, &item)
                } }
                if status == errSecItemNotFound { continue }
                try KeychainPartition.requireSuccess(status, "读取凭据权限")
                guard let item else { throw GuardFailure.message("未找到凭据权限记录") }
                let access = try KeychainPartition.access(item)
                let before = try KeychainPartition.entries(access)
                let partitions = before.filter { $0.authorizations.contains(kSecACLAuthorizationPartitionID as String) }
                guard partitions.count == 1 else { throw GuardFailure.message("钥匙串分区结构异常；未更改权限") }
                let entry = partitions[0]
                let updated = try KeychainPartition.appending(partition, to: entry.label)
                if updated == entry.label { continue }
                let dictionary = try KeychainPartition.dictionary(updated)
                guard Set(dictionary.keys) == ["Partitions"], let values = dictionary["Partitions"] as? [String],
                      values.allSatisfy({ !$0.contains(",") && !$0.contains("\n") }) else {
                    throw GuardFailure.message("分区包含未知字段；未准备修改")
                }
                // Exact service/account/keychain; no -k password argument.
                // Apple security changes only the PartitionID ACL. Redirect its
                // item-attribute listing; its password prompt uses the terminal.
                commands.append("/usr/bin/security set-generic-password-partition-list -a \(quote(account)) -s \(quote(service)) -S \(quote(values.joined(separator: ","))) \(quote(keychainPath)) > /dev/null")
            }
            guard !commands.isEmpty else { return false }
            let app = Bundle.main.bundleURL
            guard app.pathExtension == "app" else { throw GuardFailure.message("授权必须由已签名的 Guard 应用生成") }
            let executable = app.appendingPathComponent("Contents/MacOS/MotionProGuard")
            let root = scriptRoot ?? GuardIdentity.support
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let script = root.appendingPathComponent("keychain-repair.command")
            let result = root.appendingPathComponent("keychain-repair-result.json")
            let source = """
            #!/bin/zsh
            set -eu
            umask 077
            TASK_REPAIR_RESULT=\(quote(result.path))
            function repair_finished {
                local result_code=$?
                if (( result_code == 0 )); then
                    /usr/bin/printf '{"state":"verified"}\\n' > "${TASK_REPAIR_RESULT}.tmp"
                else
                    /usr/bin/printf '{"state":"failed","exitCode":%d}\\n' "$result_code" > "${TASK_REPAIR_RESULT}.tmp"
                fi
                /bin/mv -f "${TASK_REPAIR_RESULT}.tmp" "$TASK_REPAIR_RESULT"
            }
            trap repair_finished EXIT
            /usr/bin/codesign --verify --strict \(quote(app.path))
            task_current_hash=$(/usr/bin/codesign -dvvv \(quote(app.path)) 2>&1 | /usr/bin/awk -F= '/^CDHash=/{print $2}')
            if [[ "$task_current_hash" != \(quote(String(partition.dropFirst(7)))) ]]; then
                print 'Guard 已更新，请重新生成修复命令。'
                exit 2
            fi
            print 'MotionPro Guard：修复当前版本对校园 VPN 凭据的访问。'
            print '请在 Password: 后输入 Mac 登录钥匙串密码并按回车；输入不显示字符。'
            print '密码仅交给 macOS 自带的 security 工具，不保存、不传给 Guard。'
            \(commands.joined(separator: "\n"))
            \(quote(executable.path)) --check-keychain
            \(scriptRoot == nil ? "/usr/bin/open -a " + quote(app.path) + " 'motionpro-guard-oss://check-keychain'" : ":")
            print '修复完成，已通过无弹窗读取检查。可以关闭此终端窗口。'
            """
            try Data(source.utf8).write(to: script, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
            try Data("{\"state\":\"waiting_for_password\"}".utf8).write(to: result, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: result.path)
            guard openTerminal else { return true }
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/open")
            process.arguments = ["-a", "Terminal", script.path]
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw GuardFailure.message("无法打开系统工具的密码输入终端") }
            return true
        }
    }
}

/// Metadata codec shared by the explicit migration and isolated tests.
enum KeychainPartition {
    struct Entry {
        let acl: SecACL
        let authorizations: [String]
        let applications: CFArray?
        let applicationData: [Data]?
        let label: String
        let prompt: SecKeychainPromptSelector
    }
    static func requireSuccess(_ status: OSStatus, _ operation: String) throws {
        guard status == errSecSuccess else { throw GuardFailure.message("\(operation)失败（\(status)）") }
    }
    static func currentSignedGuard() throws -> String {
        let flags = SecCSFlags(rawValue: 0)
        var code: SecCode?, requirement: SecRequirement?, staticCode: SecStaticCode?, info: CFDictionary?
        try requireSuccess(SecCodeCopySelf(flags, &code), "读取当前签名")
        let fingerprint = BuildConfiguration.signingCertificateSHA1
        guard fingerprint.range(of: #"^[0-9A-Fa-f]{40}$"#, options: .regularExpression) != nil else {
            throw GuardFailure.message("钥匙串授权要求使用固定证书构建；开发用临时签名不可授权")
        }
        let expected = "identifier \"\(GuardIdentity.bundle)\" and certificate leaf = H\"\(fingerprint)\""
        try requireSuccess(SecRequirementCreateWithString(expected as CFString, flags, &requirement), "检查固定签名要求")
        guard let code, let requirement else { throw GuardFailure.message("当前签名不可用") }
        try requireSuccess(SecCodeCheckValidity(code, flags, requirement), "验证当前 Guard 签名")
        try requireSuccess(SecCodeCopyStaticCode(code, flags, &staticCode), "读取签名元数据")
        guard let staticCode else { throw GuardFailure.message("签名元数据不可用") }
        try requireSuccess(SecCodeCopySigningInformation(staticCode, flags, &info), "读取程序指纹")
        guard let info = info as? [String: Any], let hash = info[kSecCodeInfoUnique as String] as? Data,
              hash.count == 20 else { throw GuardFailure.message("程序指纹格式异常") }
        return "cdhash:" + hash.map { String(format: "%02x", $0) }.joined()
    }
    static func access(_ item: SecKeychainItem) throws -> SecAccess {
        var result: SecAccess?
        try requireSuccess(SecKeychainItemCopyAccess(item, &result), "读取钥匙串访问规则")
        guard let result else { throw GuardFailure.message("钥匙串访问规则为空") }
        return result
    }
    static func entries(_ access: SecAccess) throws -> [Entry] {
        var list: CFArray?
        try requireSuccess(SecAccessCopyACLList(access, &list), "读取访问规则列表")
        guard let list = list as? [SecACL] else { throw GuardFailure.message("访问规则列表异常") }
        return try list.map { acl in
            guard let authorizations = SecACLCopyAuthorizations(acl) as? [String] else {
                throw GuardFailure.message("访问规则用途不可读")
            }
            var applications: CFArray?, label: CFString?
            var prompt = SecKeychainPromptSelector(rawValue: 0)
            try requireSuccess(SecACLCopyContents(acl, &applications, &label, &prompt), "读取访问规则内容")
            let appData: [Data]? = try (applications as? [SecTrustedApplication]).map { apps in
                try apps.map { app in
                    var data: CFData?
                    try requireSuccess(SecTrustedApplicationCopyData(app, &data), "读取允许应用标识")
                    guard let data else { throw GuardFailure.message("允许应用标识为空") }
                    return data as Data
                }
            }
            return Entry(acl: acl, authorizations: authorizations.sorted(), applications: applications,
                applicationData: appData, label: label as String? ?? "", prompt: prompt)
        }
    }
    static func appending(_ partition: String, to hex: String) throws -> String {
        guard partition.range(of: #"^cdhash:[0-9a-f]{40}$"#, options: .regularExpression) != nil,
              !hex.isEmpty, hex.count <= 131072, hex.count % 2 == 0 else {
            throw GuardFailure.message("分区元数据格式异常；未更改权限")
        }
        var dictionary = try dictionary(hex)
        guard var values = dictionary["Partitions"] as? [String], !values.isEmpty else {
            throw GuardFailure.message("分区列表异常；未更改权限")
        }
        if values.contains(partition) { return hex }
        values.append(partition); dictionary["Partitions"] = values
        let updated = try PropertyListSerialization.data(fromPropertyList: dictionary, format: .xml, options: 0)
        return updated.map { String(format: "%02x", $0) }.joined()
    }
    static func dictionary(_ hex: String) throws -> [String: Any] {
        guard !hex.isEmpty, hex.count <= 131072, hex.count % 2 == 0 else { throw GuardFailure.message("分区编码格式异常") }
        var data = Data(), i = hex.startIndex
        while i < hex.endIndex {
            let next = hex.index(i, offsetBy: 2)
            guard let byte = UInt8(hex[i..<next], radix: 16) else { throw GuardFailure.message("分区元数据不可解析") }
            data.append(byte); i = next
        }
        guard let dictionary = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw GuardFailure.message("分区列表异常；未更改权限")
        }
        return dictionary
    }
    static func protectedMetadata(_ entries: [Entry]) -> [String] {
        entries.filter {
            !$0.authorizations.contains(kSecACLAuthorizationPartitionID as String)
            && !$0.authorizations.contains(kSecACLAuthorizationIntegrity as String)
        }.map { entry in
            let object: [String: Any] = ["authorizations": entry.authorizations,
                "label": entry.label, "prompt": entry.prompt.rawValue,
                "applications": entry.applicationData.map { $0.map { $0.base64EncodedString() } } as Any? ?? NSNull()]
            let encoded = try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            return SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
        }.sorted()
    }
}

/// Compatibility reader/writer for the installed client's own encrypted INI fields.
/// Static credentials are migrated to Keychain; this is not the guard's storage cipher.
struct VendorCipher {
    private let key: Data
    init() throws {
        let binary = try Data(contentsOf: URL(fileURLWithPath: "/Applications/MotionPro.app/Contents/MacOS/MotionPro"))
        let digest = SHA256.hash(data: binary).map { String(format: "%02x", $0) }.joined()
        guard digest == "1fc77ba8f6c67919b4b3338a7236b8a7452e827a66789ca9b57b91f80a79dfac",
              binary.count > 0x22b750 else { throw GuardFailure.unsupportedClient }
        key = binary.subdata(in: 0x22b740..<0x22b750)
    }
    init(testKey: Data) { key = testKey }
    private func crypt(_ input: Data, iv: Data, operation: CCOperation) throws -> Data {
        guard key.count == 16, iv.count == 16, input.count % 16 == 0 else { throw GuardFailure.invalidCredentials }
        var output = Data(count: input.count + 16), moved = 0
        let capacity = output.count
        let result = output.withUnsafeMutableBytes { out in
            input.withUnsafeBytes { src in
                key.withUnsafeBytes { k in
                    iv.withUnsafeBytes { v in
                        CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), 0, k.baseAddress, key.count,
                                v.baseAddress, src.baseAddress, input.count, out.baseAddress, capacity, &moved)
                    }
                }
            }
        }
        guard result == kCCSuccess else { throw GuardFailure.invalidCredentials }
        output.count = moved; return output
    }
    func decrypt(_ encoded: String) throws -> String {
        guard let raw = Data(base64Encoded: encoded), raw.count >= 32, raw.count % 16 == 0 else {
            throw GuardFailure.invalidCredentials
        }
        let plain = try crypt(Data(raw.dropFirst(16)), iv: Data(raw.prefix(16)), operation: CCOperation(kCCDecrypt))
        let prefix = plain.prefix { $0 != 0 }
        guard let value = String(data: prefix, encoding: .utf8), !value.isEmpty,
              value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else {
            throw GuardFailure.invalidCredentials
        }
        return value
    }
    func encrypt(_ text: String) throws -> String {
        var input = Data(text.utf8)
        guard !input.isEmpty else { return "" }
        let padding = (16 - input.count % 16) % 16
        input.append(Data(repeating: 0, count: padding))
        var iv = Data(count: 16)
        let result = iv.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 16, $0.baseAddress!) }
        guard result == errSecSuccess else { throw GuardFailure.message("无法生成随机数") }
        return (iv + (try crypt(input, iv: iv, operation: CCOperation(kCCEncrypt)))).base64EncodedString()
    }
}

struct INIFile {
    var lines: [String]
    init(text: String) { lines = text.components(separatedBy: "\n") }
    func raw(section: String, key: String) -> String? {
        var current = ""
        for line in lines {
            if line.hasPrefix("[") && line.hasSuffix("]") { current = String(line.dropFirst().dropLast()); continue }
            if current == section, let equal = line.firstIndex(of: "="), String(line[..<equal]) == key {
                return String(line[line.index(after: equal)...])
            }
        }
        return nil
    }
    func value(section: String, key: String) -> String? {
        guard var value = raw(section: section, key: key) else { return nil }
        if value.hasPrefix("\"") && value.hasSuffix("\"") { value = String(value.dropFirst().dropLast()) }
        return value
    }
    mutating func set(section: String, key: String, raw: String?) {
        var current = "", sectionStart: Int?, insertAt: Int?
        for i in lines.indices {
            if lines[i].hasPrefix("[") && lines[i].hasSuffix("]") {
                if current == section && insertAt == nil { insertAt = i }
                current = String(lines[i].dropFirst().dropLast())
                if current == section { sectionStart = i }
            }
            if current == section, let equal = lines[i].firstIndex(of: "="), String(lines[i][..<equal]) == key {
                if let raw { lines[i] = key + "=" + raw } else { lines.remove(at: i) }
                return
            }
        }
        guard let raw else { return }
        if sectionStart == nil { lines += ["[\(section)]", key + "=" + raw] }
        else { lines.insert(key + "=" + raw, at: insertAt ?? lines.count) }
    }
    var text: String { lines.joined(separator: "\n") }
}

struct LoginTransaction: Codable {
    var autoConnect: String?
    var reconnectInvalid: String?
    var originalSecond: String?
    var injectedSecond: String
    var prefix: String
    var createdAt: Date
    var injectedAutoConnect: String? = nil

    func restore(into ini: inout INIFile) {
        if ini.raw(section: "profiles", key: prefix + "password2") == injectedSecond {
            ini.set(section: "profiles", key: prefix + "password2", raw: originalSecond)
        }
        if ini.raw(section: "global", key: "autoconnect") == (injectedAutoConnect ?? "true") {
            ini.set(section: "global", key: "autoconnect", raw: autoConnect)
        }
        if ini.raw(section: "profiles", key: prefix + "reconn_sess_invalid") == "0" {
            ini.set(section: "profiles", key: prefix + "reconn_sess_invalid", raw: reconnectInvalid)
        }
    }
}

enum VendorProfile {
    static var url: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/MotionPro/motionpro.ini")
    }
    static func read() throws -> INIFile { INIFile(text: try String(contentsOf: url, encoding: .utf8)) }
    static func prefix(_ ini: INIFile) throws -> String {
        let count = Int(ini.value(section: "profiles", key: "data\\size") ?? "0") ?? 0
        guard count > 0 && count < 100 else { throw GuardFailure.invalidCredentials }
        let matches = (1...count).filter {
            ini.value(section: "profiles", key: "data\\\($0)\\host") == GuardIdentity.host
        }
        guard matches.count == 1 else { throw GuardFailure.message("需要唯一的目标 VPN 配置") }
        return "data\\\(matches[0])\\"
    }
    static func importCredentials() throws {
        let ini = try read(), p = try prefix(ini)
        guard let user = ini.value(section: "profiles", key: p + "username"), !user.isEmpty,
              let encrypted = ini.value(section: "profiles", key: p + "password") else { throw GuardFailure.invalidCredentials }
        let password = try VendorCipher().decrypt(encrypted)
        let credentials = Credentials(host: GuardIdentity.host, username: user, password: password)
        try Vault.put(JSONEncoder().encode(credentials), account: GuardIdentity.host, interactive: true)
    }
    static func prepare(credentials: Credentials, otp: String) throws {
        guard credentials.host == GuardIdentity.host, otp.range(of: #"^\d{6}$"#, options: .regularExpression) != nil else {
            throw GuardFailure.invalidCredentials
        }
        var ini = try read(); let p = try prefix(ini), cipher = try VendorCipher()
        guard ini.value(section: "profiles", key: p + "username") == credentials.username else {
            throw GuardFailure.message("客户端账号已改变，请重新导入凭据")
        }
        let defaultProfile = ini.value(section: "global", key: "default_profile")
        guard defaultProfile == ini.value(section: "profiles", key: p + "name") else {
            throw GuardFailure.message("请将目标 VPN 设为默认配置")
        }
        let second = "\"" + (try cipher.encrypt(otp)) + "\""
        let tx = LoginTransaction(autoConnect: ini.raw(section: "global", key: "autoconnect"),
                                  reconnectInvalid: ini.raw(section: "profiles", key: p + "reconn_sess_invalid"),
                                  originalSecond: ini.raw(section: "profiles", key: p + "password2"),
                                  injectedSecond: second, prefix: p, createdAt: Date())
        try Vault.put(JSONEncoder().encode(tx), account: "pending-login")
        ini.set(section: "global", key: "autoconnect", raw: "true")
        ini.set(section: "profiles", key: p + "reconn_sess_invalid", raw: "0")
        ini.set(section: "profiles", key: p + "password", raw: "\"" + (try cipher.encrypt(credentials.password)) + "\"")
        ini.set(section: "profiles", key: p + "password2", raw: second)
        try write(ini)
    }
    /// Read-only preflight before waiting for OTP or closing the client.
    static func validateForLogin(credentials: Credentials) throws {
        let ini = try read(), p = try prefix(ini)
        _ = try VendorCipher()
        guard credentials.host == GuardIdentity.host,
              ini.value(section: "profiles", key: p + "username") == credentials.username,
              ini.value(section: "global", key: "default_profile") == ini.value(section: "profiles", key: p + "name") else {
            throw GuardFailure.message("账号或默认站点已改变；保留客户端，请检查目标 VPN 配置")
        }
    }
    /// Reopen the UI after a pre-submission failure without submitting an old
    /// saved OTP. Keep a rollback record for the client's cached settings.
    static func prepareIdleLaunch() throws {
        try cleanup(clientStopped: true)
        var ini = try read()
        let tx = try configureIdleLaunch(&ini)
        try Vault.put(JSONEncoder().encode(tx), account: "pending-login")
        try write(ini)
    }
    static func configureIdleLaunch(_ ini: inout INIFile) throws -> LoginTransaction {
        let p = try prefix(ini)
        let second = ini.raw(section: "profiles", key: p + "password2")
        let tx = LoginTransaction(autoConnect: ini.raw(section: "global", key: "autoconnect"),
                                  reconnectInvalid: ini.raw(section: "profiles", key: p + "reconn_sess_invalid"),
                                  originalSecond: second, injectedSecond: second ?? "", prefix: p,
                                  createdAt: Date(), injectedAutoConnect: "false")
        ini.set(section: "global", key: "autoconnect", raw: "false")
        ini.set(section: "profiles", key: p + "reconn_sess_invalid", raw: "0")
        return tx
    }
    static func cleanup(clientStopped: Bool = false) throws {
        guard let data = try Vault.get("pending-login") else { return }
        let tx = try JSONDecoder().decode(LoginTransaction.self, from: data)
        var ini = try read()
        let originalText = ini.text
        // Do not overwrite credentials/preferences the user changed during a login.
        tx.restore(into: &ini)
        if ini.text != originalText { try write(ini) }
        // Qt can write its cached preferences again when the client quits.
        // Retain the rollback record until after that final write has happened.
        if clientStopped { try Vault.remove("pending-login") }
    }
    static func write(_ ini: INIFile) throws {
        try ini.text.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
