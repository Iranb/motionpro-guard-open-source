// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import CryptoKit
import CoreFoundation

/// This provider never reads a window. Token material is kept in Guard's
/// nonsynchronizing Keychain item, and each sample rechecks silent access.
enum OfflineOTP {
    static let account = "offline-otp.v1"

    enum Failure: Error, LocalizedError {
        case missing, invalid, binding, sourceUnverified, sourceChanged, officialMismatch, clockBoundary, clockSettling, clockChanged
        var errorDescription: String? {
            switch self {
            case .missing: return "尚未导入并验证后台 OTP 令牌"
            case .invalid: return "后台 OTP 令牌格式或验证记录无效"
            case .binding: return "后台 OTP 的账号或网关与当前配置不匹配"
            case .sourceUnverified: return "后台令牌未绑定官方数据源；请重新与官方口令同步，尚未提交登录"
            case .sourceChanged: return "官方令牌已变化或不可读取；请重新同步，尚未提交登录"
            case .officialMismatch: return "后台 OTP 与官方窗口不一致；停止登录并等待重新同步"
            case .clockBoundary: return "等待下一轮口令；当前有效期不足或时钟调整范围跨越轮换边界"
            case .clockSettling: return "正在检查后台计算的时钟连续性"
            case .clockChanged: return "检测到系统时间变化；等待时钟稳定后重新计算"
            }
        }
    }

    struct Token: Codable {
        let version: Int
        let host: String
        let username: String
        let seed: Data
        let period: Int
        var clockUncertainty: Double
        let verifiedAt: Date
        let verifiedPeriods: Int
        var sourcePath: String? = nil

        func validate() throws {
            guard version == 1, host == GuardIdentity.host, !username.isEmpty,
                  seed.count == 10, (30...300).contains(period), period % 30 == 0,
                  clockUncertainty.isFinite, clockUncertainty >= 0,
                  clockUncertainty < min(5, Double(period) / 4),
                  verifiedAt.timeIntervalSince1970.isFinite,
                  verifiedAt > Date(timeIntervalSince1970: 0),
                  verifiedPeriods >= 2 else { throw Failure.invalid }
        }

        func requireBinding(credentials: Credentials, profileUsername: String) throws {
            try validate()
            guard credentials.host == host, credentials.username == username,
                  profileUsername == username else { throw Failure.binding }
        }

        /// Never reuse a verified copy after the official seed/period changes.
        /// Revalidation requires the live reference; do not silently import a new seed.
        @discardableResult func requireCurrentSource() throws -> Token {
            guard let sourcePath else { throw Failure.sourceUnverified }
            do {
                let current = try OfflineOTP.candidate(data: OfflineOTP.sourceData(path: sourcePath), username: username)
                guard matchesSource(current) else { throw Failure.sourceChanged }
                return current
            } catch { throw Failure.sourceChanged }
        }

        func matchesSource(_ current: Token) -> Bool {
            // An offset refresh does not replace the enrolled seed. Its current
            // validated uncertainty is applied to generation by load().
            seed == current.seed && period == current.period && host == current.host &&
                username == current.username
        }

        /// The vendor offset's sign is not a confirmed contract. Accept only a
        /// counter shared by UTC and both possible adjustments, with a margin.
        /// Near a boundary, wait rather than guess or submit an adjacent code.
        func reading(at wallTime: TimeInterval) throws -> OTPReading {
            guard wallTime.isFinite, wallTime >= clockUncertainty,
                  wallTime < 253_402_300_799 else { throw Failure.clockChanged }
            let earliest = wallTime - clockUncertainty, latest = wallTime + clockUncertainty
            let first = floor(earliest / Double(period)), last = floor(latest / Double(period))
            guard first == last else { throw Failure.clockBoundary }
            let remaining = Int(floor((last + 1) * Double(period) - latest))
            guard remaining > 0 else { throw Failure.clockBoundary }
            return OTPReading(code: TOTP.generate(seed: seed, counter: UInt64(last)), secondsRemaining: remaining)
        }
    }

    /// Public RFC vectors use dummy keys only. Real seeds/codes never leave memory.
    enum TOTP {
        static func generate(seed: Data, counter: UInt64, digits: Int = 6) -> String {
            precondition(digits == 6 || digits == 8)
            let message = Data((0..<8).reversed().map { UInt8(truncatingIfNeeded: counter >> ($0 * 8)) })
            let digest = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: SymmetricKey(data: seed)))
            let offset = Int(digest.last! & 15)
            let value = digest[offset..<(offset + 4)].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } & 0x7fffffff
            let modulus: UInt32 = digits == 8 ? 100_000_000 : 1_000_000
            return String(format: "%0*u", digits, value % modulus)
        }
    }

    struct Clock {
        private var previous: (wall: TimeInterval, uptime: TimeInterval)?
        private var settled = false
        mutating func observe(wall: TimeInterval, uptime: TimeInterval) throws {
            guard wall.isFinite, uptime.isFinite, wall > 0, uptime >= 0 else {
                previous = nil; settled = false; throw Failure.clockChanged
            }
            defer { previous = (wall, uptime) }
            guard let old = previous else { throw Failure.clockSettling }
            let elapsed = uptime - old.uptime, wallElapsed = wall - old.wall
            guard elapsed >= 0, wallElapsed >= 0, elapsed <= 20,
                  abs(wallElapsed - elapsed) <= 1.5 else {
                settled = false; throw Failure.clockChanged
            }
            if elapsed >= 0.5 { settled = true }
            guard settled else { throw Failure.clockSettling }
        }
    }

    static func profileUsername() throws -> String {
        let ini = try VendorProfile.read(), prefix = try VendorProfile.prefix(ini)
        guard let username = ini.value(section: "profiles", key: prefix + "username"), !username.isEmpty
        else { throw Failure.binding }
        return username
    }

    static func load() throws -> Token {
        guard let bytes = try Vault.get(account) else { throw Failure.missing }
        var token: Token
        do { token = try JSONDecoder().decode(Token.self, from: bytes); try token.validate() }
        catch { throw Failure.invalid }
        guard let credentials = try Vault.credentials() else { throw GuardFailure.invalidCredentials }
        try token.requireBinding(credentials: credentials, profileUsername: profileUsername())
        token.clockUncertainty = try token.requireCurrentSource().clockUncertainty
        return token
    }

    static func sourceData(path: String) throws -> Data {
        let url = URL(fileURLWithPath: path)
        guard url.path == url.resolvingSymlinksInPath().path else { throw Failure.sourceChanged }
        let attributes = try FileManager.default.attributesOfItem(atPath: path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 1_048_576 else { throw Failure.sourceChanged }
        return try Data(contentsOf: url, options: .uncached)
    }

    /// Import is an explicit one-time action. It never modifies or rebinds the
    /// official token. Live comparison must succeed before anything is saved.
    static func candidate(data: Data, username: String) throws -> Token {
        guard data.count <= 1_048_576,
              let sites = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [[String: Any]]
        else { throw Failure.invalid }
        let selected = sites.filter { $0["VirtualSiteURL"] as? String == "https://" + GuardIdentity.host }
        guard selected.count == 1, let site = selected.first,
              let numbers = site["VirtualSiteRandomData"] as? [NSNumber], numbers.count == 10,
              numbers.allSatisfy({ CFGetTypeID($0) != CFBooleanGetTypeID() &&
                  $0.doubleValue == Double($0.intValue) && (0...255).contains($0.intValue) }),
              let period = site["VirtualSiteDyncode"] as? NSNumber,
              CFGetTypeID(period) != CFBooleanGetTypeID(), period.doubleValue == Double(period.intValue),
              let adjustment = site["VirtualSiteInterval"] as? NSNumber,
              CFGetTypeID(adjustment) != CFBooleanGetTypeID(), adjustment.doubleValue.isFinite
        else { throw Failure.invalid }
        let token = Token(version: 1, host: GuardIdentity.host, username: username,
            seed: Data(numbers.map { UInt8($0.intValue) }), period: period.intValue,
            clockUncertainty: abs(adjustment.doubleValue) + 0.5,
            verifiedAt: Date(), verifiedPeriods: 2)
        try token.validate()
        return token
    }
}
