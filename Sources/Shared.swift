// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation

enum GuardIdentity {
    static let bundle = "org.motionproguard.app"
    static let widgetBundle = "org.motionproguard.app.widget"
    static let widgetKind = "MotionProGuardOSSStatus"
    static let host = BuildConfiguration.gateway
    static let appName = "MotionPro Guard OSS"
    static var support: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/MotionProGuardOSS")
    }
    static var snapshotURL: URL { support.appendingPathComponent("status.json") }
}

struct GuardSnapshot: Codable {
    var state: String = "starting"
    var title: String = "正在检查"
    var detail: String = "读取 MotionPro 连接状态"
    var gateway: String = GuardIdentity.host
    var updatedAt = Date()
    var connectedSince: Date?
    var authenticatedAt: Date?
    var recoveryEnabled = true
    var credentialReady = false
    // Nil means not checked in this process, never "missing" or "authorized".
    var credentialCheckState: String?
    var credentialCheckedAt: Date?
    // Readability is distinct from the rollover proof required before login.
    var otpReady = false
    var otpCheckState: String?
    var otpCheckedAt: Date?
    var otpFreshnessState: String?
    var otpProvider: String?
    var offlineOTPReady: Bool?
    var offlineOTPCheckState: String?
    var lockedOTPGenerationSamples: Int?
    var accessibilityReady = false
    var lastRecovery: Date?
    var recoveryCount = 0
    // Optional so an existing snapshot remains readable during an app update.
    var recentReconnectionDates: [Date]?
    var attemptsThisHour = 0
    var pausedUntil: Date?
    var backgroundOTPVerifiedAt: Date?
    var backgroundOTPVerifiedWhileLocked: Bool?
    var backgroundOTPProbeResult: String?
    var source = "MotionPro 本机状态"
    var processGeneration: String?
    var lastCheckStartedAt: Date?
    var lastCheckCompletedAt: Date?
    var lastProgressAt: Date?
    var stateEnteredAt: Date?
    var stateDeadline: Date?
    var nextCheckAt: Date?
    var waitReason: String?
    var episodeID: String?
    var attemptID: String?
    var lastSubmissionAt: Date?
    var lastConnectionInitiator: String?
    var recoveryBusy: Bool?
    var profileMutationActive: Bool?
    var manualControlUntil: Date?
    var confirmedRecoveryCount: Int?
    var reliabilityState: String?
    static var placeholder: Self { Self() }
    var otpAccessReady: Bool {
        if offlineOTPCheckState != nil && offlineOTPCheckState != "missing" { return offlineOTPReady == true }
        return accessibilityReady
    }
    func reconnectionCount(at now: Date) -> Int? {
        recentReconnectionDates.map { dates in
            dates.filter { $0 > now.addingTimeInterval(-ReconnectHistory.window) && $0 <= now }.count
        }
    }
}

/// Successful campus tunnel reconnections, independent of who initiated them.
/// Keep the first known connection as a baseline, not as a reconnection.
struct ReconnectHistory: Codable, Equatable {
    static let window: TimeInterval = 72 * 3600
    var firstConnection: Date?
    var reconnections: [Date] = []

    mutating func merge(_ connections: [Date], now: Date) {
        let valid = connections.filter { $0.timeIntervalSince1970.isFinite && $0 <= now }
        let previousFirst = firstConnection
        firstConnection = (valid + [previousFirst].compactMap { $0 }).min()
        var candidates = Set(reconnections + valid)
        if let previousFirst { candidates.insert(previousFirst) }
        let cutoff = now.addingTimeInterval(-Self.window)
        reconnections = candidates.filter {
            $0 > cutoff && $0 <= now && $0 > (firstConnection ?? .distantFuture)
        }.sorted()
    }
}

/// Accept the connection-finished callback only when its mode confirms an L3
/// tunnel. Authentication alone and desktop-only sessions do not count.
struct ConnectionLogParser {
    private var pendingConnection: Date?
    private let formatter: DateFormatter = {
        let value = DateFormatter()
        value.locale = Locale(identifier: "en_US_POSIX")
        value.timeZone = .current
        value.dateFormat = "yyyy-MM-dd HH:mm:ss"
        value.isLenient = false
        return value
    }()

    mutating func consume(_ line: String) -> Date? {
        guard line.contains("OnVpnConnected:"), line.count >= 19,
              let date = formatter.date(from: String(line.prefix(19))) else { return nil }
        if line.contains("OnVpnConnected: vpn connected finish, start set display status.") {
            pendingConnection = date
            return nil
        }
        let confirmsTunnel = line.contains("OnVpnConnected: current tunnel type is L3VPN only")
            || line.contains("OnVpnConnected: get vpnd status is l3 connected, need send status both connected to vpnd.")
        guard confirmsTunnel, let pending = pendingConnection,
              date.timeIntervalSince(pending) >= 0, date.timeIntervalSince(pending) <= 30 else { return nil }
        pendingConnection = nil
        return pending
    }
}

enum VendorStatus: Int, Codable {
    case idle = 0, connecting = 1, connected = 2, disconnecting = 3
    case reconnecting = 4, desktopConnected = 5, bothConnected = 6, disconnected = 7
    var hasTunnel: Bool { self == .connected || self == .bothConnected }
    var isBusy: Bool { self == .connecting || self == .disconnecting || self == .reconnecting }
    var mayLogin: Bool { self == .idle || self == .disconnected }
    static func parse(_ output: String) -> Self? {
        guard let range = output.range(of: #"(?m)^VPN status:([0-7])\s*$"#, options: .regularExpression),
              let digit = output[range].trimmingCharacters(in: .whitespacesAndNewlines).last,
              let value = digit.wholeNumberValue else { return nil }
        return Self(rawValue: value)
    }
}

struct RecoveryPolicy: Codable {
    var enabled = true
    var submissions: [Date] = []
    var consecutiveFailures = 0
    var lastSuccess: Date?
    var successCount = 0
    var manualHold = false
    var manualControlUntil: Date?
    var confirmedSuccessCount: Int?
    var lockedSuccessDates: [Date]?

    static func loadOrHold(_ data: Data, now: Date = Date()) -> Self {
        if let saved = try? JSONDecoder().decode(Self.self, from: data),
           saved.consecutiveFailures >= 0, saved.successCount >= 0,
           saved.submissions.allSatisfy({ $0.timeIntervalSince1970.isFinite }) { return saved }
        // Lost/corrupt state must not grant another submission budget.
        var held = Self(); held.enabled = false; held.manualHold = true
        held.submissions = [now, now]
        return held
    }

    mutating func prune(now: Date) { submissions.removeAll { now.timeIntervalSince($0) >= 3600 } }
    func allowed(now: Date) -> Bool {
        enabled && !manualHold && (manualControlUntil == nil || manualControlUntil! <= now)
            && consecutiveFailures < 2 && submissions.filter { now.timeIntervalSince($0) < 3600 }.count < 2
    }
    mutating func submit(now: Date) throws {
        prune(now: now)
        guard allowed(now: now) else { throw GuardFailure.retryLimit }
        submissions.append(now)
    }
    mutating func failed() { consecutiveFailures += 1; if consecutiveFailures >= 2 { manualHold = true } }
    mutating func succeeded(now: Date) {
        consecutiveFailures = 0; lastSuccess = now; successCount += 1
    }
    mutating func confirmed(now: Date, locked: Bool) {
        succeeded(now: now)
        confirmedSuccessCount = (confirmedSuccessCount ?? 0) + 1
        if locked { lockedSuccessDates = Array(((lockedSuccessDates ?? []) + [now]).suffix(30)) }
    }
}

enum GuardFailure: Error, LocalizedError {
    case message(String), retryLimit, noPermission, noOTP, invalidCredentials, unsupportedClient
    var errorDescription: String? {
        switch self {
        case .message(let text): return text
        case .retryLimit: return "已达到重试上限，请检查账号后恢复"
        case .noPermission: return "需要辅助功能权限以读取动态口令"
        case .noOTP: return "请在 MotionPro OTP 中显示当前站点的动态口令"
        case .invalidCredentials: return "未找到可用的已保存账号密码"
        case .unsupportedClient: return "MotionPro 已更新，请重新检查客户端兼容性"
        }
    }
}

struct OTPReading {
    let code: String
    let secondsRemaining: Int
    static func parse(buttonDescriptions: [String]) -> Self? {
        // The OTP page exposes three code buttons followed by its timer.
        // The timer uses "0" + seconds, so 10 -> 9 changes "010" -> "09".
        // Classifying by digit count loses the final nine seconds and every rollover.
        let numeric = buttonDescriptions.filter { $0.range(of: #"^[0-9]+$"#, options: .regularExpression) != nil }
        guard numeric.count == 4,
              numeric.prefix(3).allSatisfy({ $0.range(of: #"^[0-9]{2}$"#, options: .regularExpression) != nil }),
              numeric[3].range(of: #"^[0-9]{1,3}$"#, options: .regularExpression) != nil,
              let seconds = Int(numeric[3]), (0...60).contains(seconds) else { return nil }
        return Self(code: numeric.prefix(3).joined(), secondsRemaining: seconds)
    }

    var freshEnough: Bool { secondsRemaining >= 25 }
}

/// Memory-only evidence that a background AX value is advancing in real time.
/// A cached valid-looking countdown alone must never authorize a login.
struct OTPFreshnessProof {
    private var previous: (reading: OTPReading, uptime: TimeInterval)?
    private var candidate: (code: String, expiry: TimeInterval)?

    mutating func observe(_ reading: OTPReading, uptime: TimeInterval) -> Bool {
        defer { previous = (reading, uptime) }
        guard uptime.isFinite, (0...60).contains(reading.secondsRemaining),
              reading.code.range(of: #"^[0-9]{6}$"#, options: .regularExpression) != nil,
              let old = previous else { candidate = nil; return false }
        let elapsed = uptime - old.uptime
        guard elapsed >= 0.5, elapsed <= 4 else { candidate = nil; return false }
        if old.reading.code != reading.code {
            // Require a witnessed rollover near the old code's expiry.
            candidate = Double(old.reading.secondsRemaining) <= elapsed + 2 && reading.freshEnough
                ? (reading.code, uptime + Double(reading.secondsRemaining)) : nil
            return false
        }
        guard let proof = candidate, proof.code == reading.code else { return false }
        let drop = old.reading.secondsRemaining - reading.secondsRemaining
        guard drop > 0, abs(Double(drop) - elapsed) <= 1.5,
              abs(proof.expiry - uptime - Double(reading.secondsRemaining)) <= 2 else {
            candidate = nil; return false
        }
        return reading.freshEnough && proof.expiry - uptime >= 25
    }
}
