// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import AppKit
import ApplicationServices
import Darwin

/// Only used for explicit enrollment. Runtime generation uses OfflineOTP and
/// has no dependency on this reference reader, the official app, or AX rights.
enum OTPEnrollment {
    static func reference() -> OTPReading? {
        guard AXIsProcessTrusted(), !LocalSession.isLocked else { return nil }
        let apps = NSRunningApplication.runningApplications(withBundleIdentifier: OTPReader.bundle)
        guard apps.count == 1 else { return nil }
        let root = AXUIElementCreateApplication(apps[0].processIdentifier)
        let deadline = ProcessInfo.processInfo.systemUptime + 4
        func attribute(_ node: AXUIElement, _ name: String) -> CFTypeRef? {
            guard ProcessInfo.processInfo.systemUptime < deadline else { return nil }
            AXUIElementSetMessagingTimeout(node, 0.2)
            var value: CFTypeRef?
            return AXUIElementCopyAttributeValue(node, name as CFString, &value) == .success ? value : nil
        }
        guard let windows = attribute(root, kAXWindowsAttribute) as? [AXUIElement], !windows.isEmpty else { return nil }
        var queue = windows.enumerated().map { ($0.element, 0, "window\($0.offset)") }
        var visited: [CFHashCode: [AXUIElement]] = [:], labels: Set<String> = []
        var groups: [String: [String]] = [:], cursor = 0, count = 0
        func parent(_ path: String) -> String { path.split(separator: "/").dropLast().joined(separator: "/") }
        while cursor < queue.count {
            guard count < 1000, ProcessInfo.processInfo.systemUptime < deadline else { return nil }
            let (node, depth, path) = queue[cursor]; cursor += 1
            let hash = CFHash(node)
            if visited[hash, default: []].contains(where: { CFEqual($0, node) }) { continue }
            visited[hash, default: []].append(node); count += 1
            let role = attribute(node, kAXRoleAttribute) as? String ?? ""
            let text = [kAXDescriptionAttribute, kAXTitleAttribute, kAXValueAttribute].map { attribute(node, $0) as? String ?? "" }
            if text.contains(where: { $0 == "一次性密码" || $0 == "One Time Password" }) { labels.insert(parent(path)) }
            if role == kAXButtonRole { groups[parent(path), default: []].append(text.first(where: { !$0.isEmpty }) ?? "") }
            let children = attribute(node, kAXChildrenAttribute) as? [AXUIElement] ?? []
            guard children.isEmpty || depth < 20 else { return nil }
            queue += children.enumerated().map { ($0.element, depth + 1, path + "/\($0.offset)") }
        }
        let readings = labels.compactMap { OTPReading.parse(buttonDescriptions: groups[$0] ?? []) }
        return labels.count == 1 && readings.count == 1 ? readings[0] : nil
    }

    /// Compare the existing Keychain token with the current official window.
    /// Does not enroll, write credentials/profile/policy, or run recovery.
    static func compareCurrent() async throws -> [String: Any] {
        guard AXIsProcessTrusted(), LocalSession.unlocked else {
            throw GuardFailure.message("实时比对需解锁桌面和已授权的官方 OTP 窗口；未进行登录")
        }
        var proof = OTPAlignmentProof(), clock = OfflineOTP.Clock()
        var unreadable = 0
        let deadline = ProcessInfo.processInfo.systemUptime + 75
        while ProcessInfo.processInfo.systemUptime < deadline {
            guard LocalSession.unlocked else {
                throw GuardFailure.message("桌面锁定，实时窗口比对已停止；未进行登录")
            }
            let token = try OfflineOTP.load()
            let before = Date().timeIntervalSince1970
            let uptime = ProcessInfo.processInfo.systemUptime
            do { try clock.observe(wall: before, uptime: uptime) }
            catch OfflineOTP.Failure.clockSettling {
                try await Task.sleep(nanoseconds: 1_000_000_000); continue
            }
            if let observed = reference() {
                let after = Date().timeIntervalSince1970
                do {
                    let expected = try token.reading(at: after)
                    // Require margin from both edges, avoiding UI rollover lag.
                    if observed.secondsRemaining >= 5 && expected.secondsRemaining >= 5 &&
                       Double(token.period) - (after.truncatingRemainder(dividingBy: Double(token.period))) <= Double(token.period - 2) {
                        proof.observe(matches: observed.code == expected.code, before: before, after: after, period: token.period)
                    }
                } catch OfflineOTP.Failure.clockBoundary { }
            } else { unreadable += 1 }
            if proof.verified || proof.mismatchingSamples > 0 { break }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        return ["officialOTPAligned": proof.verified,
                "matchingSamples": proof.matchingSamples, "mismatchingSamples": proof.mismatchingSamples,
                "matchingPeriods": proof.periods.count, "unreadableWindowSamples": unreadable,
                "noLogin": true, "noCredentialOrTokenWrite": true, "secretsEmitted": false]
    }

    static func run(path: String) async throws -> Int {
        guard !LocalSession.isLocked, AXIsProcessTrusted() else {
            throw GuardFailure.message("首次导入需在解锁状态与官方口令核对；之后的后台计算不依赖此权限")
        }
        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        let username = try OfflineOTP.profileUsername()
        let candidate = try OfflineOTP.candidate(data: OfflineOTP.sourceData(path: url.path), username: username)
        let deadline = ProcessInfo.processInfo.systemUptime + 75
        var proof = OTPAlignmentProof(), clock = OfflineOTP.Clock()
        while ProcessInfo.processInfo.systemUptime < deadline {
            guard !LocalSession.isLocked else { throw GuardFailure.message("首次口令核对被锁屏中断；没有保存令牌") }
            let before = Date().timeIntervalSince1970
            do { try clock.observe(wall: before, uptime: ProcessInfo.processInfo.systemUptime) }
            catch OfflineOTP.Failure.clockSettling { try await Task.sleep(nanoseconds: 1_000_000_000); continue }
            if let reference = reference() {
                let after = Date().timeIntervalSince1970
                if let generated = try? candidate.reading(at: after), reference.secondsRemaining >= 5,
                   generated.secondsRemaining >= 5, after.truncatingRemainder(dividingBy: Double(candidate.period)) >= 2 {
                    proof.observe(matches: reference.code == generated.code, before: before, after: after, period: candidate.period)
                }
                guard proof.mismatchingSamples == 0 else { throw OfflineOTP.Failure.officialMismatch }
                if proof.verified {
                    guard try OfflineOTP.profileUsername() == username else { throw OfflineOTP.Failure.binding }
                    let current = try OfflineOTP.candidate(data: OfflineOTP.sourceData(path: url.path), username: username)
                    guard candidate.matchesSource(current) else { throw OfflineOTP.Failure.sourceChanged }
                    var token = OfflineOTP.Token(version: candidate.version, host: candidate.host, username: username,
                        seed: candidate.seed, period: candidate.period, clockUncertainty: candidate.clockUncertainty,
                        verifiedAt: Date(), verifiedPeriods: proof.periods.count)
                    token.sourcePath = url.path
                    try Vault.put(JSONEncoder().encode(token), account: OfflineOTP.account)
                    return proof.periods.count
                }
            }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        throw GuardFailure.message("未在 75 秒内完成两个周期的官方口令核对；没有保存令牌")
    }
}
