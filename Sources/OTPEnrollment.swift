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

    static func run(path: String) async throws -> Int {
        guard !LocalSession.isLocked, AXIsProcessTrusted() else {
            throw GuardFailure.message("首次导入需在解锁状态与官方口令核对；之后的后台计算不依赖此权限")
        }
        let url = URL(fileURLWithPath: path).resolvingSymlinksInPath()
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              (attributes[.size] as? NSNumber)?.intValue ?? Int.max <= 1_048_576
        else { throw OfflineOTP.Failure.invalid }
        let username = try OfflineOTP.profileUsername()
        let candidate = try OfflineOTP.candidate(data: Data(contentsOf: url), username: username)
        let deadline = ProcessInfo.processInfo.systemUptime + 75
        var matchedPeriods: Set<UInt64> = [], matches = 0
        while ProcessInfo.processInfo.systemUptime < deadline {
            guard !LocalSession.isLocked else { throw GuardFailure.message("首次口令核对被锁屏中断；没有保存令牌") }
            if let reference = reference(), let generated = try? candidate.reading(at: Date().timeIntervalSince1970) {
                guard reference.code == generated.code else { throw GuardFailure.message("计算结果与官方口令不一致；没有保存令牌") }
                matchedPeriods.insert(UInt64(floor(Date().timeIntervalSince1970 / Double(candidate.period))))
                matches += 1
                if matchedPeriods.count >= 2 && matches >= 4 {
                    guard try OfflineOTP.profileUsername() == username else { throw OfflineOTP.Failure.binding }
                    let token = OfflineOTP.Token(version: candidate.version, host: candidate.host, username: username,
                        seed: candidate.seed, period: candidate.period, clockUncertainty: candidate.clockUncertainty,
                        verifiedAt: Date(), verifiedPeriods: matchedPeriods.count)
                    try Vault.put(JSONEncoder().encode(token), account: OfflineOTP.account)
                    return matchedPeriods.count
                }
            }
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        throw GuardFailure.message("未在 75 秒内完成两个周期的官方口令核对；没有保存令牌")
    }
}
