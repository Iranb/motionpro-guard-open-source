// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import AppKit
import ApplicationServices
import SystemConfiguration
import WidgetKit
import Darwin
import Network

enum VendorHelper {
    static func status() async -> VendorStatus? {
        await Task.detached(priority: .utility) {
            let process = Process(), output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/local/motionpro/vpn_cmdline")
            process.currentDirectoryURL = URL(fileURLWithPath: "/usr/local/motionpro")
            process.arguments = ["getstatus"]
            process.standardOutput = output; process.standardError = FileHandle.nullDevice
            do { try process.run() } catch { return nil }
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline { try? await Task.sleep(nanoseconds: 50_000_000) }
            if process.isRunning { process.terminate(); return nil }
            // The vendor uses the status as its exit code; 2 is a successful connected result.
            let data = output.fileHandleForReading.readDataToEndOfFile()
            return VendorStatus.parse(String(decoding: data, as: UTF8.self))
        }.value
    }
}

enum OTPReader {
    static let bundle = "net.arraynetworks.MotionProOTP"
    static var permission: Bool { AXIsProcessTrusted() }
    static var isActive: Bool { NSWorkspace.shared.frontmostApplication?.bundleIdentifier == bundle }
    struct Sample {
        var reading: OTPReading?
        var reason = "unavailable"
        var appCount = 0
        var nodes = 0
        var pairCount = 0
        var clockCount = 0
        var hasLabel = false
        var elapsed: TimeInterval = 0
        var axFailures = 0
        var numericStructure: [[String: Any]] = []
        var labelPaths: [String] = []
    }
    // Only structural diagnostics leave this reader. OTP digits stay in memory.
    static func sample() -> Sample {
        let began = ProcessInfo.processInfo.systemUptime
        var sample = Sample()
        guard permission else { sample.reason = "permission"; return sample }
        let apps = NSRunningApplication.runningApplications(withBundleIdentifier: bundle)
        sample.appCount = apps.count
        guard apps.count == 1, let app = apps.first else {
            sample.reason = apps.isEmpty ? "app_not_running" : "multiple_instances"; return sample
        }
        let root = AXUIElementCreateApplication(app.processIdentifier)
        let deadline = began + 4
        func attribute(_ item: AXUIElement, _ name: String) -> CFTypeRef? {
            guard ProcessInfo.processInfo.systemUptime < deadline else { return nil }
            AXUIElementSetMessagingTimeout(item, 0.25)
            var value: CFTypeRef?
            let status = AXUIElementCopyAttributeValue(item, name as CFString, &value)
            if status == .cannotComplete || status == .apiDisabled || status == .invalidUIElement { sample.axFailures += 1 }
            return status == .success ? value : nil
        }
        var buttons: [String] = []
        var buttonGroups: [String: [String]] = [:]
        var labelParents: Set<String> = []
        func parent(_ path: String) -> String { path.split(separator: "/").dropLast().joined(separator: "/") }
        func visit(_ node: AXUIElement, depth: Int, path: String = "root") {
            guard depth < 20 && sample.nodes < 500 && ProcessInfo.processInfo.systemUptime < deadline else { return }
            sample.nodes += 1
            let role = attribute(node, kAXRoleAttribute) as? String ?? ""
            let description = attribute(node, kAXDescriptionAttribute) as? String ?? ""
            let title = attribute(node, kAXTitleAttribute) as? String ?? ""
            let value = attribute(node, kAXValueAttribute) as? String ?? ""
            if [description, title, value].contains(where: { $0 == "一次性密码" || $0 == "One Time Password" }) {
                sample.hasLabel = true; labelParents.insert(parent(path)); sample.labelPaths.append(path)
            }
            if role == kAXButtonRole {
                let text = [description, title, value].first(where: { !$0.isEmpty }) ?? ""
                buttons.append(text)
                buttonGroups[parent(path), default: []].append(text)
                if text.range(of: #"^[0-9]+$"#, options: .regularExpression) != nil {
                    func shape(_ text: String) -> String {
                        if text.isEmpty { return "empty" }
                        return text.range(of: #"^[0-9]+$"#, options: .regularExpression) != nil ? "digits_\(text.count)" : "other"
                    }
                    sample.numericStructure.append(["path": path, "description": shape(description), "title": shape(title), "value": shape(value)])
                }
            }
            let children = attribute(node, kAXChildrenAttribute) as? [AXUIElement] ?? []
            for (index, child) in children.enumerated() { visit(child, depth: depth + 1, path: path + "/\(index)") }
        }
        visit(root, depth: 0)
        sample.elapsed = ProcessInfo.processInfo.systemUptime - began
        sample.pairCount = buttons.filter { $0.range(of: #"^[0-9]{2}$"#, options: .regularExpression) != nil }.count
        sample.clockCount = buttons.filter { $0.range(of: #"^[0-9]{3}$"#, options: .regularExpression) != nil }.count
        if sample.elapsed >= 4 { sample.reason = "read_timeout" }
        else if sample.nodes >= 500 { sample.reason = "tree_limit" }
        else if !sample.hasLabel { sample.reason = sample.axFailures > 0 ? "ax_unavailable" : "label_unavailable" }
        else {
            // Do not combine digits from different windows, tokens, or toolbar controls.
            let candidates = labelParents.compactMap { OTPReading.parse(buttonDescriptions: buttonGroups[$0] ?? []) }
            if candidates.count == 1, labelParents.count == 1 {
                sample.reading = candidates[0]; sample.reason = "readable"
            } else { sample.reason = "layout_unrecognized" }
        }
        return sample
    }
    static func read() throws -> OTPReading {
        let sample = sample()
        guard let reading = sample.reading else { throw GuardFailure.message(failureDetail(sample.reason)) }
        return reading
    }
    static func failureDetail(_ reason: String) -> String {
        switch reason {
        case "permission": return "读取 OTP 的辅助功能权限不可用"
        case "app_not_running": return "MotionPro OTP 未运行"
        case "multiple_instances": return "检测到多个 OTP 实例，无法确定当前口令来源"
        case "read_timeout": return "OTP 界面读取超时；尚未提交登录"
        case "ax_unavailable": return "OTP 界面暂未响应辅助功能读取；尚未提交登录"
        case "label_unavailable": return "OTP 正在运行，但未读到口令区域；尚未提交登录"
        case "layout_unrecognized", "tree_limit": return "OTP 界面结构未通过校验；尚未提交登录"
        default: return "OTP 暂不可读；尚未提交登录"
        }
    }
    static func diagnose() async {
        var proof = OTPFreshnessProof()
        var previous: (reading: OTPReading, at: TimeInterval)?
        let start = ProcessInfo.processInfo.systemUptime
        var index = 0, readable = 0, changes = 0, ticks = 0, verified = false
        while ProcessInfo.processInfo.systemUptime - start < 80 {
            let sample = sample(), now = ProcessInfo.processInfo.systemUptime
            var out: [String: Any] = ["sample": index, "reason": sample.reason, "appCount": sample.appCount,
                "nodes": sample.nodes, "pairCount": sample.pairCount, "clockCount": sample.clockCount,
                "hasLabel": sample.hasLabel, "readMs": Int(sample.elapsed * 1000), "axFailures": sample.axFailures,
                "locked": LocalSession.isLocked, "active": isActive]
            if index == 0 || sample.reason != "readable" { out["numericStructure"] = sample.numericStructure; out["labelPaths"] = sample.labelPaths }
            if let reading = sample.reading {
                readable += 1
                if let old = previous {
                    let changed = old.reading.code != reading.code
                    let drop = old.reading.secondsRemaining - reading.secondsRemaining
                    changes += changed ? 1 : 0; ticks += !changed && drop > 0 ? 1 : 0
                    out["codeChanged"] = changed; out["countdownDrop"] = drop
                    out["gapMs"] = Int((now - old.at) * 1000)
                    out["oldNearExpiry"] = old.reading.secondsRemaining <= 4
                }
                verified = proof.observe(reading, uptime: now)
                out["verified"] = verified
                previous = (reading, now)
            } else { proof = OTPFreshnessProof(); previous = nil }
            if index % 5 == 0 || out["codeChanged"] as? Bool == true || verified || sample.reason != "readable" {
                let data = try! JSONSerialization.data(withJSONObject: out, options: [.sortedKeys])
                print(String(decoding: data, as: UTF8.self)); fflush(stdout)
            }
            index += 1
            if verified { break }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
        let result: [String: Any] = ["complete": true, "samples": index, "readable": readable,
            "codeChanges": changes, "countdownTicks": ticks, "verified": verified, "noLogin": true]
        print(String(decoding: try! JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]), as: UTF8.self))
    }
    static func readAsync() async throws -> OTPReading {
        try await Task.detached(priority: .utility) { try read() }.value
    }
    static func openApp() {
        if let app = NSRunningApplication.runningApplications(withBundleIdentifier: bundle).first {
            app.activate(); return
        }
        NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: "/Applications/MotionProOTP.app"), configuration: .init())
    }
}

enum LocalSession {
    static var isLocked: Bool {
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return session["CGSSessionScreenIsLocked"] as? Bool == true
    }
    static var unlocked: Bool {
        guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return !(session["CGSSessionScreenIsLocked"] as? Bool ?? false)
            && (session[kCGSessionOnConsoleKey as String] as? Bool ?? true)
    }
    static var networkAvailable: Bool {
        guard let ref = SCNetworkReachabilityCreateWithName(nil, GuardIdentity.host) else { return false }
        var flags = SCNetworkReachabilityFlags()
        return SCNetworkReachabilityGetFlags(ref, &flags) && flags.contains(.reachable) && !flags.contains(.connectionRequired)
    }
}

enum LogHints {
    static func successfulTunnelConnections() -> (dates: [Date], readable: Bool) {
        let root = URL(fileURLWithPath: "/private/var/log/MotionPro")
        guard let files = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else {
            return ([], false)
        }
        var events: [Date] = [], readable = false
        for file in files.filter({ $0.pathExtension == "log" }) {
            guard let handle = try? FileHandle(forReadingFrom: file) else { continue }
            defer { try? handle.close() }
            var parser = ConnectionLogParser(), buffer = Data()
            // Stream complete files on the first scan so the 72-hour backfill is
            // not truncated by log-tail limits. No raw lines leave this method.
            do {
                while let chunk = try handle.read(upToCount: 65536), !chunk.isEmpty {
                    buffer.append(chunk)
                    while let newline = buffer.firstIndex(of: 10) {
                        let line = String(decoding: buffer[..<newline], as: UTF8.self)
                        if let date = parser.consume(line) { events.append(date) }
                        buffer.removeSubrange(...newline)
                    }
                }
                if !buffer.isEmpty, let date = parser.consume(String(decoding: buffer, as: UTF8.self)) { events.append(date) }
                readable = true
            } catch { continue }
        }
        return (events, readable)
    }

    static func recentLines() -> [String] {
        let root = URL(fileURLWithPath: "/private/var/log/MotionPro")
        let files = (try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
        return files.filter { $0.pathExtension == "log" }.flatMap { file -> [String] in
            guard let h = try? FileHandle(forReadingFrom: file) else { return [] }
            defer { try? h.close() }
            guard let size = try? h.seekToEnd() else { return [] }
            try? h.seek(toOffset: size > 320_000 ? size - 320_000 : 0)
            guard let data = try? h.readToEnd() else { return [] }
            // No raw log content is retained or published.
            return String(decoding: data, as: UTF8.self).components(separatedBy: "\n")
        }
    }
    static func date(_ line: String) -> Date? {
        guard line.count >= 19 else { return nil }
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current; f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.date(from: String(line.prefix(19)))
    }
    static func lastAuthentication() -> Date? {
        recentLines().filter { $0.contains("login successfully, method name:") }.compactMap(date).max()
    }
    static func boundedAuthentication() async -> Date? {
        (try? await ReadDeadline.run(seconds: 5) { lastAuthentication() }) ?? nil
    }
    static func boundedRejections(since: Date) async throws -> Int {
        do { return try await ReadDeadline.run(seconds: 5) { rejectionCount(since: since) } }
        catch { throw GuardFailure.message("近期认证日志读取超时；停止本次提交，等待下次检查") }
    }
    static func rejectionCount(since: Date) -> Int {
        recentLines().filter {
            $0.contains("MainWin::OnVpnLogin: error:") && (date($0) ?? .distantPast) >= since
        }.count
    }
}

@MainActor
final class GuardEngine: ObservableObject {
    @Published var snapshot = GuardSnapshot()
    @Published var setupMessage = ""
    @Published var busy = false
    @Published var authorizingCredentials = false
    @Published var probeOnNextLock = false
    @Published var policy: RecoveryPolicy
    private var timer: Timer?
    private var checking = false
    private var pendingProfileReconciled = false
    private var lastProfileReconcile = Date.distantPast
    private let journal = GuardJournal()
    private var evidence = StateEvidence()
    private var episodeID: String?
    private var activeAttempt: LoginAttribution?
    private var sessionObservers: [NSObjectProtocol] = []
    private let pathMonitor = NWPathMonitor()
    private var lastGatewayProbe = Date.distantPast
    private var gatewayReachable = false
    private var disconnectionWindow = DisconnectionWindow()
    private var lastAttemptEnd: Date?
    private var lastWidgetReload = Date.distantPast
    private var lastPublishedState = ""
    private var lastLogCheck = Date.distantPast
    private var lastReconnectScan = Date.distantPast
    private var lastPublishedReconnectCount: Int?
    private var reconnectHistory = ReconnectHistory()
    private var reconnectHistoryAvailable = false
    private var lastCredentialCheck = Date.distantPast
    private var lastOTPActivation = Date.distantPast
    private var otpClock = OfflineOTP.Clock()
    private var offlineOTPPeriod: Int?
    private var lockDescriptor: Int32 = -1
    private let policyURL = GuardIdentity.support.appendingPathComponent("recovery-policy.json")
    private let reconnectHistoryURL = GuardIdentity.support.appendingPathComponent("reconnect-history.json")

    init() {
        let root = GuardIdentity.support
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let savedPolicy = root.appendingPathComponent("recovery-policy.json")
        policy = FileManager.default.fileExists(atPath: savedPolicy.path)
            ? RecoveryPolicy.loadOrHold((try? Data(contentsOf: savedPolicy)) ?? Data()) : RecoveryPolicy()
        lockDescriptor = open(root.appendingPathComponent("guard.lock").path, O_CREAT | O_RDWR, 0o600)
        if lockDescriptor < 0 || flock(lockDescriptor, LOCK_EX | LOCK_NB) != 0 { exit(0) }
        if let data = try? Data(contentsOf: reconnectHistoryURL),
           let saved = try? JSONDecoder().decode(ReconnectHistory.self, from: data) {
            reconnectHistory = saved; reconnectHistoryAvailable = true
        }
        snapshot.processGeneration = journal.generation
        snapshot.profileMutationActive = false
        record("process_started")
    }

    func start() {
        timer = Timer.scheduledTimer(withTimeInterval: 10, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.check() }
        }
        for name in [NSWorkspace.didWakeNotification, NSWorkspace.sessionDidBecomeActiveNotification] {
            sessionObservers.append(NSWorkspace.shared.notificationCenter.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in
                    self?.record("session_or_wake_changed")
                    self?.otpClock = OfflineOTP.Clock()
                    await self?.check()
                }
            })
        }
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor in self?.lastGatewayProbe = .distantPast; await self?.check() }
        }
        pathMonitor.start(queue: DispatchQueue(label: "MotionProGuard.network-path"))
        Task { await check() }
    }

    func takeManualControl() {
        guard !busy else { setupMessage = "正在执行认证，请等待本次操作结束"; return }
        policy.manualControlUntil = Date().addingTimeInterval(600)
        snapshot.manualControlUntil = policy.manualControlUntil
        savePolicy(); record("manual_control_acquired", initiator: "user"); publish(); Task { await check() }
    }

    func resumeControl() {
        policy.manualControlUntil = nil; snapshot.manualControlUntil = nil
        savePolicy(); record("manual_control_released", initiator: "user"); publish(); Task { await check() }
    }

    func savePolicy() {
        if let data = try? JSONEncoder().encode(policy) {
            try? data.write(to: policyURL, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: policyURL.path)
        }
    }
    func setEnabled(_ enabled: Bool) { policy.enabled = enabled; savePolicy(); Task { await check() } }
    func releaseHold() {
        // A user can clear the failure hold, but not the two-submission rolling-hour budget.
        policy.manualHold = false; policy.consecutiveFailures = 0; savePolicy(); Task { await check() }
    }

    func importCredentials() async {
        guard !authorizingCredentials && !busy else { return }
        authorizingCredentials = true
        defer { authorizingCredentials = false }
        do {
            try await Task.detached(priority: .userInitiated) { try VendorProfile.importCredentials() }.value
            await refreshCredentials(interactive: true)
            setupMessage = snapshot.credentialReady ? "账号密码已加密保存在 macOS 钥匙串" : "账号已保存；钥匙串读取授权尚未完成"
        } catch { setupMessage = error.localizedDescription }
        publish()
    }

    /// The only credential-read path allowed to display a system dialog.
    func authorizeCredentials() async {
        guard !authorizingCredentials && !busy else { return }
        authorizingCredentials = true
        defer { authorizingCredentials = false; publish() }
        setupMessage = "正在准备当前版本的钥匙串访问修复"
        publish()
        do {
            let awaitingPassword = try await Task.detached(priority: .userInitiated) { try Vault.repairAccess() }.value
            if awaitingPassword {
                setupMessage = "请在已打开的终端中完成 macOS 钥匙串密码验证；完成后会自动复核"
                return
            }
        } catch {
            snapshot.credentialReady = false
            snapshot.credentialCheckState = "unavailable"
            setupMessage = error.localizedDescription
            return
        }
        // An interactive read can succeed without persisting background access.
        // Only a fresh noninteractive read can mark this build ready.
        await verifyKeychainAccess()
    }

    func verifyKeychainAccess() async {
        guard !busy else { return }
        await refreshCredentials()
        guard snapshot.credentialReady else {
            setupMessage = snapshot.credentialCheckState == "missing" ? "未保存账号，请先导入" : "后台仍无法读取钥匙串；请主动修复授权"
            publish()
            return
        }
        do {
            _ = try await Task.detached(priority: .utility) { try Vault.get("pending-login") != nil }.value
            _ = try await Task.detached(priority: .utility) { try Vault.get(OfflineOTP.account) != nil }.value
            setupMessage = "已验证当前版本能静默读取钥匙串；未发起登录"
        } catch { setupMessage = "账号已可读；恢复事务的授权未完成" }
        publish()
    }

    private func refreshCredentials(interactive: Bool = false) async {
        let state: String
        do {
            state = try await ReadDeadline.run(seconds: 5) {
                do { return try Vault.credentials(interactive: interactive) == nil ? "missing" : "ready" }
                catch { return "unavailable" }
            }
        } catch { state = "timeout" }
        snapshot.credentialReady = state == "ready"
        snapshot.credentialCheckState = state
        snapshot.credentialCheckedAt = Date()
        lastCredentialCheck = Date()
    }

    func requestAccessibility() {
        let prompt = kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String
        _ = AXIsProcessTrustedWithOptions([prompt: true] as CFDictionary)
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")!)
    }

    func importOfflineOTP() async {
        guard !busy && !authorizingCredentials && LocalSession.unlocked else { return }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.allowedFileTypes = ["plist"]
        panel.message = "选择 MotionPro OTP 已绑定令牌的 VSite.plist；只读核对后加密保存到 Guard 钥匙串"
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Containers")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        setupMessage = "与官方 OTP 核对两个周期（最多 75 秒）；不会提交 VPN 登录"
        publish()
        do {
            _ = try await Task.detached(priority: .utility) { try await OTPEnrollment.run(path: url.path) }.value
            setupMessage = "已验证并加密保存后台令牌；锁屏计算不再依赖 OTP 窗口"
        } catch { setupMessage = error.localizedDescription }
        busy = false; otpClock = OfflineOTP.Clock()
        await readiness()
    }

    private func readOTP() async throws -> OTPReading {
        snapshot.otpCheckedAt = Date()
        // Fall back to AX only if no enrolled token exists. Access denial,
        // corrupt material, or changed binding must not select another token.
        do {
            let token = try await ReadDeadline.run(seconds: 5) { try OfflineOTP.load() }
            snapshot.otpProvider = "offline_totp"
            snapshot.offlineOTPReady = true; snapshot.offlineOTPCheckState = "ready"
            offlineOTPPeriod = token.period
            do {
                let now = Date().timeIntervalSince1970
                try otpClock.observe(wall: now, uptime: ProcessInfo.processInfo.systemUptime)
                let reading = try token.reading(at: now)
                snapshot.otpReady = true; snapshot.otpCheckState = "computed"
                return reading
            } catch {
                snapshot.otpReady = false; snapshot.otpCheckState = "clock_waiting"
                snapshot.otpFreshnessState = "unverified"
                throw error
            }
        } catch OfflineOTP.Failure.missing {
            snapshot.offlineOTPReady = false; snapshot.offlineOTPCheckState = "missing"
            snapshot.otpProvider = "accessibility"
        } catch {
            snapshot.otpProvider = "offline_totp"
            let clockFailure: Bool
            switch error {
            case OfflineOTP.Failure.clockBoundary, OfflineOTP.Failure.clockSettling, OfflineOTP.Failure.clockChanged: clockFailure = true
            default: clockFailure = false
            }
            if !clockFailure {
                snapshot.offlineOTPReady = false
                if case OfflineOTP.Failure.binding = error { snapshot.offlineOTPCheckState = "binding_mismatch" }
                else if case OfflineOTP.Failure.invalid = error { snapshot.offlineOTPCheckState = "invalid" }
                else { snapshot.offlineOTPCheckState = "unavailable" }
                snapshot.otpReady = false; snapshot.otpCheckState = "unavailable"
            }
            throw error
        }
        let sample = try await ReadDeadline.run(seconds: 5) { OTPReader.sample() }
        snapshot.otpCheckedAt = Date()
        snapshot.otpCheckState = sample.reason
        snapshot.otpReady = sample.reading != nil
        guard let reading = sample.reading else {
            snapshot.otpFreshnessState = "unverified"
            throw GuardFailure.message(OTPReader.failureDetail(sample.reason))
        }
        return reading
    }

    func readiness() async {
        guard !authorizingCredentials && !busy else { return }
        snapshot.accessibilityReady = OTPReader.permission
        do {
            await refreshCredentials()
            guard snapshot.credentialReady else {
                throw GuardFailure.message(snapshot.credentialCheckState == "missing" ? "请先导入账号" : "钥匙串暂不可读；请主动点击授权钥匙串")
            }
            _ = try VendorCipher()
            let reading: OTPReading
            do { reading = try await readOTP() }
            catch OfflineOTP.Failure.clockSettling {
                try await Task.sleep(nanoseconds: 1_000_000_000)
                reading = try await readOTP()
            }
            snapshot.otpReady = true
            setupMessage = reading.freshEnough ? "登录条件已就绪；没有发起登录或中断连接" : "已能读取动态口令；登录时会等候新口令"
        } catch { setupMessage = error.localizedDescription }
        publish()
    }

    /// Read-only probe, using the installed process's actual AX permission.
    /// It never prepares client preferences, spends a retry, or submits a login.
    func probeBackgroundOTP() async {
        guard !busy && !checking else { return }
        busy = true
        defer { busy = false; publish(); Task { await check() } }
        snapshot.backgroundOTPProbeResult = "running"
        snapshot.lastProgressAt = Date(); snapshot.stateDeadline = Date().addingTimeInterval(80)
        snapshot.lockedOTPGenerationSamples = 0
        otpClock = OfflineOTP.Clock()
        setupMessage = "正在验证后台取码（最多 75 秒）；本次不会发起 VPN 登录"
        publish()
        do {
            let result = try await verifiedBackgroundOTP(probeOnly: true)
            snapshot.backgroundOTPVerifiedAt = Date()
            snapshot.backgroundOTPVerifiedWhileLocked = result.lockedThroughout
            snapshot.backgroundOTPProbeResult = result.lockedThroughout ? "verified_locked" : "verified_unlocked_or_mixed"
            setupMessage = result.lockedThroughout ? "已验证锁屏期间后台计算与钥匙串读取；未测试 VPN 登录" : "已验证后台口令轮换；本次未全程锁屏"
        } catch {
            snapshot.backgroundOTPProbeResult = "unavailable"
            setupMessage = error.localizedDescription
        }
    }

    func armLockedOTPProbe() {
        probeOnNextLock = true
        snapshot.backgroundOTPProbeResult = "waiting_for_lock"
        setupMessage = "下次锁屏时验证后台取码；不主动断开 VPN 或提交登录"
        publish()
    }

    func check() async {
        guard !checking && !busy else { return }; checking = true
        snapshot.lastCheckStartedAt = Date()
        defer {
            checking = false; snapshot.lastCheckCompletedAt = Date()
            snapshot.nextCheckAt = Date().addingTimeInterval(10); publish()
        }
        let now = Date(); policy.prune(now: now)
        snapshot.manualControlUntil = policy.manualControlUntil
        snapshot.confirmedRecoveryCount = policy.confirmedSuccessCount ?? 0
        let lockedDates = policy.lockedSuccessDates ?? []
        let days = Set(lockedDates.map { Calendar.current.startOfDay(for: $0) }).count
        snapshot.reliabilityState = days >= 3 ? "locked_recovery_observed_three_days" : (!lockedDates.isEmpty ? "locked_recovery_observed" : "locked_login_not_verified")
        if probeOnNextLock && LocalSession.isLocked {
            checking = false; probeOnNextLock = false
            await probeBackgroundOTP()
            return
        }
        await refreshReconnectStats(now: now)
        snapshot.recoveryEnabled = policy.enabled
        snapshot.accessibilityReady = OTPReader.permission
        snapshot.attemptsThisHour = policy.submissions.count
        snapshot.recoveryCount = policy.successCount; snapshot.lastRecovery = policy.lastSuccess
        let observation = await VendorHelper.status()
        let persistentlyDisconnected = disconnectionWindow.observe(observation, uptime: ProcessInfo.processInfo.systemUptime)
        guard let status = observation else {
            set("unknown", "状态不可读", "未尝试登录；请检查 MotionPro 后台服务"); return
        }
        if !pendingProfileReconciled && !status.isBusy && !authorizingCredentials
           && (policy.manualControlUntil ?? .distantPast) <= Date()
           && Date().timeIntervalSince(lastProfileReconcile) >= 60, let control = RecoveryLease() {
            lastProfileReconcile = Date()
            snapshot.profileMutationActive = true; snapshot.lastProgressAt = Date(); publish()
            do {
                // Reconcile only settings covered by Guard's saved transaction;
                // no client shutdown, tunnel operation, or retry is involved.
                try await Task.detached(priority: .utility) { try VendorProfile.cleanup() }.value
                pendingProfileReconciled = true; record("startup_profile_reconciled")
            } catch { record("startup_profile_reconcile_deferred") }
            snapshot.profileMutationActive = false
            withExtendedLifetime(control) { }
        }
        if status.hasTunnel {
            if snapshot.state != "connected", activeAttempt == nil {
                snapshot.lastConnectionInitiator = "external_or_unknown"
                record("external_connection_observed", status: status, initiator: "external_or_unknown")
            }
            episodeID = nil; snapshot.episodeID = nil
            if snapshot.connectedSince == nil { snapshot.connectedSince = now }
            if now.timeIntervalSince(lastLogCheck) > 60 { snapshot.authenticatedAt = await LogHints.boundedAuthentication(); lastLogCheck = now }
            let detail: String
            if !policy.enabled { detail = "校园网已连接 · 自动恢复已暂停" }
            else if snapshot.credentialCheckState == nil { detail = "连接正常 · 断线时检查凭据与 OTP" }
            else if !snapshot.credentialReady { detail = "连接正常 · 自动恢复待检查钥匙串" }
            else if !snapshot.otpAccessReady { detail = "连接正常 · 后台取码待就绪" }
            else if !snapshot.otpReady { detail = "连接正常 · 断线时自动唤起 OTP" }
            else { detail = "自动恢复已开启 · 正常连接时不操作" }
            set("connected", "已连接", detail); return
        }
        snapshot.connectedSince = nil
        if status.isBusy { set("connecting", "正在连接", "等待 MotionPro 完成当前操作"); return }
        guard status.mayLogin else { set("unknown", "等待客户端", "当前模式不是校园网隧道连接"); return }
        if persistentlyDisconnected && episodeID == nil {
            episodeID = UUID().uuidString; snapshot.episodeID = episodeID
            record("persistent_disconnect_confirmed", status: status)
        }
        guard policy.enabled else { set("paused", "自动恢复已暂停", "监控仍在运行；开启后可自动登录"); return }
        if let until = policy.manualControlUntil, until > now {
            set("waiting", "手动接管中", "十分钟接管期内持续监控；到期恢复自动处理", reason: "manual_control"); return
        }
        guard !authorizingCredentials else { set("permission", "等待钥匙串授权", "后台状态监控继续运行"); return }
        if now.timeIntervalSince(lastCredentialCheck) > 60 { await refreshCredentials() }
        guard snapshot.credentialReady else {
            if snapshot.credentialCheckState == "missing" {
                set("setup", "待导入账号", "从现有 MotionPro 配置导入钥匙串")
            } else { set("permission", "钥匙串暂不可读", "打开小组件管理页，点击授权钥匙串；后台不会弹窗") }
            return
        }
        guard LocalSession.networkAvailable else { set("offline", "等待网络", "网络恢复后再尝试登录", reason: "network_path_unavailable"); return }
        if now.timeIntervalSince(lastGatewayProbe) >= 15 {
            gatewayReachable = await GatewayProbe.reachable(); lastGatewayProbe = Date()
        }
        guard gatewayReachable else { set("offline", "网关暂不可达", "TCP 探测未成功；等待网关网络路径恢复", reason: "gateway_tcp_unreachable"); return }
        guard policy.allowed(now: now) else {
            snapshot.pausedUntil = policy.submissions.first?.addingTimeInterval(3600)
            set("held", "自动登录已暂停", "已限制失败重试，请检查账号与 OTP"); return
        }
        guard persistentlyDisconnected else {
            set("disconnected", "连接已断开", "确认状态后自动恢复，避免干扰短暂重连"); return
        }
        if let lastAttemptEnd, now.timeIntervalSince(lastAttemptEnd) < 90 {
            set("waiting", "等待再次尝试", "等候新的动态口令；最多两次登录尝试", reason: "retry_backoff"); return
        }
        // A manually opened client may contain unsaved settings. Wait until focus moves away.
        if LocalSession.unlocked && NSRunningApplication.runningApplications(withBundleIdentifier: "com.arraynetworks.motionpro").first?.isActive == true {
            set("waiting", "等待客户端操作", "切换到其他窗口后自动恢复", reason: "user_foreground_client"); return
        }
        // Background reading is allowed even when the desktop is locked.
        // Only an unlocked session may activate the app as a fallback.
        do { _ = try await readOTP() }
        catch {
            if snapshot.otpProvider == "accessibility", LocalSession.unlocked && now.timeIntervalSince(lastOTPActivation) >= 60 {
                OTPReader.openApp(); lastOTPActivation = now
            }
            set("otp", "动态口令暂不可读", error.localizedDescription)
            return
        }
        checking = false
        await recover()
    }

    private func set(_ state: String, _ title: String, _ detail: String, reason: String? = nil) {
        let code = reason ?? ["connected": "tunnel_connected", "connecting": "vendor_transition", "unknown": "vendor_state_unknown", "paused": "recovery_disabled", "permission": "permission_unavailable", "setup": "credential_missing", "offline": "network_unavailable", "held": "authentication_budget_or_hold", "disconnected": "confirming_disconnect", "waiting": "recovery_wait", "otp": "otp_unavailable", "recovering": "authentication_in_progress"][state] ?? "state_changed"
        let now = Date()
        snapshot.state = state; snapshot.title = title; snapshot.detail = detail
        if evidence.transition(state: state, reason: code, now: now) {
            snapshot.lastProgressAt = now
            record("state_observed", reason: code)
        }
        snapshot.waitReason = code; snapshot.stateEnteredAt = evidence.enteredAt
        let duration: TimeInterval? = ["starting": 20, "connecting": 120, "recovering": 120, "disconnected": 40, "waiting": 90, "otp": 120, "permission": 120, "offline": 120][state]
        snapshot.stateDeadline = duration.map { evidence.enteredAt.addingTimeInterval($0) }
        if code == "manual_control" { snapshot.stateDeadline = policy.manualControlUntil }
        publish()
    }

    private func record(_ name: String, reason: String? = nil, status: VendorStatus? = nil, initiator: String? = nil) {
        journal.append(GuardEvent(at: Date(), generation: journal.generation, name: name,
            state: snapshot.state, reason: reason, episodeID: episodeID, attemptID: activeAttempt?.id,
            vendorStatus: status?.rawValue, locked: LocalSession.isLocked, initiator: initiator))
    }
    private func refreshReconnectStats(now: Date) async {
        let before = reconnectHistory
        if now.timeIntervalSince(lastReconnectScan) >= 60 {
            if let scan = try? await ReadDeadline.run(seconds: 10, operation: { LogHints.successfulTunnelConnections() }) {
                reconnectHistory.merge(scan.dates, now: now)
                reconnectHistoryAvailable = reconnectHistoryAvailable || scan.readable
            }
            lastReconnectScan = now
        } else {
            reconnectHistory.merge([], now: now)
        }
        if reconnectHistoryAvailable {
            snapshot.recentReconnectionDates = reconnectHistory.reconnections
            if before != reconnectHistory || !FileManager.default.fileExists(atPath: reconnectHistoryURL.path) {
                if let data = try? JSONEncoder().encode(reconnectHistory) {
                    try? data.write(to: reconnectHistoryURL, options: .atomic)
                    try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: reconnectHistoryURL.path)
                }
            }
        }
    }
    func publish() {
        snapshot.updatedAt = Date()
        snapshot.recoveryBusy = busy || authorizingCredentials
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        try? data.write(to: GuardIdentity.snapshotURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: GuardIdentity.snapshotURL.path)
        let container = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Containers/\(GuardIdentity.widgetBundle)/Data/Library/Application Support/MotionProGuardOSS")
        if FileManager.default.fileExists(atPath: container.deletingLastPathComponent().deletingLastPathComponent().path) {
            try? FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
            try? data.write(to: container.appendingPathComponent("status.json"), options: .atomic)
        }
        let count = snapshot.reconnectionCount(at: snapshot.updatedAt)
        let changed = lastPublishedState != snapshot.state || lastPublishedReconnectCount != count
        if changed || Date().timeIntervalSince(lastWidgetReload) > 300 {
            WidgetCenter.shared.reloadTimelines(ofKind: GuardIdentity.widgetKind)
            lastWidgetReload = Date(); lastPublishedState = snapshot.state; lastPublishedReconnectCount = count
        }
    }

    private func launchClient() async throws -> Int32 {
        let configuration = NSWorkspace.OpenConfiguration(); configuration.activates = false
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Int32, Error>) in
            NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: "/Applications/MotionPro.app"), configuration: configuration) { app, error in
                if let error { continuation.resume(throwing: error) }
                else if let app { continuation.resume(returning: app.processIdentifier) }
                else { continuation.resume(throwing: GuardFailure.message("无法启动 MotionPro")) }
            }
        }
    }

    /// Bounded, allowlisted events only. Never store credentials, OTP, or raw
    /// vendor errors; preserve enough ordering to explain a client shutdown.
    private func recoveryEvent(_ name: String, status: VendorStatus? = nil) {
        struct Event: Codable { let at: Date; let name: String; let vendorStatus: Int?; var otpProvider: String?; var locked: Bool? }
        record(name, status: status, initiator: activeAttempt == nil ? nil : "guard")
        snapshot.lastProgressAt = Date()
        let url = GuardIdentity.support.appendingPathComponent("recovery-events.json")
        var events = (try? JSONDecoder().decode([Event].self, from: Data(contentsOf: url))) ?? []
        events.append(Event(at: Date(), name: name, vendorStatus: status?.rawValue,
                            otpProvider: snapshot.otpProvider, locked: LocalSession.isLocked))
        if let data = try? JSONEncoder().encode(Array(events.suffix(200))) {
            try? data.write(to: url, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        }
    }

    private func recover() async {
        guard !busy, let control = RecoveryLease() else { return }; busy = true
        activeAttempt = LoginAttribution(); snapshot.attemptID = activeAttempt?.id
        snapshot.profileMutationActive = false
        defer {
            withExtendedLifetime(control) { }
            busy = false; activeAttempt = nil; snapshot.attemptID = nil
            snapshot.profileMutationActive = false
            lastAttemptEnd = Date(); savePolicy(); publish(); Task { await check() }
        }
        var submitted = false
        var profileTouched = false
        var clientCloseRequested = false
        var lockedThroughout = LocalSession.isLocked
        var started = Date()
        let originalClient = NSRunningApplication.runningApplications(withBundleIdentifier: "com.arraynetworks.motionpro").first
        do {
            guard let credentials = try await Task.detached(priority: .utility, operation: { try Vault.credentials() }).value else { throw GuardFailure.invalidCredentials }
            try RecoveryFlow.requireDisconnected(await VendorHelper.status())
            guard policy.allowed(now: Date()), try await LogHints.boundedRejections(since: Date().addingTimeInterval(-3600)) < 2 else {
                throw GuardFailure.retryLimit
            }
            try await Task.detached(priority: .utility) {
                try VendorProfile.validateForLogin(credentials: credentials)
                // A transaction created by an earlier binary may have its own
                // ACL. Fail silently before any client shutdown if unreadable.
                _ = try Vault.get("pending-login")
            }.value
            recoveryEvent("otp_verification_started")
            try await RecoveryFlow.run(status: { await VendorHelper.status() }, verify: {
                let result = try await self.verifiedBackgroundOTP()
                lockedThroughout = lockedThroughout && result.lockedThroughout
                // Re-read site/account after the potentially long wait, before touching the client.
                try await Task.detached(priority: .utility) { try VendorProfile.validateForLogin(credentials: credentials) }.value
                self.recoveryEvent("otp_verified")
                return result
            }, validate: { verified in
                lockedThroughout = lockedThroughout && LocalSession.isLocked
                guard self.policy.allowed(now: Date()) else { throw GuardFailure.retryLimit }
                guard LocalSession.networkAvailable else { throw GuardFailure.message("网络暂不可用；停止本次恢复") }
                guard Double(verified.reading.secondsRemaining) - (ProcessInfo.processInfo.systemUptime - verified.sampledAt) >= 20 else {
                    throw GuardFailure.message("口令已接近过期；未提交登录，等待下一轮")
                }
                let client = NSRunningApplication.runningApplications(withBundleIdentifier: "com.arraynetworks.motionpro").first
                if let client, LocalSession.unlocked && client.isActive {
                    throw GuardFailure.message("客户端正在由用户操作；停止本次恢复")
                }
                guard client?.processIdentifier == (clientCloseRequested ? nil : originalClient?.processIdentifier) else {
                    throw GuardFailure.message("客户端进程已改变；停止本次恢复")
                }
            }, closeClient: {
                // All readiness checks are complete. Only now close the offline
                // client, immediately followed by preparation and relaunch.
                if let client = originalClient {
                    self.recoveryEvent("client_close_requested_after_otp_verified")
                    guard client.terminate() else { throw GuardFailure.message("客户端未退出，请处理其弹窗") }
                    clientCloseRequested = true
                    for _ in 0..<40 {
                        if client.isTerminated { break }
                        try await Task.sleep(nanoseconds: 100_000_000)
                    }
                    guard client.isTerminated else { throw GuardFailure.message("等待客户端退出；没有强制结束进程") }
                    self.recoveryEvent("client_closed")
                }
            }, prepare: { verified in
                snapshot.profileMutationActive = true; publish()
                profileTouched = true
                try await Task.detached(priority: .utility) {
                    try VendorProfile.cleanup(clientStopped: true)
                    try VendorProfile.prepare(credentials: credentials, otp: verified.reading.code)
                }.value
                self.recoveryEvent("profile_prepared")
            }, submit: {
                lockedThroughout = lockedThroughout && LocalSession.isLocked
                // Spend the shared budget only immediately before a login launch.
                try self.policy.submit(now: Date()); self.savePolicy(); submitted = true
                self.snapshot.attemptsThisHour = self.policy.submissions.count
                started = Date(); self.snapshot.lastSubmissionAt = started
                self.activeAttempt?.submitted(at: started)
                self.recoveryEvent("login_submission_intent")
                let launchedPID = try await self.launchClient()
                self.activeAttempt?.launched(pid: launchedPID)
                self.recoveryEvent("login_launch_confirmed")
            })
            set("recovering", "正在登录", "已提交新口令，等待安全隧道建立", reason: "waiting_tunnel")
            let tunnelDeadline = ProcessInfo.processInfo.systemUptime + 120
            while ProcessInfo.processInfo.systemUptime < tunnelDeadline {
                try await Task.sleep(nanoseconds: 2_000_000_000)
                lockedThroughout = lockedThroughout && LocalSession.isLocked
                let currentClient = NSRunningApplication.runningApplications(withBundleIdentifier: "com.arraynetworks.motionpro").first
                self.activeAttempt?.observe(pid: currentClient?.processIdentifier,
                    userActive: LocalSession.unlocked && currentClient?.isActive == true,
                    manualLease: (policy.manualControlUntil ?? .distantPast) > Date())
                if let status = await VendorHelper.status(), status.hasTunnel {
                    let authentication = await LogHints.boundedAuthentication()
                    let attribution = activeAttempt?.classify(authenticationAt: authentication, connectedPID: currentClient?.processIdentifier) ?? "unknown_or_external"
                    snapshot.lastConnectionInitiator = attribution
                    let cleaned = await Task.detached(priority: .utility) { (try? VendorProfile.cleanup()) != nil }.value
                    if attribution == "guard_submission_confirmed" {
                        policy.confirmed(now: Date(), locked: lockedThroughout)
                        record("guard_connection_confirmed", status: status, initiator: attribution)
                    } else {
                        record("connection_attribution_unconfirmed", status: status, initiator: attribution)
                    }
                    savePolicy()
                    recoveryEvent("tunnel_connected", status: status)
                    lastReconnectScan = .distantPast
                    await refreshReconnectStats(now: Date())
                    snapshot.authenticatedAt = authentication
                    snapshot.lastRecovery = policy.lastSuccess; snapshot.recoveryCount = policy.successCount
                    snapshot.attemptsThisHour = policy.submissions.count
                    snapshot.confirmedRecoveryCount = policy.confirmedSuccessCount ?? 0
                    set("connected", "已连接", attribution == "guard_submission_confirmed" ? "Guard 提交后连接已确认；锁屏可靠性需累计自然到期验收" : "连接已建立；本次发起归属无法确认")
                    if !cleaned { record("profile_cleanup_deferred") }
                    return
                }
                if try await LogHints.boundedRejections(since: started) > 0 { throw GuardFailure.message("认证被拒绝，请检查账号密码或 OTP 站点") }
            }
            throw GuardFailure.message("连接未在两分钟内完成，请检查客户端提示")
        } catch {
            if profileTouched || clientCloseRequested {
                try? await Task.detached(priority: .utility) { try VendorProfile.cleanup() }.value
            }
            // If preparation fails after a confirmed shutdown, restore the UI
            // with auto-login disabled. This cannot spend a retry or send old OTP.
            if clientCloseRequested, originalClient?.isTerminated == true,
               NSRunningApplication.runningApplications(withBundleIdentifier: "com.arraynetworks.motionpro").isEmpty {
                do {
                    try await Task.detached(priority: .utility) { try VendorProfile.prepareIdleLaunch() }.value
                    _ = try await launchClient()
                    recoveryEvent("client_reopened_without_login")
                } catch { recoveryEvent("idle_reopen_failed") }
            }
            if case RecoveryInterrupted.tunnelState(let status) = error {
                _ = disconnectionWindow.observe(status, uptime: ProcessInfo.processInfo.systemUptime)
                recoveryEvent("recovery_cancelled_state_changed", status: status)
                set("waiting", "恢复已撤销", "连接状态已变化；重新检查隧道")
                return
            }
            if submitted { policy.failed() }
            if case GuardFailure.retryLimit = error { policy.manualHold = true }
            recoveryEvent(submitted ? "failed_after_submission" : "stopped_before_submission")
            setupMessage = error.localizedDescription
            set("attention", "需要检查", error.localizedDescription)
        }
    }

    private func verifiedBackgroundOTP(probeOnly: Bool = false) async throws -> (reading: OTPReading, sampledAt: TimeInterval, lockedThroughout: Bool) {
        var proof = OTPFreshnessProof()
        var firstOfflinePeriod: UInt64?
        var offlineSampleCount = 0
        snapshot.otpFreshnessState = "waiting_for_rollover"
        var lockedThroughout = LocalSession.isLocked
        let deadline = ProcessInfo.processInfo.systemUptime + 75
        if !probeOnly { set("recovering", "校验后台动态口令", "保持客户端运行；确认新口令后才恢复连接", reason: "verifying_otp") }
        while ProcessInfo.processInfo.systemUptime < deadline {
            if !probeOnly {
                guard policy.allowed(now: Date()) else { throw GuardFailure.retryLimit }
                try RecoveryFlow.requireDisconnected(await VendorHelper.status())
                if LocalSession.unlocked && NSRunningApplication.runningApplications(withBundleIdentifier: "com.arraynetworks.motionpro").first?.isActive == true {
                    throw GuardFailure.message("客户端正在由用户操作；停止本次恢复")
                }
            }
            lockedThroughout = lockedThroughout && LocalSession.isLocked
            do {
                let reading = try await readOTP()
                let sampledAt = ProcessInfo.processInfo.systemUptime
                if snapshot.otpProvider == "offline_totp" {
                    offlineSampleCount += 1
                    if LocalSession.isLocked { snapshot.lockedOTPGenerationSamples = (snapshot.lockedOTPGenerationSamples ?? 0) + 1 }
                    guard let period = offlineOTPPeriod else { throw OfflineOTP.Failure.invalid }
                    let step = UInt64(floor(Date().timeIntervalSince1970 / Double(period)))
                    if firstOfflinePeriod == nil { firstOfflinePeriod = step }
                    // Enrollment proved compatibility. A normal recovery needs
                    // a fresh calculation and stable clock, not a UI rollover.
                    // The explicit probe also witnesses a period advancing.
                    if reading.freshEnough && (!probeOnly || (firstOfflinePeriod != step && offlineSampleCount >= 3)) {
                        snapshot.otpFreshnessState = "verified"
                        return (reading, sampledAt, lockedThroughout)
                    }
                    snapshot.otpFreshnessState = "waiting_for_valid_window"
                    publish()
                    try await Task.sleep(nanoseconds: 1_000_000_000)
                    continue
                }
                if proof.observe(reading, uptime: sampledAt) {
                    snapshot.otpFreshnessState = "verified"
                    return (reading, sampledAt, lockedThroughout)
                }
                snapshot.otpFreshnessState = "waiting_for_rollover"
            } catch {
                proof = OTPFreshnessProof()
                if case OfflineOTP.Failure.clockChanged = error { firstOfflinePeriod = nil; offlineSampleCount = 0 }
                if snapshot.otpProvider == "offline_totp" && snapshot.offlineOTPReady != true { throw error }
            }
            // Keep the status snapshot alive while waiting; publish no OTP data.
            publish()
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        snapshot.otpFreshnessState = "unverified"
        throw GuardFailure.message(snapshot.otpReady
            ? "OTP 可读取，但未通过实时轮换校验；未提交登录"
            : "OTP 读取中断，未完成轮换校验；未提交登录")
    }
}
