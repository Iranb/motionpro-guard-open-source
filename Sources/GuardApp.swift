// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import AppKit
import SwiftUI

extension GuardSnapshot {
    var tint: Color {
        switch state {
        case "connected": return Color(red: 0.08, green: 0.57, blue: 0.37)
        case "connecting", "recovering", "starting": return .blue
        case "attention", "held": return .orange
        default: return .secondary
        }
    }
    var symbol: String { state == "connected" ? "checkmark.shield.fill" : state == "recovering" ? "arrow.clockwise.circle.fill" : "shield.lefthalf.filled" }
    var recoveryLabel: String {
        if !recoveryEnabled { return "恢复已暂停" }
        if credentialCheckState == nil { return "恢复已开启 · 凭据待检查" }
        if !credentialReady { return "恢复待就绪" }
        if !otpAccessReady { return "后台取码待就绪" }
        return "恢复已开启 · 锁屏登录待验收"
    }
}

struct DesktopCard: View {
    @ObservedObject var engine: GuardEngine
    let manage: () -> Void
    var body: some View {
        let status = engine.snapshot
        VStack(alignment: .leading, spacing: 13) {
            HStack {
                Image(systemName: "shield.lefthalf.filled").foregroundStyle(status.tint)
                Text("MotionPro").font(.system(size: 14, weight: .semibold))
                Spacer()
                Button(action: manage) { Image(systemName: "ellipsis.circle").font(.system(size: 16)) }
                    .buttonStyle(.plain).help("管理自动恢复")
            }
            HStack(alignment: .center, spacing: 10) {
                Image(systemName: status.symbol).font(.system(size: 33, weight: .medium)).foregroundStyle(status.tint)
                VStack(alignment: .leading, spacing: 3) {
                    Text(status.title).font(.system(size: 25, weight: .semibold, design: .rounded))
                    Text("VPN 网络").font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            HStack(alignment: .center, spacing: 12) {
                Text(status.detail).font(.system(size: 12)).foregroundStyle(.secondary).lineLimit(2)
                    .frame(maxWidth: .infinity, alignment: .leading)
                VStack(alignment: .trailing, spacing: 2) {
                    Text(status.reconnectionCount(at: status.updatedAt).map { "\($0) 次" } ?? "—")
                        .font(.system(size: 18, weight: .semibold, design: .rounded)).monospacedDigit()
                    Text("72h 内重连").font(.system(size: 10)).foregroundStyle(.secondary)
                }
                .help("最近 72 小时内已记录的成功重连，包含自动与手动；失败尝试不计入")
            }.frame(height: 32)
            Divider()
            HStack(spacing: 5) {
                Circle().fill(status.recoveryEnabled && status.credentialReady && status.otpAccessReady ? status.tint : Color.secondary).frame(width: 5, height: 5)
                Text(status.recoveryLabel).font(.system(size: 11, weight: .medium))
                Spacer()
                Text(status.updatedAt, style: .time).font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary)
            }
        }
        .padding(20).frame(width: 326, height: 225)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 23))
        .overlay(RoundedRectangle(cornerRadius: 23).strokeBorder(Color.primary.opacity(0.08), lineWidth: 1))
        .padding(4)
    }
}

struct ReadinessRow: View {
    let ready: Bool
    let title: String
    let detail: String
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: ready ? "checkmark.circle.fill" : "circle.dashed")
                .foregroundStyle(ready ? Color.green : Color.secondary).font(.system(size: 17))
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 13, weight: .medium))
                Text(detail).font(.system(size: 11)).foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}

struct ControlView: View {
    @ObservedObject var engine: GuardEngine
    let quit: () -> Void
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("MotionPro Guard").font(.system(size: 25, weight: .semibold, design: .rounded))
                    Text("连接状态与动态口令自动恢复").foregroundStyle(.secondary)
                }
                Spacer()
                Label(engine.snapshot.title, systemImage: engine.snapshot.symbol)
                    .font(.system(size: 12, weight: .medium)).foregroundStyle(engine.snapshot.tint)
            }
            Text(engine.snapshot.detail).font(.system(size: 12)).foregroundStyle(.secondary)
            Toggle("断线后自动登录", isOn: Binding(get: { engine.policy.enabled }, set: { engine.setEnabled($0) }))
                .toggleStyle(.switch).disabled(engine.busy)
            Divider()
            VStack(alignment: .leading, spacing: 15) {
                ReadinessRow(ready: engine.snapshot.credentialReady, title: "账号密码 · macOS 钥匙串", detail: engine.snapshot.credentialCheckState == nil ? "本次启动尚未检查；正常连接时不读取钥匙串" : "权限不足时静默等待；仅主动授权会弹出系统窗口")
                ReadinessRow(ready: engine.snapshot.offlineOTPReady == true, title: "OTP · 后台计算", detail: engine.snapshot.offlineOTPReady == true ? "已核对官方口令并验证账号绑定；每次计算检查钥匙串和时钟" : "首次导入并核对令牌后，锁屏运行不再依赖官方窗口")
                ReadinessRow(ready: engine.snapshot.accessibilityReady, title: "辅助功能 · 令牌导入与备用读取", detail: "首次核对官方口令时使用；已有后台令牌的计算无需此权限")
            }
            HStack {
                Button("导入已保存账号") { Task { await engine.importCredentials() } }.disabled(engine.busy || engine.authorizingCredentials)
                Button("授权钥匙串") { Task { await engine.authorizeCredentials() } }.disabled(engine.busy || engine.authorizingCredentials)
                Button("导入后台令牌") { Task { await engine.importOfflineOTP() } }.disabled(engine.busy || engine.authorizingCredentials)
                Button("授权读取 OTP") { engine.requestAccessibility() }
                Button("打开 OTP") { OTPReader.openApp() }
            }
            Button("检查登录条件") { Task { await engine.readiness() } }.buttonStyle(.borderedProminent).disabled(engine.busy || engine.authorizingCredentials)
            Button("验证后台取码（不登录）") { Task { await engine.probeBackgroundOTP() } }.disabled(engine.busy)
            Button(engine.probeOnNextLock ? "已等待下次锁屏验证" : "验证下次锁屏取码（不登录）") { engine.armLockedOTPProbe() }.disabled(engine.busy || engine.probeOnNextLock)
            if !engine.setupMessage.isEmpty {
                Text(engine.setupMessage).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Divider()
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("72 小时内成功重连 \(engine.snapshot.reconnectionCount(at: engine.snapshot.updatedAt).map(String.init) ?? "—") 次")
                        .font(.system(size: 13, weight: .medium))
                        .help("包含自动与手动成功重连；从客户端日志补齐历史记录")
                    Text("本版归属确认 \(engine.policy.confirmedSuccessCount ?? 0) 次 · 历史计数 \(engine.policy.successCount) 次 · 本小时提交 \(engine.policy.submissions.count) / 2 次")
                        .font(.system(size: 11)).foregroundStyle(.secondary)
                }
                Spacer()
                Button("立即检查") { Task { await engine.check() } }.disabled(engine.busy)
                Button("手动接管10分钟") { engine.takeManualControl() }.disabled(engine.busy)
                if (engine.policy.manualControlUntil ?? .distantPast) > Date() {
                    Button("结束接管") { engine.resumeControl() }
                }
                if engine.policy.manualHold { Button("已检查，恢复尝试") { engine.releaseHold() }.disabled(engine.busy) }
            }
            Text("每 10 秒检查状态。优先使用钥匙串令牌在后台计算 OTP，锁屏期间可运行。电脑休眠时需等待唤醒。已连接时不重连，每小时最多提交两次；权限或时钟异常时停止提交。")
                .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("暂停自动恢复", action: quit)
            }
            Text("原生小组件：右键桌面 → 编辑小组件 → 搜索 MotionPro Guard。")
                .font(.system(size: 10)).foregroundStyle(.tertiary)
        }
        .padding(26).frame(width: 570)
    }
}

@MainActor
final class GuardDelegate: NSObject, NSApplicationDelegate {
    let engine = GuardEngine()
    var controls: NSWindow!

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        NSAppleEventManager.shared().setEventHandler(self, andSelector: #selector(handleURL(_:reply:)), forEventClass: AEEventClass(kInternetEventClass), andEventID: AEEventID(kAEGetURL))
        let screen = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        controls = NSWindow(contentRect: NSRect(x: screen.midX - 285, y: screen.midY - 315, width: 570, height: 630), styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
        controls.title = "MotionPro Guard"; controls.isReleasedWhenClosed = false
        controls.contentView = NSHostingView(rootView: ControlView(engine: engine, quit: { [weak self] in self?.quitApp() }))
        // Never trigger an interactive credential import during unattended launch.
        // The explicit import button remains available when authorization is needed.
        engine.start()
    }
    @objc func openControls() { controls.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
    @objc func quitApp() { engine.setEnabled(false) }
    @objc func handleURL(_ event: NSAppleEventDescriptor, reply: NSAppleEventDescriptor) {
        let url = event.paramDescriptor(forKeyword: keyDirectObject)?.stringValue.flatMap(URL.init(string:))
        if url?.host == "check-keychain" {
            // Explicit, read-only maintenance request. No prompt, OTP access,
            // client operation or response containing credentials.
            Task { await engine.verifyKeychainAccess(); await engine.readiness() }
            return
        }
        if url?.host == "check-offline-otp" {
            Task { await engine.readiness() }
            return
        }
        if url?.host == "probe-offline-otp" {
            Task { await engine.probeBackgroundOTP() }
            return
        }
        if url?.host == "probe-next-lock" {
            engine.armLockedOTPProbe()
            return
        }
        if url?.host == "manual-control" { engine.takeManualControl(); return }
        if url?.host == "resume-control" { engine.resumeControl(); return }
        openControls()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

@main
struct MotionProGuardMain {
    @MainActor static func main() {
        if CommandLine.arguments.dropFirst().first == "--prepare-keychain-repair" {
            guard CommandLine.arguments.count == 3 else { exit(64) }
            do {
                let root = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
                let prepared = try Vault.repairAccess(scriptRoot: root, openTerminal: false)
                print("{\"repairScriptPrepared\":\(prepared),\"keychainPermissionsChanged\":false}")
                exit(0)
            } catch { emitFailure(error, field: "repairScriptPrepared"); exit(2) }
        }
        if let action = CommandLine.arguments.dropFirst().first, ["--watchdog", "--watchdog-inspect"].contains(action) {
            Task { await GuardWatchdog.run(allowRestart: action == "--watchdog"); exit(0) }
            RunLoop.main.run(); return
        }
        if CommandLine.arguments.dropFirst().first == "--import-offline-otp" {
            let path: String
            if CommandLine.arguments.count == 3 { path = CommandLine.arguments[2] }
            else if CommandLine.arguments.count == 2 {
                guard LocalSession.unlocked else { exit(2) }
                NSApplication.shared.setActivationPolicy(.accessory)
                let panel = NSOpenPanel()
                panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
                panel.allowedFileTypes = ["plist"]
                panel.message = "一次性导入：选择已绑定的 VSite.plist，核对官方 OTP 后将令牌加密保存在 Guard 钥匙串。此后可锁屏取码；不提交 VPN 登录。"
                panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Containers/net.arraynetworks.MotionProOTP/Data")
                guard panel.runModal() == .OK, let selected = panel.url else { exit(3) }
                path = selected.path
            } else { exit(64) }
            Task.detached {
                do {
                    let periods = try await OTPEnrollment.run(path: path)
                    print("{\"offlineTokenImported\":true,\"officialMatchPeriods\":\(periods),\"noLogin\":true}")
                    exit(0)
                } catch {
                    emitFailure(error, field: "offlineTokenImported"); exit(2)
                }
            }
            RunLoop.main.run(); return
        }
        if CommandLine.arguments.dropFirst().first == "--check-offline-otp" {
            Task.detached {
                do {
                    var clock = OfflineOTP.Clock()
                    let token = try OfflineOTP.load()
                    do { try clock.observe(wall: Date().timeIntervalSince1970, uptime: ProcessInfo.processInfo.systemUptime) }
                    catch OfflineOTP.Failure.clockSettling { }
                    try await Task.sleep(nanoseconds: 1_000_000_000)
                    // Re-read the Keychain; a cached token cannot prove locked access.
                    let current = try OfflineOTP.load()
                    try clock.observe(wall: Date().timeIntervalSince1970, uptime: ProcessInfo.processInfo.systemUptime)
                    _ = try current.reading(at: Date().timeIntervalSince1970)
                    print("{\"offlineOTPReady\":true,\"keychainSilentRead\":true,\"periodSeconds\":\(token.period),\"locked\":\(LocalSession.isLocked),\"noLogin\":true}")
                    exit(0)
                } catch { emitFailure(error, field: "offlineOTPReady"); exit(2) }
            }
            RunLoop.main.run(); return
        }
        if CommandLine.arguments.dropFirst().first == "--diagnose-otp" {
            Task.detached { await OTPReader.diagnose(); exit(0) }
            RunLoop.main.run()
            return
        }
        if let action = CommandLine.arguments.dropFirst().first,
           ["--check-keychain", "--repair-keychain-access"].contains(action) {
            do {
                if action == "--repair-keychain-access", try Vault.repairAccess() {
                    print("{\"awaitingKeychainPasswordInTerminal\":true}")
                    exit(3)
                }
                let ready = try Vault.credentials() != nil
                let pending = try Vault.get("pending-login") != nil
                let token = try Vault.get(OfflineOTP.account) != nil
                print("{\"credentialReady\":\(ready),\"pendingTransactionPresent\":\(pending),\"offlineTokenPresent\":\(token),\"silentCheck\":true}")
                exit(ready ? 0 : 2)
            } catch {
                let detail = (error as? GuardFailure)?.errorDescription ?? "已保存凭据未能通过检查"
                let data = try! JSONSerialization.data(withJSONObject: ["credentialReady": false, "error": detail], options: [.sortedKeys])
                print(String(decoding: data, as: UTF8.self))
                exit(2)
            }
        }
        let app = NSApplication.shared
        let delegate = GuardDelegate(); app.delegate = delegate
        withExtendedLifetime(delegate) { app.run() }
    }
    private static func emitFailure(_ error: Error, field: String) {
        let detail = (error as? GuardFailure)?.errorDescription ?? (error as? OfflineOTP.Failure)?.errorDescription ?? "后台令牌检查未完成"
        let data = try! JSONSerialization.data(withJSONObject: [field: false, "error": detail, "noLogin": true], options: [.sortedKeys])
        print(String(decoding: data, as: UTF8.self))
    }
}
