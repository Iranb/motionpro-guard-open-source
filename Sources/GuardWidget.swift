// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import SwiftUI
import WidgetKit

struct GuardEntry: TimelineEntry { let date: Date; let snapshot: GuardSnapshot }
struct GuardProvider: TimelineProvider {
    func placeholder(in context: Context) -> GuardEntry { .init(date: Date(), snapshot: .placeholder) }
    func read() -> GuardSnapshot {
        let root = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let url = root.appendingPathComponent("MotionProGuardOSS/status.json")
        guard let data = try? Data(contentsOf: url), let snapshot = try? JSONDecoder().decode(GuardSnapshot.self, from: data) else {
            var missing = GuardSnapshot(); missing.title = "打开监控应用"; missing.detail = "启动 MotionPro Guard OSS 后显示状态"; return missing
        }
        return snapshot
    }
    func getSnapshot(in context: Context, completion: @escaping (GuardEntry) -> Void) { completion(.init(date: Date(), snapshot: read())) }
    func getTimeline(in context: Context, completion: @escaping (Timeline<GuardEntry>) -> Void) {
        let now = Date(), snapshot = read()
        let expirations = Set((snapshot.recentReconnectionDates ?? []).map { $0.addingTimeInterval(ReconnectHistory.window) }.filter { $0 > now }).sorted()
        let entries = ([now] + expirations).map { GuardEntry(date: $0, snapshot: snapshot) }
        let refresh = snapshot.automaticCheckMode == LoginExpirySchedule.mode
            ? max(snapshot.nextCheckAt ?? now.addingTimeInterval(86_400), now.addingTimeInterval(60))
            : now.addingTimeInterval(60)
        completion(Timeline(entries: entries, policy: .after(refresh)))
    }
}

struct GuardWidgetView: View {
    let entry: GuardEntry
    @Environment(\.widgetFamily) var family
    var s: GuardSnapshot { entry.snapshot }
    var color: Color { s.state == "connected" ? .green : (s.state == "recovering" ? .blue : .secondary) }
    var scheduled: Bool { s.automaticCheckMode == LoginExpirySchedule.mode && (s.nextCheckAt ?? .distantPast) > entry.date }
    var stale: Bool { !scheduled && entry.date.timeIntervalSince(s.updatedAt) > 180 }
    var title: String { scheduled ? "定时恢复" : (stale ? "等待更新" : s.title) }
    var reconnectCount: String { s.reconnectionCount(at: entry.date).map(String.init) ?? "—" }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Label("MotionPro", systemImage: "shield.lefthalf.filled").font(.system(size: 12, weight: .semibold))
                Spacer()
                Circle().fill(stale ? Color.secondary : color).frame(width: 6, height: 6)
            }
            if family == .systemSmall {
                Text(title).font(.system(size: 23, weight: .semibold, design: .rounded)).lineLimit(1).minimumScaleFactor(0.75)
                Text("校园 VPN").font(.system(size: 11)).foregroundStyle(.secondary)
                HStack {
                    Text("72h 内重连").font(.system(size: 10)).foregroundStyle(.secondary)
                    Spacer()
                    Text("\(reconnectCount) 次").font(.system(size: 17, weight: .semibold, design: .rounded)).monospacedDigit()
                }
            } else {
                HStack(alignment: .center, spacing: 16) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(title).font(.system(size: 29, weight: .semibold, design: .rounded)).lineLimit(1).minimumScaleFactor(0.75)
                        Text(s.detail).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(2)
                    }
                    Spacer(minLength: 0)
                    VStack(alignment: .trailing, spacing: 3) {
                        Text("\(reconnectCount) 次").font(.system(size: 29, weight: .semibold, design: .rounded)).monospacedDigit()
                        Text("72h 内成功重连").font(.system(size: 10)).foregroundStyle(.secondary)
                    }
                }
            }
            Spacer(minLength: 0)
            HStack {
                Text(!s.recoveryEnabled ? "恢复已暂停" : (s.credentialCheckState == nil ? "恢复已开启 · 凭据待检查" : (!s.credentialReady ? "恢复待就绪" : (!s.otpAccessReady ? "后台取码待就绪" : "恢复开启 · 锁屏待验收"))))
                    .font(.system(size: 10, weight: .medium)).lineLimit(1)
                if family != .systemSmall { Spacer(); Text(s.updatedAt, style: .time).font(.system(size: 10, design: .monospaced)).foregroundStyle(.tertiary) }
            }
        }
        .containerBackground(for: .widget) { Color(.windowBackgroundColor) }
        .widgetURL(URL(string: "motionpro-guard-oss://open"))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("MotionPro，\(stale ? "等待更新" : s.title)，最近 72 小时成功重连 \(reconnectCount) 次")
    }
}

@main
struct MotionProGuardWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: GuardIdentity.widgetKind, provider: GuardProvider()) { GuardWidgetView(entry: $0) }
            .configurationDisplayName("MotionPro Guard OSS")
            .description("查看校园 VPN 状态、72 小时成功重连次数与自动恢复是否就绪。")
            .supportedFamilies([.systemSmall, .systemMedium])
    }
}
