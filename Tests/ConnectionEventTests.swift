// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation

@main struct ConnectionEventTests {
    static func main() throws {
        var count = 0
        func check(_ condition: Bool, _ message: String) { precondition(condition, message); count += 1 }
        let window = ConnectionObservationWindow(startedAt: 100)
        var offline = DisconnectionWindow()
        let transition: [(TimeInterval, VendorStatus?)] = [(100, nil), (110, nil), (120, .disconnected),
                                                         (130, .disconnected), (140, .disconnected), (150, .disconnected)]
        for (index, sample) in transition.enumerated() {
            let confirmed = offline.observe(sample.1, uptime: sample.0)
            let state = sample.1 == nil ? "unknown" : "disconnected"
            let reason = sample.1 == nil ? "vendor_state_unknown" : "confirming_disconnect"
            check(window.shouldContinue(state: state, reason: reason, uptime: sample.0),
                  "an unreadable transition keeps the existing observation window open")
            check(confirmed == (index == transition.count - 1),
                  "only thirty seconds of known disconnection can authorize recovery")
        }
        check(!window.shouldContinue(state: "unknown", reason: "vendor_state_unknown", uptime: 280),
              "unreadable status cannot extend the bounded window")
        check(!window.shouldContinue(state: "connected", reason: "tunnel_connected", uptime: 120),
              "a healthy tunnel ends observation")
        check(!window.shouldContinue(state: "unknown", reason: "vendor_mode_not_tunnel", uptime: 120),
              "a known desktop-only mode does not loop or authenticate")
        check(!window.shouldContinue(state: "setup", reason: "credential_missing", uptime: 120),
              "missing credentials stop observation")
        var parser = ConnectionEventLines()
        check(!parser.consume(Data("ordinary keepalive\n".utf8)), "routine log writes do not trigger status checks")
        check(!parser.consume(Data("vpn disconn".utf8)), "partial lines wait for completion")
        check(parser.consume(Data("ected\n".utf8)), "a split disconnect line generates an event")
        check(!parser.consume(Data()), "consumed history does not replay")
        check(parser.consume(Data("session expired\nlogout\n".utf8)), "a burst produces one request")
        check(parser.consume(Data("login successfully, method name: fictional\n".utf8)), "successful manual logins can update the schedule")
        check(!parser.consume(Data(repeating: 65, count: 70000)), "oversized incomplete lines are discarded")
        check(parser.consume(Data("DISCONNECTED\n".utf8)), "parsing recovers after an oversized line")

        let root = FileManager.default.temporaryDirectory.appendingPathComponent("guard-event-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let path = root.appendingPathComponent("MotionPro_test.log")
        try Data("historic disconnect\n".utf8).write(to: path)
        var signals = 0
        let monitor = VendorLogEvents(root: root) { signals += 1 }
        check(monitor.start(), "native file notifications start on a temporary fixture")
        defer { monitor.stop() }
        func pump(_ seconds: TimeInterval) {
            let end = Date().addingTimeInterval(seconds)
            while Date() < end { RunLoop.main.run(until: min(end, Date().addingTimeInterval(0.02))) }
        }
        func append(_ text: String) throws {
            let file = try FileHandle(forWritingTo: path)
            try file.seekToEnd(); try file.write(contentsOf: Data(text.utf8)); try file.synchronize(); try file.close()
        }
        func waitForSignal(after old: Int) {
            let deadline = Date().addingTimeInterval(3)
            while signals <= old && Date() < deadline { pump(0.02) }
            check(signals > old, "native filesystem event reaches the recovery callback")
        }
        pump(0.1)
        check(signals == 0, "starting the monitor does not replay old disconnections")
        try append("ordinary keepalive\n"); pump(0.15)
        check(signals == 0, "ordinary appends do not request recovery")
        try append("vpn disconnected\n"); waitForSignal(after: 0)
        let beforeRotate = signals
        try FileManager.default.moveItem(at: path, to: root.appendingPathComponent("previous.old"))
        try Data("session expired\n".utf8).write(to: path)
        waitForSignal(after: beforeRotate)
        pump(0.1)
        let afterRotate = signals
        try append("logout\n"); waitForSignal(after: afterRotate)
        pump(0.1)
        let beforeTruncate = signals
        let file = try FileHandle(forWritingTo: path)
        try file.truncate(atOffset: 0); try file.write(contentsOf: Data("logout\n".utf8)); try file.synchronize(); try file.close()
        waitForSignal(after: beforeTruncate)
        monitor.stop(); pump(0.1)
        let stopped = signals
        try append("logout\n"); pump(0.15)
        check(signals == stopped, "stopped observers do not schedule recovery")
        print("Connection event checks passed: \(count)")
    }
}
