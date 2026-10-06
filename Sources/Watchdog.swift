// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import Darwin

enum GuardWatchdog {
    struct Health: Codable {
        var startedAt: Date
        var completedAt: Date
        var decision: String
        var processRunning: Bool
        var vendorStatus: Int?
        var restartDates: [Date]
        var lastJournalAt: Date?
        var restartOutcome: String?
    }
    private static func snapshot() -> GuardSnapshot? {
        guard let bytes = try? Data(contentsOf: GuardIdentity.snapshotURL) else { return nil }
        return try? JSONDecoder().decode(GuardSnapshot.self, from: bytes)
    }
    private static func processRunning() -> Bool {
        // launchctl list emits PID, exit status and job label, not environment.
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["list"]; process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return false }
        let bytes = pipe.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        return String(decoding: bytes, as: UTF8.self).split(separator: "\n").contains { line in
            let cells = line.split(whereSeparator: { $0.isWhitespace })
            return cells.count == 3 && cells[2] == Substring(GuardIdentity.bundle) && Int32(cells[0]) != nil
        }
    }
    private static func restart(killExisting: Bool) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["kickstart"] + (killExisting ? ["-k"] : []) + ["gui/\(getuid())/" + GuardIdentity.bundle]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        do { try process.run(); process.waitUntilExit(); return process.terminationStatus == 0 }
        catch { return false }
    }
    static func run(allowRestart: Bool = true) async {
        let started = Date(), path = GuardIdentity.support.appendingPathComponent("watchdog-health.json")
        let old = (try? Data(contentsOf: path)).flatMap { try? JSONDecoder().decode(Health.self, from: $0) }
        let running = processRunning()
        let status = await VendorHelper.status()
        let observed = snapshot()
        let decision = WatchdogDecision.evaluate(snapshot: observed, running: running, status: status, now: Date())
        var dates = (old?.restartDates ?? []).filter { Date().timeIntervalSince($0) < 3600 }
        var outcome: String?
        var restartAttempted = false
        if allowRestart && (decision == .stoppedStart || decision == .staleConnectedRestart) {
            if dates.count >= 3 { outcome = "restart_budget_exhausted" }
            else if let lease = RecoveryLease() {
                let latest = snapshot(), live = await VendorHelper.status()
                let reviewed = WatchdogDecision.evaluate(snapshot: latest, running: processRunning(), status: live, now: Date())
                if reviewed == decision {
                    dates.append(Date())
                    restartAttempted = true
                    outcome = restart(killExisting: decision == .staleConnectedRestart) ? "guard_service_started" : "launchctl_refused"
                } else { outcome = "state_changed_restart_cancelled" }
                withExtendedLifetime(lease) { }
            } else { outcome = "recovery_control_busy" }
        }
        let journalAt = old?.lastJournalAt ?? .distantPast
        let record = old?.decision != decision.rawValue || outcome != nil || Date().timeIntervalSince(journalAt) >= 300
        let health = Health(startedAt: started, completedAt: Date(), decision: decision.rawValue,
            processRunning: running, vendorStatus: status?.rawValue, restartDates: dates,
            lastJournalAt: record ? Date() : old?.lastJournalAt, restartOutcome: outcome)
        if allowRestart { try? FileManager.default.createDirectory(at: GuardIdentity.support, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
        if allowRestart, let bytes = try? JSONEncoder().encode(health) {
            try? bytes.write(to: path, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        }
        if allowRestart && record {
            let journal = GuardJournal(generation: "watchdog")
            journal.append(GuardEvent(at: Date(), generation: journal.generation, name: "watchdog_completed",
                state: observed?.state, reason: outcome ?? decision.rawValue, episodeID: observed?.episodeID,
                attemptID: observed?.attemptID, vendorStatus: status?.rawValue, locked: LocalSession.isLocked, initiator: "watchdog"))
        }
        print("{\"watchdogCompleted\":true,\"decision\":\"\(decision.rawValue)\",\"restartAttempted\":\(restartAttempted),\"noVPNClientOperation\":true}")
    }
}
