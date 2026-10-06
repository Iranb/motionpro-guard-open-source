// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import Darwin

final class RecoveryLease {
    private let descriptor: Int32
    init?(root: URL = GuardIdentity.support) {
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let descriptor = open(root.appendingPathComponent("recovery-control.lock").path, O_CREAT | O_RDWR, 0o600)
        guard descriptor >= 0 else { return nil }
        guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { close(descriptor); return nil }
        self.descriptor = descriptor
    }
    deinit { _ = flock(descriptor, LOCK_UN); close(descriptor) }
}

/// Diagnostic records contain only fixed reason codes and operation metadata.
/// Callers must never pass vendor text, account names, OTP or token material.
struct GuardEvent: Codable {
    var at: Date
    var generation: String
    var name: String
    var state: String?
    var reason: String?
    var episodeID: String?
    var attemptID: String?
    var vendorStatus: Int?
    var locked: Bool?
    var initiator: String?
}

final class GuardJournal {
    let root: URL
    let generation: String
    private let lock = NSLock()
    init(root: URL = GuardIdentity.support.appendingPathComponent("events"), generation: String = UUID().uuidString) {
        self.root = root; self.generation = generation
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        prune()
    }
    func append(_ event: GuardEvent) {
        lock.lock(); defer { lock.unlock() }
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0); formatter.dateFormat = "yyyy-MM-dd"
        let file = root.appendingPathComponent(formatter.string(from: event.at) + ".jsonl")
        guard let bytes = try? JSONEncoder().encode(event) else { return }
        if !FileManager.default.fileExists(atPath: file.path) {
            _ = FileManager.default.createFile(atPath: file.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        // Bound disk use even if a future bug emits the same event repeatedly.
        guard let handle = try? FileHandle(forWritingTo: file) else { return }
        defer { try? handle.close() }
        guard flock(handle.fileDescriptor, LOCK_EX) == 0 else { return }
        defer { _ = flock(handle.fileDescriptor, LOCK_UN) }
        guard let size = try? handle.seekToEnd(), size < 2_097_152 else { return }
        try? handle.write(contentsOf: bytes + Data([10]))
        try? handle.synchronize()
    }
    private func prune() {
        let cutoff = Date().addingTimeInterval(-30 * 86400)
        guard let files = try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.contentModificationDateKey]) else { return }
        for file in files where file.pathExtension == "jsonl" {
            if let date = try? file.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate, date < cutoff {
                try? FileManager.default.removeItem(at: file)
            }
        }
    }
}

struct StateEvidence {
    private(set) var state = "starting"
    private(set) var reason = "startup"
    private(set) var enteredAt = Date()
    private var lastRecordedAt = Date.distantPast
    mutating func transition(state: String, reason: String, now: Date) -> Bool {
        let changed = self.state != state || self.reason != reason
        if changed { self.state = state; self.reason = reason; enteredAt = now }
        let record = changed || now.timeIntervalSince(lastRecordedAt) >= 300
        if record { lastRecordedAt = now }
        return record
    }
}

struct LoginAttribution {
    let id = UUID().uuidString
    private(set) var submittedAt: Date?
    private(set) var launchedPID: Int32?
    private(set) var interference = false
    mutating func submitted(at: Date) { submittedAt = at }
    mutating func launched(pid: Int32) { launchedPID = pid }
    mutating func observe(pid: Int32?, userActive: Bool, manualLease: Bool) {
        if userActive || manualLease || (launchedPID != nil && launchedPID != pid) { interference = true }
    }
    func classify(authenticationAt: Date?, connectedPID: Int32?) -> String {
        guard !interference, let submittedAt, let launchedPID, connectedPID == launchedPID,
              let authenticationAt, authenticationAt >= submittedAt else { return "unknown_or_external" }
        return "guard_submission_confirmed"
    }
}

enum WatchdogDecision: String {
    case healthy, expectedWait, blockedNeedsAttention, staleConnectedRestart, stoppedStart, staleOfflineNeedsAttention, mutationActive, manualControl
    static func evaluate(snapshot: GuardSnapshot?, running: Bool, status: VendorStatus?, now: Date) -> Self {
        if let snapshot {
            if let lease = snapshot.manualControlUntil, lease > now { return .manualControl }
            if !running { return .stoppedStart }
            if snapshot.recoveryBusy == true || snapshot.profileMutationActive == true {
                if let deadline = snapshot.stateDeadline, deadline <= now { return .blockedNeedsAttention }
                if let progress = snapshot.lastProgressAt, now.timeIntervalSince(progress) > 120 { return .blockedNeedsAttention }
                return .mutationActive
            }
            if let deadline = snapshot.stateDeadline, deadline > now { return .expectedWait }
            if let deadline = snapshot.stateDeadline, deadline <= now, snapshot.state != "connected" { return .blockedNeedsAttention }
            if let tick = snapshot.lastCheckCompletedAt, now.timeIntervalSince(tick) < 90 { return .healthy }
        }
        if !running { return .stoppedStart }
        return status?.hasTunnel == true ? .staleConnectedRestart : .staleOfflineNeedsAttention
    }
}

/// Unlike a task group, the deadline does not wait for an uncooperative read.
/// Use ONLY for read-only operations; mutations must complete transactionally.
enum ReadDeadline {
    struct Expired: Error { }
    private final class Race<T>: @unchecked Sendable {
        let lock = NSLock()
        var continuation: CheckedContinuation<T, Error>?
        init(_ continuation: CheckedContinuation<T, Error>) { self.continuation = continuation }
        func finish(_ result: Result<T, Error>) {
            lock.lock(); let target = continuation; continuation = nil; lock.unlock()
            target?.resume(with: result)
        }
    }
    static func run<T>(seconds: Double, operation: @escaping @Sendable () async throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            let race = Race(continuation)
            Task.detached {
                do { race.finish(.success(try await operation())) }
                catch { race.finish(.failure(error)) }
            }
            Task.detached {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                race.finish(.failure(Expired()))
            }
        }
    }
}
