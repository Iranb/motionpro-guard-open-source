// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import Darwin

/// Same recovery-policy.json and flock as GUI/manual recovery. A failed disk
/// write prevents the POST. Atomic rename + fsync preserve crash reservations.
enum RecoveryPolicyDisk {
    static func read(root: URL = GuardIdentity.support) throws -> RecoveryPolicy {
        let path = root.appendingPathComponent("recovery-policy.json")
        guard let data = try? Data(contentsOf: path) else { throw HeadlessFailure.persistence }
        return RecoveryPolicy.loadOrHold(data)
    }
    static func write(_ value: RecoveryPolicy, root: URL = GuardIdentity.support) throws {
        let temporary = root.appendingPathComponent(".policy-" + UUID().uuidString)
        let path = root.appendingPathComponent("recovery-policy.json")
        // Preserve manual-controller receipts and future metadata. Clear owned
        // optional fields explicitly; nil must not restore an old reservation.
        var object: [String: Any] = [:]
        if FileManager.default.fileExists(atPath: path.path) {
            guard let original = try? JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any] else { throw HeadlessFailure.persistence }
            object = original
        }
        for key in ["enabled","submissions","consecutiveFailures","lastSuccess","successCount","manualHold",
                    "manualControlUntil","confirmedSuccessCount","lockedSuccessDates","pendingHeadlessAttempt",
                    "pendingOfficialAttempt","recoveryBackend","lastSuccessfulLoginAt","lastScheduledEvaluationAt",
                    "oneTimeHourlyLimitOverrideUntil"] { object.removeValue(forKey: key) }
        let owned = try JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as! [String: Any]
        object.merge(owned, uniquingKeysWith: { _, new in new })
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        let fd = open(temporary.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw HeadlessFailure.persistence }
        defer { close(fd); _ = unlink(temporary.path) }
        var written = 0
        while written < data.count {
            let count = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: written), data.count - written) }
            guard count > 0 else { throw HeadlessFailure.persistence }; written += count
        }
        guard fsync(fd) == 0, rename(temporary.path, path.path) == 0 else { throw HeadlessFailure.persistence }
        let directory = open(root.path, O_RDONLY | O_DIRECTORY)
        guard directory >= 0 else { throw HeadlessFailure.persistence }
        defer { close(directory) }
        guard fsync(directory) == 0 else { throw HeadlessFailure.persistence }
    }
}

/// Side effects are explicit injectable operations, so tests exercise the real
/// ordering with synthetic data and can prove there is at most one POST/start.
@MainActor enum HeadlessRecoveryFlow {
    struct Operations {
        var status: () async throws -> VendorStatus
        var prepare: () async throws -> GatewayLoginForm
        var freshOTP: () async throws -> OTPReading
        var validate: () async throws -> Void
        var reserve: () throws -> Void
        var authenticate: (GatewayLoginForm, OTPReading) async throws -> HeadlessSession
        var start: (HeadlessSession) async throws -> Void
        var phase: (String) -> Void
        var wait: () async throws -> Void
        var uptime: () -> TimeInterval = { ProcessInfo.processInfo.systemUptime }
    }
    struct Result { var transitionObserved: Bool }
    static func run(_ ops: Operations, timeout: TimeInterval = 120) async throws -> Result {
        try RecoveryFlow.requireDisconnected(try await ops.status())
        try await ops.validate()
        ops.phase("fetching_login_form")
        let form = try await ops.prepare()
        let reading = try await ops.freshOTP()
        let sampledAt = ops.uptime()
        try await ops.validate()
        try RecoveryFlow.requireDisconnected(try await ops.status())
        guard reading.freshEnough, Double(reading.secondsRemaining) - (ops.uptime() - sampledAt) >= 20 else { throw HeadlessFailure.offlineRequired }
        // No awaited operation between durable reservation and auth dispatch.
        try ops.reserve()
        ops.phase("authentication_submitted")
        let session = try await ops.authenticate(form, reading)
        try session.requireFresh()
        ops.phase("session_received")
        try await ops.validate()
        try RecoveryFlow.requireDisconnected(try await ops.status())
        try await ops.start(session)
        ops.phase("waiting_native_tunnel")
        let deadline = ops.uptime() + timeout
        var transition = false
        while ops.uptime() < deadline {
            try await ops.wait()
            let status = try await ops.status()
            if status.hasTunnel { return Result(transitionObserved: transition) }
            if status == .connecting || status == .reconnecting { transition = true }
            if status == .desktopConnected { throw HeadlessFailure.nativeProtocol }
        }
        throw HeadlessFailure.timeout
    }
}

enum HeadlessCLI {
    static let requestURL = GuardIdentity.support.appendingPathComponent("cli-request.json")
    struct Request: Codable { let id: String; let generation: String; let expiresAt: Date }
    static func requestRecovery() throws -> [String: Any] {
        let native = try NativeTunnel()
        let observation = try native.status()
        if observation.status.hasTunnel { return ["requestAccepted": false, "alreadyConnected": true, "noLogin": true] }
        try RecoveryFlow.requireDisconnected(observation.status)
        let policy = try RecoveryPolicyDisk.read()
        guard policy.allowed(now: Date()) else { throw GuardFailure.retryLimit }
        let saved = try JSONDecoder().decode(GuardSnapshot.self, from: Data(contentsOf: GuardIdentity.snapshotURL))
        guard Date().timeIntervalSince(saved.updatedAt) < 30, let generation = saved.processGeneration,
              saved.recoveryBackend == "headless_native", saved.recoveryBusy != true else { throw HeadlessFailure.interrupted }
        let request = Request(id: UUID().uuidString, generation: generation, expiresAt: Date().addingTimeInterval(30))
        try JSONEncoder().encode(request).write(to: requestURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: requestURL.path)
        return ["requestAccepted": true, "requestID": request.id, "noLoginInCLI": true,
                "resultInGuardStatus": true, "failureHoldPreserved": true]
    }
    static func consume(generation: String) -> String? {
        let fd = open(requestURL.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { return nil }; defer { close(fd) }
        var metadata = stat()
        guard fstat(fd, &metadata) == 0, metadata.st_uid == getuid(), metadata.st_size < 4096,
              (metadata.st_mode & S_IFMT) == S_IFREG, (metadata.st_mode & 0o077) == 0 else { return nil }
        let data = FileHandle(fileDescriptor: fd, closeOnDealloc: false).readDataToEndOfFile()
        try? FileManager.default.removeItem(at: requestURL)
        guard let request = try? JSONDecoder().decode(Request.self, from: data), request.generation == generation,
              UUID(uuidString: request.id) != nil, request.expiresAt > Date(), request.expiresAt < Date().addingTimeInterval(31) else { return nil }
        return request.id
    }
}
