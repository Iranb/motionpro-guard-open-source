// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation

/// Require consecutive observations; an unreadable state or sleep/wake gap
/// invalidates the old evidence of a disconnected tunnel.
struct DisconnectionWindow {
    private var beganAt: TimeInterval?
    private var observedAt: TimeInterval?

    mutating func observe(_ status: VendorStatus?, uptime: TimeInterval) -> Bool {
        guard status?.mayLogin == true, uptime.isFinite else {
            beganAt = nil; observedAt = nil; return false
        }
        if let last = observedAt, uptime < last || uptime - last > 20 { beganAt = nil }
        if beganAt == nil { beganAt = uptime }
        observedAt = uptime
        return uptime - beganAt! >= 30
    }
}

enum RecoveryInterrupted: Error {
    case tunnelState(VendorStatus?)
}

/// The same ordering runs in production and in isolated regression tests.
/// OTP verification must finish before any client shutdown or profile write.
@MainActor
enum RecoveryFlow {
    nonisolated static func requireDisconnected(_ status: VendorStatus?) throws {
        guard status?.mayLogin == true else { throw RecoveryInterrupted.tunnelState(status) }
    }

    static func run<Proof>(
        status: () async -> VendorStatus?,
        verify: () async throws -> Proof,
        validate: (Proof) throws -> Void,
        closeClient: () async throws -> Void,
        prepare: (Proof) async throws -> Void,
        submit: () async throws -> Void
    ) async throws {
        try requireDisconnected(await status())
        let proof = try await verify()
        // No await between this final validation and the start of closeClient.
        try requireDisconnected(await status())
        try validate(proof)
        try await closeClient()
        try requireDisconnected(await status())
        try validate(proof)
        try await prepare(proof)
        try requireDisconnected(await status())
        try validate(proof)
        try await submit()
    }
}

/// Evidence for a read-only comparison with the live official OTP window.
/// Ignore samples crossing a period boundary; never count a mismatch as a match.
struct OTPAlignmentProof {
    private(set) var matchingSamples = 0
    private(set) var mismatchingSamples = 0
    private(set) var periods: Set<UInt64> = []
    var verified: Bool { periods.count >= 2 && matchingSamples >= 4 && mismatchingSamples == 0 }
    mutating func observe(matches: Bool, before: TimeInterval, after: TimeInterval, period: Int) {
        guard period > 0, before.isFinite, after.isFinite, before >= 0, after >= before,
              after - before <= 5, after < 253_402_300_799 else { return }
        let first = floor(before / Double(period)), last = floor(after / Double(period))
        guard first == last else { return }
        if matches { matchingSamples += 1; periods.insert(UInt64(last)) }
        else { mismatchingSamples += 1 }
    }
}
