// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import Network

enum GatewayProbe {
    /// Transport readiness only. It never authenticates or changes routes.
    static func reachable() async -> Bool {
        await withCheckedContinuation { continuation in
            let queue = DispatchQueue(label: "MotionProGuard.gateway-probe")
            let connection = NWConnection(host: NWEndpoint.Host(GuardIdentity.host), port: 443, using: .tcp)
            var finished = false
            func finish(_ value: Bool) {
                guard !finished else { return }; finished = true
                connection.stateUpdateHandler = nil; connection.cancel()
                continuation.resume(returning: value)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(true)
                case .failed, .cancelled: finish(false)
                default: break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + 4) { finish(false) }
        }
    }
}
