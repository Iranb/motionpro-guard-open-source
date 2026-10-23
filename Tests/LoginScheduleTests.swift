// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation

@main struct LoginScheduleTests {
    static func main() throws {
        var count = 0
        func check(_ value: Bool, _ description: String) { precondition(value, description); count += 1 }
        let login = Date(timeIntervalSince1970: 1_700_000_000)
        let first = login.addingTimeInterval(86_520)
        check(LoginExpirySchedule.next(lastLogin: nil, evaluatedAt: nil) == nil, "unknown login time must not invent a deadline")
        check(LoginExpirySchedule.next(lastLogin: login, evaluatedAt: nil) == first, "first evaluation follows login by exactly 24h plus two minutes")
        check(LoginExpirySchedule.next(lastLogin: login, evaluatedAt: first.addingTimeInterval(-1)) == first, "an early manual check does not postpone expiry")
        check(LoginExpirySchedule.next(lastLogin: login, evaluatedAt: first) == first.addingTimeInterval(86_400), "a completed scheduled check cannot immediately fire again")
        let late = first.addingTimeInterval(2 * 86_400 + 60)
        check(LoginExpirySchedule.next(lastLogin: login, evaluatedAt: late) == first.addingTimeInterval(3 * 86_400), "a late wake skips missed slots without replaying them")
        let recentLogin = first.addingTimeInterval(-3600)
        check(LoginExpirySchedule.next(lastLogin: recentLogin, evaluatedAt: first) == recentLogin.addingTimeInterval(86_520), "a successful manual login starts a new full lifetime")
        var policy = RecoveryPolicy()
        policy.lastSuccessfulLoginAt = login; policy.lastScheduledEvaluationAt = first
        policy.submissions = [first.addingTimeInterval(-10)]
        let decoded = try JSONDecoder().decode(RecoveryPolicy.self, from: JSONEncoder().encode(policy))
        check(decoded.lastSuccessfulLoginAt == login && decoded.lastScheduledEvaluationAt == first, "restart retains the login anchor and consumed schedule")
        check(decoded.submissions == policy.submissions, "schedule persistence keeps the submission history")
        let oldObject: [String: Any] = ["enabled":true,"submissions":[],"consecutiveFailures":0,"successCount":0,"manualHold":false]
        let oldPolicy = RecoveryPolicy.loadOrHold(try JSONSerialization.data(withJSONObject: oldObject))
        check(oldPolicy.enabled && oldPolicy.lastSuccessfulLoginAt == nil, "existing policy remains readable without fabricating a login time")
        policy.succeeded(now: recentLogin)
        check(policy.lastSuccessfulLoginAt == recentLogin, "confirmed tunnel success rearms from the new login")
        check(LoginExpirySchedule.next(lastLogin: policy.lastSuccessfulLoginAt, evaluatedAt: first) == recentLogin.addingTimeInterval(86_520), "old evaluation does not delay a new session")
        print("Login schedule checks passed: \(count)")
    }
}
