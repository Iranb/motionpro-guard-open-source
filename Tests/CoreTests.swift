// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import Security

@main struct CoreTests {
    @MainActor static func main() async throws {
        var passed = 0
        func check(_ condition: @autoclosure () -> Bool, _ label: String) {
            guard condition() else { fatalError("FAIL: " + label) }; passed += 1
        }
        // Metadata-only migration: preserve existing restrictions and unrelated
        // plist keys, reject malformed metadata, and never add broad partitions.
        let oldPartitions = ["cdhash:" + String(repeating: "1", count: 40), "teamid:example"]
        let newPartition = "cdhash:" + String(repeating: "2", count: 40)
        let originalPlist: [String: Any] = ["Partitions": oldPartitions, "preserve": "metadata"]
        let originalBytes = try PropertyListSerialization.data(fromPropertyList: originalPlist, format: .xml, options: 0)
        let originalHex = originalBytes.map { String(format: "%02x", $0) }.joined()
        let appended = try KeychainPartition.appending(newPartition, to: originalHex)
        var decoded = Data()
        for i in stride(from: 0, to: appended.count, by: 2) {
            let start = appended.index(appended.startIndex, offsetBy: i)
            decoded.append(UInt8(appended[start..<appended.index(start, offsetBy: 2)], radix: 16)!)
        }
        let migrated = try PropertyListSerialization.propertyList(from: decoded, format: nil) as! [String: Any]
        check(migrated["Partitions"] as? [String] == oldPartitions + [newPartition], "only append the current build partition")
        check(migrated["preserve"] as? String == "metadata", "preserve unrelated partition metadata")
        let repeated = try KeychainPartition.appending(newPartition, to: appended)
        check(repeated == appended, "migration is byte-stable when already authorized")
        for candidate in ["unsigned:", "apple:", "teamid:unrelated", "cdhash:invalid"] {
            var refused = false
            do { _ = try KeychainPartition.appending(candidate, to: originalHex) } catch { refused = true }
            check(refused, "refuse partition values outside a specific build hash")
        }
        for malformed in ["", "0", "zz", "0000"] {
            var refused = false
            do { _ = try KeychainPartition.appending(newPartition, to: malformed) } catch { refused = true }
            check(refused, "malformed partition data never authorizes mutation")
        }
        var unsignedRefused = false
        do { _ = try KeychainPartition.currentSignedGuard() } catch { unsignedRefused = true }
        check(unsignedRefused, "test executable cannot impersonate the pinned Guard identity")
        func interactionAllowed() throws -> Bool {
            var allowed: DarwinBoolean = false
            guard SecKeychainGetUserInteractionAllowed(&allowed) == errSecSuccess else {
                throw GuardFailure.message("Cannot inspect test process interaction flag")
            }
            return allowed.boolValue
        }
        let originalInteraction = try interactionAllowed()
        let duringSilent = try Vault.withInteraction { try interactionAllowed() }
        check(!duringSilent, "legacy file-keychain interaction is disabled during background access")
        let afterSilent = try interactionAllowed()
        check(afterSilent == originalInteraction, "interaction flag restored after success")
        enum SyntheticFailure: Error { case expected }
        do {
            try Vault.withInteraction { () throws -> Void in throw SyntheticFailure.expected }
        } catch SyntheticFailure.expected { }
        let afterFailure = try interactionAllowed()
        check(afterFailure == originalInteraction, "interaction flag restored after a denied or failed operation")
        try Vault.withInteraction(true) {
            let duringExplicit = try interactionAllowed()
            check(duringExplicit, "explicit user action may allow keychain interaction")
            let nestedSilent = try Vault.withInteraction { try interactionAllowed() }
            check(!nestedSilent, "nested background operation still disables interaction")
            let afterNested = try interactionAllowed()
            check(afterNested, "nested operation restores outer interaction policy")
        }
        let afterExplicit = try interactionAllowed()
        check(afterExplicit == originalInteraction, "explicit operation restores process policy")
        // Simulate an outstanding user prompt on a worker. Background monitoring
        // must return without waiting for it; no real prompt or item is created.
        let acquired = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let worker = Task.detached {
            try Vault.withInteraction(true) { acquired.signal(); release.wait() }
        }
        check(acquired.wait(timeout: .now() + 5) == .success, "explicit interaction scope acquired")
        let startedAt = ProcessInfo.processInfo.systemUptime
        var backgroundRefused = false
        do { try Vault.withInteraction { } } catch { backgroundRefused = true }
        release.signal()
        try await worker.value
        check(backgroundRefused, "background access refuses while user authorization is outstanding")
        check(ProcessInfo.processInfo.systemUptime - startedAt < 1, "background access does not wait on a user prompt")
        let afterConcurrent = try interactionAllowed()
        check(afterConcurrent == originalInteraction, "concurrent scope restores process flag")
        check(VendorStatus.parse("VPN status:2\n(0:idle;1:connecting;2:connected)") == .connected, "vendor connected output")
        check(VendorStatus.parse("error\n(0:idle;2:connected)") == nil, "do not parse help as status")
        check(VendorStatus.reconnecting.isBusy && !VendorStatus.reconnecting.mayLogin, "do not interrupt reconnection")
        check(!VendorStatus.connected.mayLogin && VendorStatus.disconnected.mayLogin, "never relogin connected session")
        var window = DisconnectionWindow()
        for t in [0.0, 10, 20] { check(!window.observe(.disconnected, uptime: t), "wait for 30 seconds of consecutive offline observations") }
        check(window.observe(.disconnected, uptime: 30), "persistent offline qualifies")
        check(!window.observe(nil, uptime: 40), "unknown status cancels offline evidence")
        check(!window.observe(.disconnected, uptime: 50), "unknown gap cannot be counted as offline")
        for t in [60.0, 70, 80] { _ = window.observe(.disconnected, uptime: t) }
        check(!window.observe(.disconnected, uptime: 200), "sleep/wake observation gap requires fresh confirmation")
        for status in [VendorStatus.connected, .bothConnected, .connecting, .reconnecting, .disconnecting, .desktopConnected] {
            check(!window.observe(status, uptime: 210), "active or ambiguous modes reset offline confirmation")
        }

        // Exercise the actual production sequencing using synthetic side effects.
        func flow(statuses: [VendorStatus?], failAt: String? = nil) async -> [String] {
            var steps: [String] = [], index = 0
            do {
                try await RecoveryFlow.run(status: {
                    let value = statuses[min(index, statuses.count - 1)]; index += 1
                    steps.append("status"); return value
                }, verify: {
                    steps.append("verify")
                    if failAt == "verify" { throw GuardFailure.noOTP }
                    return true
                }, validate: { _ in
                    steps.append("validate")
                    if failAt == "validate" { throw GuardFailure.noOTP }
                }, closeClient: {
                    steps.append("close")
                    if failAt == "close" { throw GuardFailure.message("synthetic close failure") }
                }, prepare: { _ in
                    steps.append("prepare")
                    if failAt == "prepare" { throw GuardFailure.message("synthetic preparation failure") }
                }, submit: { steps.append("submit") })
            } catch { steps.append("stopped") }
            return steps
        }
        let missingOTP = await flow(statuses: [.disconnected], failAt: "verify")
        check(missingOTP == ["status", "verify", "stopped"], "OTP failure never closes client, writes profile, or submits")
        let staleOTP = await flow(statuses: [.disconnected], failAt: "validate")
        check(!staleOTP.contains("close") && !staleOTP.contains("submit"), "expired OTP or user intervention stops before shutdown")
        for status: VendorStatus? in [.connected, .bothConnected, .connecting, .disconnecting, .reconnecting, .desktopConnected, nil] {
            let initial = await flow(statuses: [status])
            check(initial == ["status", "stopped"], "active or unknown tunnel prevents recovery")
            let duringOTP = await flow(statuses: [.disconnected, status])
            check(!duringOTP.contains("close") && !duringOTP.contains("prepare"), "state change while waiting for OTP preserves client")
            let afterClose = await flow(statuses: [.disconnected, .disconnected, status])
            check(!afterClose.contains("prepare") && !afterClose.contains("submit"), "state change after shutdown prevents profile injection")
            let afterPrepare = await flow(statuses: [.disconnected, .disconnected, .disconnected, status])
            check(!afterPrepare.contains("submit"), "state change before launch prevents duplicate login")
        }
        let closeFailure = await flow(statuses: [.disconnected], failAt: "close")
        check(!closeFailure.contains("prepare") && !closeFailure.contains("submit"), "failed graceful close never overwrites live configuration")
        let prepareFailure = await flow(statuses: [.disconnected], failAt: "prepare")
        check(!prepareFailure.contains("submit"), "configuration failure does not spend a login submission")
        let successfulOrder = await flow(statuses: [.disconnected])
        check(successfulOrder == ["status", "verify", "status", "validate", "close", "status", "validate", "prepare", "status", "validate", "submit"], "OTP verified before shutdown, state rechecked at each mutation boundary")

        for auto in ["true", "false"] {
            var idle = INIFile(text: "[global]\nautoconnect=\(auto)\nunrelated=keep\n[profiles]\ndata\\size=1\ndata\\1\\host=\(GuardIdentity.host)\ndata\\1\\password2=synthetic-old\ndata\\1\\reconn_sess_invalid=1\n")
            let original = idle.text
            let transaction = try VendorProfile.configureIdleLaunch(&idle)
            check(idle.value(section: "global", key: "autoconnect") == "false", "failure relaunch never auto-submits cached OTP")
            check(idle.value(section: "profiles", key: "data\\1\\reconn_sess_invalid") == "0", "failure relaunch disables expired-session retry")
            let restored = try JSONDecoder().decode(LoginTransaction.self, from: JSONEncoder().encode(transaction))
            restored.restore(into: &idle)
            check(idle.text == original, "idle relaunch transaction restores original preferences exactly")
        }
        let now = Date(timeIntervalSince1970: 1_000_000)
        var policy = RecoveryPolicy()
        try policy.submit(now: now); policy.failed()
        check(policy.allowed(now: now.addingTimeInterval(100)), "one retry permitted")
        try policy.submit(now: now.addingTimeInterval(100)); policy.failed()
        check(!policy.allowed(now: now.addingTimeInterval(110)), "two failures stop automation")
        let restored = try JSONDecoder().decode(RecoveryPolicy.self, from: JSONEncoder().encode(policy))
        check(!restored.allowed(now: now.addingTimeInterval(120)), "restart preserves retry budget")
        policy.manualHold = false; policy.consecutiveFailures = 0
        check(!policy.allowed(now: now.addingTimeInterval(200)), "manual release does not erase hourly limit")
        policy.prune(now: now.addingTimeInterval(4000))
        check(policy.allowed(now: now.addingTimeInterval(4000)), "hourly budget expires")
        let statsNow = Date(timeIntervalSince1970: 1_800_000_000)
        let oldConnection = statsNow.addingTimeInterval(-100 * 3600)
        let cutoff = statsNow.addingTimeInterval(-ReconnectHistory.window)
        let recent = statsNow.addingTimeInterval(-10)
        var history = ReconnectHistory()
        history.merge([oldConnection, cutoff, cutoff.addingTimeInterval(1), recent, recent, statsNow.addingTimeInterval(5)], now: statsNow)
        check(history.firstConnection == oldConnection, "initial connection is a persistent baseline")
        check(history.reconnections == [cutoff.addingTimeInterval(1), recent], "72h excludes exact boundary, future events and duplicates")
        history.merge([oldConnection, recent, recent], now: statsNow)
        check(history.reconnections.count == 2, "repeated log scans do not increment count")
        var restoredHistory = try JSONDecoder().decode(ReconnectHistory.self, from: JSONEncoder().encode(history))
        check(restoredHistory == history, "restart preserves reconnection timestamps and baseline")
        restoredHistory.merge([], now: statsNow.addingTimeInterval(2))
        check(restoredHistory.reconnections == [recent], "72h window expires without another connection")
        restoredHistory.merge([], now: statsNow.addingTimeInterval(ReconnectHistory.window))
        check(restoredHistory.reconnections.isEmpty && restoredHistory.firstConnection == oldConnection, "expired records pruned while baseline retained")
        var firstSession = ReconnectHistory()
        firstSession.merge([recent], now: statsNow)
        check(firstSession.reconnections.isEmpty, "first observed session alone is not a reconnection")
        firstSession.merge([oldConnection], now: statsNow)
        check(firstSession.reconnections == [recent], "earlier backfill reclassifies baseline correctly")
        var statsSnapshot = GuardSnapshot()
        let legacySnapshot = try JSONDecoder().decode(GuardSnapshot.self, from: JSONEncoder().encode(statsSnapshot))
        check(legacySnapshot.reconnectionCount(at: statsNow) == nil, "old snapshots show unavailable rather than a false zero")
        statsSnapshot.recentReconnectionDates = history.reconnections
        check(statsSnapshot.reconnectionCount(at: statsNow) == 2, "snapshot count uses requested timeline date")
        check(statsSnapshot.reconnectionCount(at: statsNow.addingTimeInterval(2)) == 1, "widget count expires at a future timeline entry")
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current; formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let logDate = formatter.date(from: "2020-01-02 10:00:00")!
        var parser = ConnectionLogParser()
        let finish = "2020-01-02 10:00:00 MainWin::OnVpnConnected: vpn connected finish, start set display status."
        let l3 = "2020-01-02 10:00:01 MainWin::OnVpnConnected: current tunnel type is L3VPN only"
        check(parser.consume("2020-01-02 10:00:00 login successfully, method name: synthetic") == nil, "authentication alone is not a successful tunnel")
        check(parser.consume(l3) == nil, "mode line without a connection callback is ignored")
        check(parser.consume(finish) == nil, "connection callback waits for L3 confirmation")
        check(parser.consume(l3) == logDate, "confirmed campus tunnel uses connection event timestamp")
        check(parser.consume(l3) == nil, "repeated mode lines do not duplicate event")
        _ = parser.consume(finish)
        check(parser.consume("2020-01-02 10:00:01 MainWin::OnVpnConnected: display desktop tab.") == nil, "desktop-only session is not a campus tunnel")
        check(parser.consume("2020-01-02 10:00:31 MainWin::OnVpnConnected: current tunnel type is L3VPN only") == nil, "stale callback cannot confirm another session")
        _ = parser.consume(finish)
        check(parser.consume("2020-01-02 10:00:01 MainWin::OnVpnConnected: get vpnd status is l3 connected, need send status both connected to vpnd.") == logDate, "combined desktop and L3 mode counts once")
        check(parser.consume("invalid timestamp OnVpnConnected: vpn connected finish, start set display status.") == nil, "invalid log timestamp is rejected")
        let otp = OTPReading.parse(buttonDescriptions: ["AddButtonIcon", "12", "34", "56", "045"])
        check(otp?.code == "123456" && otp?.freshEnough == true, "OTP grouping and fresh clock")
        check(OTPReading.parse(buttonDescriptions: ["12", "34", "56", "006"])?.freshEnough == false, "wait for almost expired OTP")
        check(OTPReading.parse(buttonDescriptions: ["12", "34", "56", "78", "045"]) == nil, "reject ambiguous OTP")
        check(OTPReading.parse(buttonDescriptions: ["12", "34", "56"]) == nil, "require countdown")
        check(OTPReading.parse(buttonDescriptions: ["12", "34", "56", "09"])?.secondsRemaining == 9, "two-digit countdown is distinct from the three code groups")
        check(OTPReading.parse(buttonDescriptions: ["12", "34", "56", "00"])?.secondsRemaining == 0, "zero countdown stays readable across rollover")
        check(OTPReading.parse(buttonDescriptions: ["12", "34", "56", "9"])?.secondsRemaining == 9, "single-digit countdown is recognized by position")
        check(OTPReading.parse(buttonDescriptions: ["045", "12", "34", "56"]) == nil, "misordered timer cannot be confused with code")
        check(OTPReading.parse(buttonDescriptions: ["12", "34", "56", "99"]) == nil, "invalid countdown is rejected")
        check(OTPReading.parse(buttonDescriptions: ["12", "34", "56", "09", "008"]) == nil, "extra numeric control is ambiguous")
        var boundaryProof = OTPFreshnessProof()
        for (index, clock) in ["010", "09", "08", "07", "06", "05", "04", "03", "02", "01"].enumerated() {
            let reading = OTPReading.parse(buttonDescriptions: ["11", "11", "11", clock])
            check(reading != nil, "countdown remains readable through its width change")
            if let reading { _ = boundaryProof.observe(reading, uptime: 100 + Double(index)) }
        }
        let rollover = OTPReading.parse(buttonDescriptions: ["22", "22", "22", "030"])!
        let confirmingTick = OTPReading.parse(buttonDescriptions: ["22", "22", "22", "029"])!
        check(!boundaryProof.observe(rollover, uptime: 110), "rollover still needs a confirming countdown tick")
        check(boundaryProof.observe(confirmingTick, uptime: 111), "realistic countdown formatting can prove fresh rollover")
        var proof = OTPFreshnessProof()
        check(!proof.observe(OTPReading(code: "111111", secondsRemaining: 2), uptime: 100), "initial background value is untrusted")
        check(!proof.observe(OTPReading(code: "111111", secondsRemaining: 1), uptime: 101), "countdown alone does not prove rollover")
        check(!proof.observe(OTPReading(code: "222222", secondsRemaining: 30), uptime: 102), "rollover waits for a confirming tick")
        check(proof.observe(OTPReading(code: "222222", secondsRemaining: 29), uptime: 103), "live background rollover verified")
        check(!proof.observe(OTPReading(code: "222222", secondsRemaining: 29), uptime: 104), "frozen AX clock invalidates proof")
        check(!proof.observe(OTPReading(code: "222222", secondsRemaining: 28), uptime: 105), "invalidated proof cannot silently recover")
        var gapProof = OTPFreshnessProof()
        _ = gapProof.observe(OTPReading(code: "111111", secondsRemaining: 1), uptime: 100)
        check(!gapProof.observe(OTPReading(code: "222222", secondsRemaining: 30), uptime: 110), "long background suspension rejected")
        check(!gapProof.observe(OTPReading(code: "222222", secondsRemaining: 29), uptime: 111), "stale resume cannot authorize login")
        var jumpProof = OTPFreshnessProof()
        _ = jumpProof.observe(OTPReading(code: "111111", secondsRemaining: 40), uptime: 100)
        check(!jumpProof.observe(OTPReading(code: "222222", secondsRemaining: 30), uptime: 101), "unexpected code switch is not a valid rollover")
        check(!jumpProof.observe(OTPReading(code: "222222", secondsRemaining: 29), uptime: 102), "wrong-token switch stays untrusted")
        var expiryProof = OTPFreshnessProof()
        _ = expiryProof.observe(OTPReading(code: "111111", secondsRemaining: 1), uptime: 100)
        _ = expiryProof.observe(OTPReading(code: "222222", secondsRemaining: 25), uptime: 101)
        check(!expiryProof.observe(OTPReading(code: "222222", secondsRemaining: 24), uptime: 102), "short-lived code cannot authorize login")
        check(!expiryProof.observe(OTPReading(code: "222222", secondsRemaining: 29), uptime: 90), "monotonic clock reversal invalidates proof")
        // Published RFC keys only; never read a real OTP seed in core tests.
        let rfcKey = Data("12345678901234567890".utf8)
        for (counter, expected) in ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"].enumerated() {
            check(OfflineOTP.TOTP.generate(seed: rfcKey, counter: UInt64(counter)) == expected, "RFC 4226 HOTP vector")
        }
        for (time, expected) in [(59.0, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"), (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")] {
            check(OfflineOTP.TOTP.generate(seed: rfcKey, counter: UInt64(floor(time / 30)), digits: 8) == expected, "RFC 6238 SHA1 vector")
        }
        func siteData(_ site: [String: Any], duplicate: Bool = false) throws -> Data {
            try PropertyListSerialization.data(fromPropertyList: duplicate ? [site, site] : [site], format: .binary, options: 0)
        }
        let fakeSite: [String: Any] = ["VirtualSiteURL": "https://" + GuardIdentity.host,
            "VirtualSiteRandomData": Array(repeating: 17, count: 10),
            "VirtualSiteDyncode": 30, "VirtualSiteInterval": 0.5]
        let syntheticToken = try OfflineOTP.candidate(data: siteData(fakeSite), username: "synthetic-user")
        check(syntheticToken.period == 30 && syntheticToken.clockUncertainty == 1, "period and clock adjustment use different vendor fields")
        let syntheticCredentials = Credentials(host: GuardIdentity.host, username: "synthetic-user", password: "dummy")
        try syntheticToken.requireBinding(credentials: syntheticCredentials, profileUsername: "synthetic-user")
        for (credentials, profile) in [(Credentials(host: "other.invalid", username: "synthetic-user", password: "dummy"), "synthetic-user"),
                (Credentials(host: GuardIdentity.host, username: "changed", password: "dummy"), "synthetic-user"),
                (syntheticCredentials, "changed")] {
            var refused = false
            do { try syntheticToken.requireBinding(credentials: credentials, profileUsername: profile) } catch { refused = true }
            check(refused, "token cannot follow a changed account or gateway")
        }
        for (key, value) in [("VirtualSiteURL", "https://other.invalid" as Any), ("VirtualSiteDyncode", 0),
                ("VirtualSiteDyncode", 30.5), ("VirtualSiteDyncode", true), ("VirtualSiteInterval", 60),
                ("VirtualSiteRandomData", Array(repeating: 17, count: 9)),
                ("VirtualSiteRandomData", [17,17,17,17,17,17,17,17,17,256]),
                ("VirtualSiteRandomData", [17,17,17,17,17,17,17,17,17,17.5]),
                ("VirtualSiteRandomData", Array(repeating: true, count: 10))] {
            var site = fakeSite; site[key] = value
            var refused = false
            do { _ = try OfflineOTP.candidate(data: siteData(site), username: "synthetic-user") } catch { refused = true }
            check(refused, "malformed or foreign token material is rejected before enrollment")
        }
        var duplicateRefused = false
        do { _ = try OfflineOTP.candidate(data: siteData(fakeSite, duplicate: true), username: "synthetic-user") } catch { duplicateRefused = true }
        check(duplicateRefused, "multiple matching sites cannot choose a seed implicitly")
        for time in [59.1, 60.1, 60.9, -1, Double.infinity, Double.nan] {
            var refused = false
            do { _ = try syntheticToken.reading(at: time) } catch { refused = true }
            check(refused, "ambiguous counter boundaries or invalid times never produce a login code")
        }
        let offlineReading = try syntheticToken.reading(at: 62)
        check(offlineReading.secondsRemaining == 27 && offlineReading.freshEnough, "expiry uses the earliest possible server boundary")
        let agingReading = try syntheticToken.reading(at: 64.1)
        check(!agingReading.freshEnough, "computed code near expiry must wait for a new period")
        var clock = OfflineOTP.Clock()
        var settling = false
        do { try clock.observe(wall: 1000, uptime: 100) } catch OfflineOTP.Failure.clockSettling { settling = true }
        check(settling, "one wall-clock sample cannot establish clock stability")
        try clock.observe(wall: 1001, uptime: 101)
        var changed = false
        do { try clock.observe(wall: 2002, uptime: 102) } catch OfflineOTP.Failure.clockChanged { changed = true }
        check(changed, "wall-clock jump invalidates current generation proof")
        try clock.observe(wall: 2003, uptime: 103)
        var resumed = false
        do { try clock.observe(wall: 2100, uptime: 200) } catch OfflineOTP.Failure.clockChanged { resumed = true }
        check(resumed, "sleep or observation gap requires a fresh clock baseline")
        try clock.observe(wall: 2101, uptime: 201)
        var independentSnapshot = GuardSnapshot(); independentSnapshot.accessibilityReady = false
        independentSnapshot.offlineOTPCheckState = "ready"; independentSnapshot.offlineOTPReady = true
        check(independentSnapshot.otpAccessReady, "enrolled offline backend does not depend on AX permission")
        independentSnapshot.accessibilityReady = true; independentSnapshot.offlineOTPReady = false
        independentSnapshot.offlineOTPCheckState = "unavailable"
        check(!independentSnapshot.otpAccessReady, "denied enrolled token cannot silently claim AX fallback readiness")
        // Manual interaction, old authentication and a changed PID invalidate attribution.
        let testNow = Date(timeIntervalSince1970: 1_800_000_000)
        var attributed = LoginAttribution()
        attributed.submitted(at: testNow); attributed.launched(pid: 101)
        check(attributed.classify(authenticationAt: testNow.addingTimeInterval(1), connectedPID: 101) == "guard_submission_confirmed", "fresh auth and same launched PID corroborate submission")
        check(attributed.classify(authenticationAt: testNow.addingTimeInterval(-1), connectedPID: 101) == "unknown_or_external", "old auth cannot prove new login")
        check(attributed.classify(authenticationAt: testNow, connectedPID: 102) == "unknown_or_external", "changed PID prevents success count")
        attributed.observe(pid: 101, userActive: true, manualLease: false)
        check(attributed.classify(authenticationAt: testNow, connectedPID: 101) == "unknown_or_external", "manual interaction in the same PID invalidates attribution")
        var missingLaunch = LoginAttribution(); missingLaunch.submitted(at: testNow)
        check(missingLaunch.classify(authenticationAt: testNow, connectedPID: 101) == "unknown_or_external", "launch intent alone is unconfirmed")
        var evidence = StateEvidence()
        check(evidence.transition(state: "otp", reason: "otp_unavailable", now: testNow), "blocked reason initially journaled")
        check(!evidence.transition(state: "otp", reason: "otp_unavailable", now: testNow.addingTimeInterval(10)), "repeated waits do not flood journal")
        check(evidence.enteredAt == testNow, "repeated checks cannot reset blocked deadline")
        check(evidence.transition(state: "otp", reason: "otp_unavailable", now: testNow.addingTimeInterval(301)), "long waits get summaries")
        var health = GuardSnapshot(); health.state = "connected"; health.lastCheckCompletedAt = testNow
        check(WatchdogDecision.evaluate(snapshot: health, running: true, status: .connected, now: testNow) == .healthy, "healthy completion needs no restart")
        check(WatchdogDecision.evaluate(snapshot: health, running: false, status: .connected, now: testNow) == .stoppedStart, "dead process not hidden by fresh snapshot")
        check(WatchdogDecision.evaluate(snapshot: health, running: true, status: .connected, now: testNow.addingTimeInterval(100)) == .staleConnectedRestart, "stale observer may restart with connected tunnel")
        check(WatchdogDecision.evaluate(snapshot: health, running: true, status: .disconnected, now: testNow.addingTimeInterval(100)) == .staleOfflineNeedsAttention, "offline stale observer requires attention")
        health.recoveryBusy = true
        check(WatchdogDecision.evaluate(snapshot: health, running: true, status: .connected, now: testNow.addingTimeInterval(100)) == .mutationActive, "active authentication inhibits watchdog restart")
        health.stateDeadline = testNow.addingTimeInterval(120)
        check(WatchdogDecision.evaluate(snapshot: health, running: true, status: .connected, now: testNow.addingTimeInterval(121)) == .blockedNeedsAttention, "expired mutation reports blockage without restart")
        check(WatchdogDecision.evaluate(snapshot: health, running: false, status: .connected, now: testNow.addingTimeInterval(121)) == .stoppedStart, "dead process is not hidden by stale busy flag")
        health.stateDeadline = nil
        health.recoveryBusy = false; health.manualControlUntil = testNow.addingTimeInterval(600)
        check(WatchdogDecision.evaluate(snapshot: health, running: true, status: .connected, now: testNow.addingTimeInterval(100)) == .manualControl, "watchdog respects manual takeover")
        health.manualControlUntil = nil; health.state = "otp"; health.stateDeadline = testNow.addingTimeInterval(75)
        check(WatchdogDecision.evaluate(snapshot: health, running: true, status: .disconnected, now: testNow.addingTimeInterval(10)) == .expectedWait, "bounded wait recognized")
        check(WatchdogDecision.evaluate(snapshot: health, running: true, status: .disconnected, now: testNow.addingTimeInterval(76)) == .blockedNeedsAttention, "expired state needs attention")
        let deadlineStart = ProcessInfo.processInfo.systemUptime
        var timedOut = false
        do {
            let _: Int = try await ReadDeadline.run(seconds: 0.03) { try await Task.sleep(nanoseconds: 300_000_000); return 1 }
        } catch is ReadDeadline.Expired { timedOut = true }
        check(timedOut && ProcessInfo.processInfo.systemUptime - deadlineStart < 0.2, "read deadline does not wait for worker")
        let logRoot = FileManager.default.temporaryDirectory.appendingPathComponent("guard-journal-test-" + UUID().uuidString)
        let journal = GuardJournal(root: logRoot, generation: "synthetic-generation")
        journal.append(GuardEvent(at: testNow, generation: journal.generation, name: "state_observed", state: "otp", reason: "otp_unavailable"))
        let files = try FileManager.default.contentsOfDirectory(at: logRoot, includingPropertiesForKeys: nil)
        check(files.count == 1, "event persisted separately from overwritten snapshot")
        let persisted = try JSONDecoder().decode(GuardEvent.self, from: Data(contentsOf: files[0]))
        check(persisted.reason == "otp_unavailable" && persisted.at == testNow, "event preserves reason and time")
        try FileManager.default.removeItem(at: logRoot)
        var handoffPolicy = RecoveryPolicy(); handoffPolicy.manualControlUntil = testNow.addingTimeInterval(600)
        let restoredHandoff = try JSONDecoder().decode(RecoveryPolicy.self, from: JSONEncoder().encode(handoffPolicy))
        check(!restoredHandoff.allowed(now: testNow), "manual lease survives restart")
        check(restoredHandoff.allowed(now: testNow.addingTimeInterval(601)), "manual lease expires without resetting budget")
        let corruptPolicy = RecoveryPolicy.loadOrHold(Data("broken-json".utf8), now: testNow)
        check(!corruptPolicy.enabled && corruptPolicy.manualHold, "corrupt persisted policy pauses automation")
        check(corruptPolicy.submissions.count == 2, "corrupt state cannot restore a fresh hourly submission budget")
        let cipher = VendorCipher(testKey: Data(repeating: 0x47, count: 16))
        for secret in ["synthetic", "1234567890abcdef", "中文合成测试密码"] {
            let encrypted = try cipher.encrypt(secret)
            let decrypted = try cipher.decrypt(encrypted)
            check(decrypted == secret, "vendor encryption roundtrip")
        }
        let first = try cipher.encrypt("synthetic"), second = try cipher.encrypt("synthetic")
        check(first != second, "random IV per encryption")
        var ini = INIFile(text: "[global]\nautoconnect=false\nunrelated=keep\n[profiles]\ndata\\1\\password2=\"abc=\"\n")
        check(ini.value(section: "profiles", key: "data\\1\\password2") == "abc=", "Qt quoted base64")
        ini.set(section: "global", key: "autoconnect", raw: "true")
        ini.set(section: "profiles", key: "data\\1\\new", raw: "x")
        ini.set(section: "profiles", key: "data\\1\\password2", raw: nil)
        check(ini.value(section: "global", key: "unrelated") == "keep", "preserve unrelated setting")
        check(ini.value(section: "profiles", key: "data\\1\\new") == "x", "append within section")
        check(ini.value(section: "profiles", key: "data\\1\\password2") == nil, "remove temporary secret")
        print("PASS: \(passed) checks; no credentials or OTP values emitted")
    }
}
