// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation

@main struct HeadlessTests {
    @MainActor static func main() async throws {
        var passed = 0
        func check(_ value: Bool, _ label: String) { guard value else { fatalError("FAIL: " + label) }; passed += 1 }
        func refused(_ label: String, _ body: () throws -> Void) {
            do { try body(); fatalError("FAIL: " + label) } catch { passed += 1 }
        }
        let formHTML = Data(#"<input name="uname"><input name='pwd' type='password'><input name="pwd1"><input name="pwd2"><input type="hidden" name="method" value="radius">"#.utf8)
        let form = try GatewayLoginForm.parse(formHTML)
        let credentials = Credentials(host: GuardIdentity.host, username: "synthetic+user", password: "synthetic&secret=+中文")
        let otp = OTPReading(code: "123456", secondsRemaining: 29)
        let payload = String(decoding: try form.body(credentials: credentials, reading: otp), as: UTF8.self)
        check(payload.contains("pwd=synthetic%26secret%3D%2B%E4%B8%AD%E6%96%87"), "static password correctly encoded")
        check(payload.contains("pwd1=123456") && payload.contains("pwd2="), "Dvpn is the second password field")
        check(payload.contains("uname=synthetic%2Buser") && payload.contains("method=radius"), "account and method mapping")
        refused("expired OTP not accepted") { _ = try form.body(credentials: credentials, reading: OTPReading(code: "123456", secondsRemaining: 10)) }
        refused("changed auth method blocked") { _ = try GatewayLoginForm.parse(formHTML + Data(#"<input name="method" value="other">"#.utf8)) }
        refused("ambiguous duplicate password field blocked") { _ = try GatewayLoginForm.parse(formHTML + Data(#"<input name="pwd1">"#.utf8)) }
        refused("captcha requires unlock") { _ = try GatewayLoginForm.parse(formHTML + Data(#"<input name="validcode" value="challenge">"#.utf8)) }
        for url in ["http://\(GuardIdentity.host)/", "https://evil.example/", "https://\(GuardIdentity.host):444/", "https://user@\(GuardIdentity.host)/"] {
            check(!HeadlessGateway.sameOrigin(URL(string: url)!), "disallow changed HTTPS origin")
        }
        func cookie(_ name: String = "ANsession123", value: String = "syntheticSession0123456789", domain: String = GuardIdentity.host, expires: Date? = nil) -> HTTPCookie {
            var properties: [HTTPCookiePropertyKey: Any] = [.name: name, .value: value, .domain: domain, .path: "/", .secure: "TRUE"]
            if let expires { properties[.expires] = expires }
            return HTTPCookie(properties: properties)!
        }
        let syntheticCookie = cookie()
        _ = try HeadlessGateway.sessionCookie([syntheticCookie]); passed += 1
        _ = try HeadlessGateway.sessionCookie([syntheticCookie, syntheticCookie]); passed += 1
        refused("HTTP 200 alone not authentication") { _ = try HeadlessGateway.sessionCookie([]) }
        refused("foreign-domain session rejected") { _ = try HeadlessGateway.sessionCookie([cookie(domain: "evil.example")]) }
        refused("short sentinel cookie rejected") { _ = try HeadlessGateway.sessionCookie([cookie(value: "true")]) }
        refused("cookie header injection rejected") { _ = try HeadlessGateway.sessionCookie([cookie(value: "syntheticSession0123456789;evil=1")]) }
        refused("ambiguous sessions rejected") { _ = try HeadlessGateway.sessionCookie([syntheticCookie, cookie("ANsession456")]) }
        refused("expired session rejected") { _ = try HeadlessGateway.sessionCookie([cookie(expires: Date().addingTimeInterval(-10))]) }
        refused("old memory session cannot start") { try HeadlessSession(cookie: "synthetic", acquiredAt: 1, expiresAt: nil).requireFresh(uptime: 62) }
        let session = HeadlessSession(cookie: "ANsession123=syntheticSession0123456789", acquiredAt: ProcessInfo.processInfo.systemUptime, expiresAt: nil)
        let start = try NativeTunnelProtocol.startRequest(session, pid: 1234)
        let request = try JSONSerialization.jsonObject(with: start) as! [String: Any]
        let startData = request["data"] as! [String: Any], site = startData["site"] as! [String: Any]
        check(startData["action"] as? Int == 6 && site["tunneltype"] as? Int == 1, "native session start requests an L3 tunnel")
        check(site["domain"] as? String == GuardIdentity.host, "native domain supplied for the gateway session")
        for field in ["host", "domain", "method", "validcode", "username", "password", "session", "certpath", "certpassword", "proxyhost", "proxydomain", "proxyusername", "proxypassword"] {
            check(site[field] is String, "vpnd required string field: " + field)
        }
        check(site["username"] as? String == "nouser" && site["password"] as? String == "nopass", "native IPC does not receive credentials")
        check(!String(decoding: start, as: UTF8.self).contains(credentials.password), "static password absent from IPC")
        check(site["reconncount"] as? Int == 0 && site["reconntime"] as? Int == 0, "no hidden engine authentication retry")
        let observed = try NativeTunnelProtocol.observation(JSONSerialization.data(withJSONObject:
            ["error": 0, "data": ["action": 8, "status": 2, "site": ["name": GuardIdentity.host]]]))
        check(observed.status.hasTunnel && observed.gatewayName == GuardIdentity.host, "vendor status parser")
        for data in [#"{"error":1,"data":{"action":8,"status":2}}"#, #"{"error":0,"data":{"action":6,"status":2}}"#, #"{"error":0,"data":{"action":8,"status":9}}"#] {
            refused("unknown or failed native response blocked") { _ = try NativeTunnelProtocol.observation(Data(data.utf8)) }
        }
        // Transport mocks run the real form, cookie, redirect and POST code.
        for kind in ["success", "success_lowercase", "no_cookie", "redirect307", "foreign_redirect", "preexisting_cookie"] {
            var posts = 0, requests: [URLRequest] = []
            let gateway = HeadlessGateway { request in
                requests.append(request)
                if request.httpMethod == "POST" {
                    posts += 1
                    let headers = kind.hasPrefix("success") ? [kind == "success_lowercase" ? "set-cookie" : "Set-Cookie": "ANsession123=syntheticSession0123456789; Path=/; Secure"] : [:]
                    if kind == "redirect307" { return GatewayReply(url: request.url!, status: 307, headers: ["location": GatewayLoginForm.endpoint.absoluteString], body: Data()) }
                    if kind == "foreign_redirect" { return GatewayReply(url: request.url!, status: 302, headers: ["location": "https://evil.example/"], body: Data()) }
                    return GatewayReply(url: request.url!, status: 200, headers: headers, body: Data("synthetic welcome".utf8))
                }
                let headers = kind == "preexisting_cookie" ? ["Set-Cookie": "ANsession123=syntheticSession0123456789; Path=/; Secure"] : [:]
                return GatewayReply(url: request.url!, status: 200, headers: headers, body: formHTML)
            }
            let current = try await gateway.prepare()
            var success = false
            do { _ = try await gateway.authenticate(form: current, credentials: credentials, reading: otp); success = true } catch { }
            check(success == kind.hasPrefix("success"), "fresh session required: " + kind)
            check(posts == 1, "one credential POST only: " + kind)
            do { _ = try await gateway.authenticate(form: current, credentials: credentials, reading: otp); fatalError("second POST allowed") } catch { passed += 1 }
            check(posts == 1, "repeated auth call cannot send again")
            check(requests.allSatisfy { HeadlessGateway.sameOrigin($0.url!) }, "all requests same HTTPS origin")
        }
        // State machine must reserve durably before POST and preserve live VPN.
        for scenario in ["success", "connected", "busy", "hold", "disk_fail", "otp_expiry", "auth_fail", "timeout", "state_change", "native_restart"] {
            var sequence: [String] = [], tick = 0.0, submitted = false, started = false
            var reads = 0
            let ops = HeadlessRecoveryFlow.Operations(status: {
                reads += 1
                if scenario == "connected" || (scenario == "state_change" && reads == 2) { return .connected }
                if scenario == "busy" { return .reconnecting }
                if started && scenario == "native_restart" { throw HeadlessFailure.nativeRestarted }
                if started && scenario != "timeout" { return tick < 2 ? .connecting : .connected }
                return .disconnected
            }, prepare: { sequence.append("prepare"); return form }, freshOTP: { sequence.append("otp"); return otp }, validate: {
                if scenario == "hold" { throw GuardFailure.retryLimit }
                if scenario == "otp_expiry" { tick += 12 }
            }, reserve: {
                sequence.append("reserve")
                if scenario == "disk_fail" { throw HeadlessFailure.persistence }
            }, authenticate: { _, _ in
                submitted = true; sequence.append("post")
                if scenario == "auth_fail" { throw HeadlessFailure.serverRejected }
                return session
            }, start: { _ in started = true; sequence.append("start") }, phase: { _ in }, wait: { tick += 1 }, uptime: { tick })
            var success = false, failure: HeadlessFailure?
            do { _ = try await HeadlessRecoveryFlow.run(ops, timeout: 3); success = true } catch { failure = error as? HeadlessFailure }
            if scenario == "native_restart" {
                check(failure == .nativeRestarted && tick == 1, "daemon restart ends recovery before tunnel timeout")
                check(sequence.filter { $0 == "post" }.count == 1, "daemon restart does not submit credentials again")
            }
            check(success == (scenario == "success"), "flow outcome: " + scenario)
            check(submitted == ["success","auth_fail","timeout","native_restart"].contains(scenario), "POST prevented when unsafe: " + scenario)
            check(started == ["success","timeout","native_restart"].contains(scenario), "no tunnel start without session: " + scenario)
            if submitted { check(sequence.firstIndex(of: "reserve")! < sequence.firstIndex(of: "post")!, "durable budget first") }
        }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("headless-policy-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: root) }
        var policy = RecoveryPolicy(); policy.consecutiveFailures = 1
        try policy.submit(now: Date()); policy.pendingHeadlessAttempt = UUID().uuidString
        try RecoveryPolicyDisk.write(policy, root: root)
        let policyURL = root.appendingPathComponent("recovery-policy.json")
        var external = try JSONSerialization.jsonObject(with: Data(contentsOf: policyURL)) as! [String: Any]
        external["motionproAccessResultId"] = "synthetic-receipt"; external["motionproAccessResultOutcome"] = "failure"
        try JSONSerialization.data(withJSONObject: external).write(to: policyURL)
        var restored = try RecoveryPolicyDisk.read(root: root)
        check(restored.pendingHeadlessAttempt == policy.pendingHeadlessAttempt && restored.submissions.count == 1, "reservation survives process recreation")
        restored.pendingHeadlessAttempt = nil; restored.failed(); try RecoveryPolicyDisk.write(restored, root: root)
        let settled = try RecoveryPolicyDisk.read(root: root)
        let final = try JSONSerialization.jsonObject(with: Data(contentsOf: policyURL)) as! [String: Any]
        check(final["motionproAccessResultId"] as? String == "synthetic-receipt" && final["motionproAccessResultOutcome"] as? String == "failure", "manual receipts survive a policy update")
        check(final["pendingHeadlessAttempt"] == nil, "cleared reservation is not restored by metadata merge")
        check(settled.manualHold && settled.consecutiveFailures == 2 && settled.submissions.count == 1, "unknown auth outcome retains budget and failure hold")
        let attributes = try FileManager.default.attributesOfItem(atPath: root.appendingPathComponent("recovery-policy.json").path)
        check(attributes[.posixPermissions] as? Int == 0o600, "policy remains private")
        var completed = settled
        completed.pendingOfficialAttempt = "synthetic-official-attempt"
        try RecoveryPolicyDisk.write(completed, root: root)
        check(try RecoveryPolicyDisk.read(root: root).pendingOfficialAttempt != nil, "official reservation persists before launch")
        completed.pendingOfficialAttempt = nil
        try RecoveryPolicyDisk.write(completed, root: root)
        check(try RecoveryPolicyDisk.read(root: root).pendingOfficialAttempt == nil, "completed official reservation cannot reappear after restart")
        var granted = RecoveryPolicy()
        let grantTime = Date()
        try granted.submit(now: grantTime.addingTimeInterval(-20))
        try granted.submit(now: grantTime.addingTimeInterval(-10))
        granted.oneTimeHourlyLimitOverrideUntil = grantTime.addingTimeInterval(600)
        try RecoveryPolicyDisk.write(granted, root: root)
        var reserved = try RecoveryPolicyDisk.read(root: root)
        check(reserved.allowed(now: grantTime), "the disk policy retains an authorized unspent test grant")
        try reserved.submit(now: grantTime)
        try RecoveryPolicyDisk.write(reserved, root: root)
        let consumed = try RecoveryPolicyDisk.read(root: root)
        check(consumed.oneTimeHourlyLimitOverrideUntil == nil && consumed.submissions.count == 3,
              "durable reservation consumes the grant and retains all three submissions")
        check(!consumed.allowed(now: grantTime.addingTimeInterval(1)), "metadata merge cannot resurrect the consumed test grant")
        print("Headless tests passed: \(passed)")
    }
}
