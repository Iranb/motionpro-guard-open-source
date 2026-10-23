// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation

@main struct OfficialProfileTests {
    static func main() throws {
        var checks = 0
        func check(_ condition: Bool, _ message: String) {
            precondition(condition, message); checks += 1
        }
        let cipher = VendorCipher(testKey: Data(repeating: 7, count: 16))
        let prefix = "data\\1\\"
        let originalSecond = "\"" + (try cipher.encrypt("111111")) + "\""
        let staticPassword = "\"" + (try cipher.encrypt("fictional-static-password")) + "\""
        let injected = "\"" + (try cipher.encrypt("222222")) + "\""
        let transaction = OfficialProfile.Transaction(ini_path: VendorProfile.url.path, prefix: prefix,
            originals: ["password2": originalSecond, "autoconnect": nil, "reconn_sess_invalid": "1"],
            injected: ["password2": injected, "autoconnect": "true", "reconn_sess_invalid": "0"],
            sections: ["password2": "profiles", "autoconnect": "global", "reconn_sess_invalid": "profiles"],
            created: 1234, phase: "prepared")
        var ini = INIFile(text: "[global]\nautoconnect=true\n[profiles]\n\(prefix)password=\(staticPassword)\n\(prefix)password2=\(injected)\n\(prefix)reconn_sess_invalid=0\n[other]\nsetting=unchanged\n")
        let bytes = try JSONEncoder().encode(transaction)
        let object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        check((object["originals"] as! [String: Any])["autoconnect"] is NSNull, "Python journal keeps absent originals as null")
        let decoded = try JSONDecoder().decode(OfficialProfile.Transaction.self, from: bytes)
        let restored = try decoded.restored(ini, cipher: cipher)
        check(restored.raw(section: "global", key: "autoconnect") == nil, "restore absence rather than enabling automatic login")
        check(restored.raw(section: "profiles", key: prefix + "password2") == originalSecond, "restore original encrypted OTP")
        check(restored.raw(section: "profiles", key: prefix + "password") == staticPassword, "static password stays untouched")
        check(restored.raw(section: "other", key: "setting") == "unchanged", "unrelated settings stay untouched")
        let again = try decoded.restored(restored, cipher: cipher)
        check(again.text == restored.text, "interrupted cleanup can be repeated")
        ini.set(section: "profiles", key: prefix + "password2", raw: "\"" + (try cipher.encrypt("222222")) + "\"")
        check(try decoded.restored(ini, cipher: cipher).raw(section: "profiles", key: prefix + "password2") == originalSecond,
              "Qt re-encryption of the same OTP can be restored")
        ini.set(section: "profiles", key: prefix + "password2", raw: "\"" + (try cipher.encrypt("333333")) + "\"")
        do { _ = try decoded.restored(ini, cipher: cipher); preconditionFailure("changed user setting must stop cleanup") }
        catch { checks += 1 }
        for status: VendorStatus? in [.connected, .bothConnected, .connecting, .disconnecting, .reconnecting, .desktopConnected, nil] {
            do { try OfficialProfile.requireIdle(status: status, clientRunning: false); preconditionFailure("active or unknown session cannot be modified") }
            catch { checks += 1 }
        }
        for status: VendorStatus in [.idle, .disconnected] {
            try OfficialProfile.requireIdle(status: status, clientRunning: false); checks += 1
            do { try OfficialProfile.requireIdle(status: status, clientRunning: true); preconditionFailure("live GUI caches must be preserved") }
            catch { checks += 1 }
        }
        var policy = RecoveryPolicy(); policy.submissions = [Date()]
        policy.pendingOfficialAttempt = "fictional-attempt"
        let saved = try JSONDecoder().decode(RecoveryPolicy.self, from: JSONEncoder().encode(policy))
        check(saved.pendingOfficialAttempt == policy.pendingOfficialAttempt && saved.submissions.count == 1,
              "submission reservation survives process restart")
        print("Official profile checks passed: \(checks)")
    }
}
