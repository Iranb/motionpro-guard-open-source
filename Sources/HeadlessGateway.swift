// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation

enum HeadlessFailure: String, Error, LocalizedError {
    case formChanged, unsafeRedirect, responseTooLarge, transport, serverRejected
    case sessionMissing, sessionExpired, nativeUnavailable, nativeChanged, nativeProtocol
    case persistence, interrupted, timeout, offlineRequired, nativeRestarted
    var errorDescription: String? {
        switch self {
        case .formChanged: return "网关认证表单或挑战已改变；未提交登录"
        case .unsafeRedirect: return "认证跳转不符合已核对的 HTTPS 流程；停止本次尝试"
        case .responseTooLarge: return "网关响应超过限制；停止本次尝试"
        case .transport: return "HTTPS 请求未完成；不会自动重复提交本次口令"
        case .serverRejected: return "网关拒绝本次认证；请解锁后检查静态密码和 OTP"
        case .sessionMissing: return "未取得唯一有效的认证会话；未启动隧道"
        case .sessionExpired: return "认证会话已过期；未启动隧道"
        case .nativeUnavailable: return "官方后台隧道服务不可读；未提交登录"
        case .nativeChanged: return "官方服务版本或身份已改变；需重新核对无窗口接口"
        case .nativeProtocol: return "官方服务返回未知格式；停止后台恢复"
        case .nativeRestarted: return "官方后台隧道服务已重启；停止本次恢复，未重复提交登录"
        case .persistence: return "无法可靠保存尝试记录；后台登录已暂停"
        case .interrupted: return "网络、时钟或人工控制状态已变化；停止本次恢复"
        case .timeout: return "后台隧道未在两分钟内建立；本次尝试已结束"
        case .offlineRequired: return "锁屏恢复需要已验证的本地令牌；不使用窗口取码"
        }
    }
}

struct GatewayReply {
    let url: URL
    let status: Int
    let headers: [String: String]
    let body: Data
}

/// Redirects and authentication retries are handled explicitly. Response bodies
/// and cookies remain in this instance's memory; URLCache and shared cookie
/// storage are disabled. No HTTP dump or raw exception is logged.
final class PrivateGatewayTransport: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<GatewayReply, Error>?
    private var response: HTTPURLResponse?
    private var bytes = Data()
    private var failure: Error?
    private(set) var failureCode: Int?
    private lazy var session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpCookieStorage = nil; config.httpShouldSetCookies = false
        config.urlCredentialStorage = nil; config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 25; config.waitsForConnectivity = false
        config.connectionProxyDictionary = [:]
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()
    func close() { session.invalidateAndCancel() }
    func send(_ request: URLRequest) async throws -> GatewayReply {
        try await withCheckedThrowingContinuation { target in
            lock.lock()
            guard continuation == nil else { lock.unlock(); target.resume(throwing: HeadlessFailure.interrupted); return }
            continuation = target; response = nil; bytes.removeAll(keepingCapacity: false); failure = nil; failureCode = nil
            lock.unlock()
            session.dataTask(with: request).resume()
        }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Retain platform TLS verification. Never respond to a second HTTP
        // credential challenge with the static password or an old OTP.
        completionHandler(challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust
            ? .performDefaultHandling : .cancelAuthenticationChallenge, nil)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard let http = response as? HTTPURLResponse, http.expectedContentLength <= 262_144 else {
            failure = HeadlessFailure.responseTooLarge; completionHandler(.cancel); return
        }
        self.response = http; completionHandler(.allow)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock(); defer { lock.unlock() }
        guard bytes.count + data.count <= 262_144 else {
            failure = HeadlessFailure.responseTooLarge; dataTask.cancel(); return
        }
        bytes.append(data)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        lock.lock()
        let target = continuation; continuation = nil
        let result: Result<GatewayReply, Error>
        let http = response ?? task.response as? HTTPURLResponse
        if let failure { result = .failure(failure) }
        else if let error {
            failureCode = (error as? URLError)?.code.rawValue
            result = .failure(HeadlessFailure.transport)
        }
        else if let response = http, let url = response.url {
            var headers: [String: String] = [:]
            for (key, value) in response.allHeaderFields { headers[String(describing: key).lowercased()] = String(describing: value) }
            result = .success(GatewayReply(url: url, status: response.statusCode, headers: headers, body: bytes))
        } else { result = .failure(HeadlessFailure.transport) }
        bytes.removeAll(keepingCapacity: false); response = nil; failure = nil
        lock.unlock(); target?.resume(with: result)
    }
}

struct HeadlessSession {
    // Deliberately not Codable or CustomStringConvertible. Never persist it.
    let cookie: String
    let acquiredAt: TimeInterval
    let expiresAt: Date?
    func requireFresh(now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) throws {
        guard uptime >= acquiredAt, uptime - acquiredAt < 60,
              expiresAt == nil || expiresAt! > now.addingTimeInterval(10) else { throw HeadlessFailure.sessionExpired }
    }
}

struct GatewayLoginForm {
    static let endpoint = URL(string: "https://\(GuardIdentity.host)/prx/000/http/localhost/login")!
    let fields: [String: String]
    static func parse(_ body: Data) throws -> Self {
        guard let html = String(data: body, encoding: .utf8), html.utf8.count <= 262_144 else { throw HeadlessFailure.formChanged }
        let input = try NSRegularExpression(pattern: #"(?is)<input\b[^>]*>"#)
        let attrs = try NSRegularExpression(pattern: #"([a-zA-Z_][\w-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#)
        var fields: [String: String] = [:]
        for match in input.matches(in: html, range: NSRange(html.startIndex..., in: html)) {
            let tag = String(html[Range(match.range, in: html)!]); var values: [String: String] = [:]
            for attr in attrs.matches(in: tag, range: NSRange(tag.startIndex..., in: tag)) {
                let key = String(tag[Range(attr.range(at: 1), in: tag)!]).lowercased()
                let range = (2...4).first { attr.range(at: $0).location != NSNotFound }!
                values[key] = String(tag[Range(attr.range(at: range), in: tag)!])
            }
            guard let name = values["name"] else { continue }
            if ["uname", "pwd", "pwd1", "pwd2", "method", "hardwareid", "validcode", "valid"].contains(name) {
                guard fields[name] == nil else { throw HeadlessFailure.formChanged }
                fields[name] = (values["value"] ?? "").replacingOccurrences(of: "&amp;", with: "&")
            }
        }
        guard ["uname", "pwd", "pwd1"].allSatisfy({ fields[$0] != nil }),
              fields["method"] == nil || fields["method"] == "radius",
              (fields["validcode"] ?? "").isEmpty, (fields["valid"] ?? "").isEmpty,
              !html.lowercased().contains("captcha") else { throw HeadlessFailure.formChanged }
        return Self(fields: fields)
    }
    func body(credentials: Credentials, reading: OTPReading) throws -> Data {
        guard credentials.host == GuardIdentity.host, !credentials.username.isEmpty, !credentials.password.isEmpty,
              reading.freshEnough, reading.code.range(of: #"^[0-9]{6}$"#, options: .regularExpression) != nil else { throw GuardFailure.invalidCredentials }
        var values = ["method": "radius", "uname": credentials.username, "pwd": credentials.password,
                      "pwd1": reading.code, "pwd2": "", "hardwareid": fields["hardwareid"] ?? ""]
        if fields["validcode"] != nil { values["validcode"] = "" }
        func encode(_ value: String) -> String {
            value.utf8.map { c in
                if (65...90).contains(c) || (97...122).contains(c) || (48...57).contains(c) || [45,46,95,126].contains(c) { return String(UnicodeScalar(c)) }
                return String(format: "%%%02X", c)
            }.joined()
        }
        return Data(values.keys.sorted().map { encode($0) + "=" + encode(values[$0]!) }.joined(separator: "&").utf8)
    }
}

final class HeadlessGateway {
    typealias Transport = (URLRequest) async throws -> GatewayReply
    private let transport: Transport
    private var cookies: [HTTPCookie] = []
    private var posted = false
    init(transport: @escaping Transport) { self.transport = transport }
    static func sameOrigin(_ url: URL) -> Bool {
        url.scheme == "https" && url.host?.lowercased() == GuardIdentity.host && (url.port ?? 443) == 443
            && url.user == nil && url.password == nil
    }
    private func capture(_ response: GatewayReply) throws {
        guard Self.sameOrigin(response.url) else { throw HeadlessFailure.unsafeRedirect }
        // HTTPCookie's parser on macOS requires the canonical Set-Cookie key.
        // HTTPURLResponse header casing is not stable across HTTP versions.
        var headers = response.headers
        if let entry = headers.first(where: { $0.key.lowercased() == "set-cookie" }) { headers["Set-Cookie"] = entry.value }
        for cookie in HTTPCookie.cookies(withResponseHeaderFields: headers, for: response.url) {
            let domain = cookie.domain.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
            guard domain == GuardIdentity.host || GuardIdentity.host.hasSuffix("." + domain) else { continue }
            cookies.removeAll { $0.name == cookie.name && $0.domain == cookie.domain && $0.path == cookie.path }
            if !cookie.isSessionOnly && (cookie.expiresDate ?? .distantPast) <= Date() { continue }
            cookies.append(cookie)
        }
    }
    private func request(_ url: URL, method: String = "GET", body: Data? = nil) throws -> URLRequest {
        guard Self.sameOrigin(url) else { throw HeadlessFailure.unsafeRedirect }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.httpMethod = method; request.httpBody = body
        request.setValue("MotionProGuard/1.4", forHTTPHeaderField: "User-Agent")
        request.setValue("https://\(GuardIdentity.host)", forHTTPHeaderField: "Origin")
        request.setValue(GatewayLoginForm.endpoint.absoluteString + "/index.html", forHTTPHeaderField: "Referer")
        if method == "POST" { request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type") }
        let eligible = cookies.filter { ($0.expiresDate ?? .distantFuture) > Date() && url.path.hasPrefix($0.path) }
        if !eligible.isEmpty { request.setValue(HTTPCookie.requestHeaderFields(with: eligible)["Cookie"], forHTTPHeaderField: "Cookie") }
        return request
    }
    private func follow(_ initial: GatewayReply) async throws -> GatewayReply {
        var response = initial
        for _ in 0..<5 {
            try capture(response)
            guard (300...399).contains(response.status) else { return response }
            // 307/308 could replay the credential POST. Stop even when same-host.
            guard [301,302,303].contains(response.status), let location = response.headers["location"],
                  let next = URL(string: location, relativeTo: response.url)?.absoluteURL, Self.sameOrigin(next) else { throw HeadlessFailure.unsafeRedirect }
            response = try await transport(request(next))
        }
        throw HeadlessFailure.unsafeRedirect
    }
    func prepare() async throws -> GatewayLoginForm {
        guard !posted else { throw HeadlessFailure.interrupted }
        let initial = try await transport(request(GatewayLoginForm.endpoint))
        let response = try await follow(initial)
        guard response.status == 200 else { throw HeadlessFailure.formChanged }
        // Discard a session cookie that appeared before this attempt's POST.
        cookies.removeAll { $0.name.hasPrefix("ANsession") }
        return try GatewayLoginForm.parse(response.body)
    }
    static func sessionCookie(_ cookies: [HTTPCookie], now: Date = Date()) throws -> (String, Date?) {
        let candidates = cookies.filter {
            let domain = $0.domain.trimmingCharacters(in: CharacterSet(charactersIn: ".")).lowercased()
            return (domain == GuardIdentity.host || GuardIdentity.host.hasSuffix("." + domain)) && ($0.expiresDate ?? .distantFuture) > now.addingTimeInterval(10)
                && $0.name.range(of: #"^ANsession[0-9]*$"#, options: .regularExpression) != nil
                && $0.value.utf8.count >= 16 && $0.value.utf8.count < 4000
                && $0.value.utf8.allSatisfy { (33...126).contains($0) && ![34,59,92].contains($0) }
        }
        let unique = Set(candidates.map { $0.name + "=" + $0.value })
        guard unique.count == 1, let value = unique.first else { throw HeadlessFailure.sessionMissing }
        return (value, candidates.compactMap(\.expiresDate).min())
    }
    func authenticate(form: GatewayLoginForm, credentials: Credentials, reading: OTPReading) async throws -> HeadlessSession {
        guard !posted else { throw HeadlessFailure.interrupted }
        let body = try form.body(credentials: credentials, reading: reading)
        posted = true
        let initial = try await transport(request(GatewayLoginForm.endpoint, method: "POST", body: body))
        let response = try await follow(initial)
        guard response.status == 200 else { throw HeadlessFailure.serverRejected }
        let text = String(decoding: response.body, as: UTF8.self)
        if text.contains("_AN_str_errormsg_login") || text.contains("login failed") { throw HeadlessFailure.serverRejected }
        let value = try Self.sessionCookie(cookies)
        return HeadlessSession(cookie: value.0, acquiredAt: ProcessInfo.processInfo.systemUptime, expiresAt: value.1)
    }
}
