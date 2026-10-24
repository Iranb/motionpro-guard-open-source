// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

import Foundation
import SystemConfiguration
import Darwin

struct ConnectionObservationWindow {
    let deadline: TimeInterval

    init(startedAt: TimeInterval) { deadline = startedAt + 180 }

    func shouldContinue(state: String, reason: String, uptime: TimeInterval) -> Bool {
        guard uptime < deadline else { return false }
        return ["disconnected", "connecting"].contains(state)
            || (state == "waiting" && reason == "retry_backoff")
            || (state == "unknown" && reason == "vendor_state_unknown")
    }
}

/// Vendor text stays in memory. A matching line only requests a live status check.
struct ConnectionEventLines {
    private var partial = Data()
    mutating func consume(_ bytes: Data) -> Bool {
        partial.append(bytes)
        var signal = false
        while let newline = partial.firstIndex(of: 10) {
            let line = String(decoding: partial[..<newline], as: UTF8.self).lowercased()
            signal = signal || ["disconnect", "logout", "session invalid", "session expired",
                                "session timeout", "login successfully, method name:"]
                .contains(where: line.contains)
            partial.removeSubrange(...newline)
        }
        if partial.count > 65536 { partial.removeAll() }
        return signal
    }
}

/// File notifications survive normal log rotation without a periodic read loop.
final class VendorLogEvents {
    private let root: URL
    private let signal: () -> Void
    private var directory: DispatchSourceFileSystemObject?
    private var files: [String: DispatchSourceFileSystemObject] = [:]

    init(root: URL, signal: @escaping () -> Void) { self.root = root; self.signal = signal }

    @discardableResult func start() -> Bool {
        guard directory == nil else { return true }
        let fd = open(root.path, O_EVTONLY)
        guard fd >= 0 else { return false }
        let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: .write, queue: .main)
        source.setEventHandler { [weak self] in self?.refresh() }
        source.setCancelHandler { close(fd) }
        directory = source; source.resume(); refresh(readNewContents: false)
        return true
    }

    private func refresh(readNewContents: Bool = true) {
        let paths = (try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
        for path in paths where path.pathExtension == "log" && files[path.path] == nil {
            guard let reader = try? FileHandle(forReadingFrom: path) else { continue }
            let fd = open(path.path, O_EVTONLY)
            guard fd >= 0 else { try? reader.close(); continue }
            // Existing history is not a new event. New writes use this descriptor's offset.
            let end = (try? reader.seekToEnd()) ?? 0
            if readNewContents { try? reader.seek(toOffset: end > 65536 ? end - 65536 : 0) }
            var parser = ConnectionEventLines()
            if readNewContents, let bytes = try? reader.readToEnd(), parser.consume(bytes) {
                DispatchQueue.main.async { [weak self] in self?.signal() }
            }
            let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd,
                eventMask: [.write, .rename, .delete], queue: .main)
            source.setEventHandler { [weak self] in
                guard let self else { return }
                var changed = false
                do {
                    let offset = try reader.offset(), end = try reader.seekToEnd()
                    if end < offset { parser = ConnectionEventLines() }
                    try reader.seek(toOffset: end < offset ? 0 : offset)
                    while let bytes = try reader.read(upToCount: 65536), !bytes.isEmpty {
                        changed = parser.consume(bytes) || changed
                    }
                } catch { }
                if source.data.contains(.rename) || source.data.contains(.delete) {
                    self.files.removeValue(forKey: path.path)?.cancel()
                    self.refresh()
                }
                if changed { self.signal() }
            }
            source.setCancelHandler { close(fd); try? reader.close() }
            files[path.path] = source; source.resume()
        }
    }

    func stop() {
        directory?.cancel(); directory = nil
        for source in files.values { source.cancel() }
        files.removeAll()
    }
    deinit { stop() }
}

/// Native callbacks detect interface removal and network restoration while locked.
final class ConnectionEvents {
    private var store: SCDynamicStore?
    private var logs: VendorLogEvents?
    private let signal: (String) -> Void
    init(signal: @escaping (String) -> Void) { self.signal = signal }

    @discardableResult func start() -> Bool {
        let logs = VendorLogEvents(root: URL(fileURLWithPath: "/private/var/log/MotionPro")) { [weak self] in
            self?.signal("vendor_log_event")
        }
        self.logs = logs
        let logReady = logs.start()
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                           retain: nil, release: nil, copyDescription: nil)
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            Unmanaged<ConnectionEvents>.fromOpaque(info).takeUnretainedValue().signal("network_interface_event")
        }
        guard let store = SCDynamicStoreCreate(nil, "MotionProGuardConnectionEvents" as CFString, callback, &context) else {
            return logReady
        }
        let patterns = ["State:/Network/Interface/.*/IPv4", "State:/Network/Interface/.*/IPv6",
                        "State:/Network/Global/IPv4", "State:/Network/Global/IPv6"] as CFArray
        let networkReady = SCDynamicStoreSetNotificationKeys(store, nil, patterns) &&
            SCDynamicStoreSetDispatchQueue(store, .main)
        if networkReady { self.store = store }
        return networkReady || logReady
    }
    deinit {
        if let store { SCDynamicStoreSetDispatchQueue(store, nil) }
        logs?.stop()
    }
}
