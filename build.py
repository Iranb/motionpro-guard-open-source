#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 MotionPro Guard contributors
"""Compile synthetic tests and stage an app; never install, launch or enroll."""
import argparse
import json
import platform
import plistlib
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUNDLE = "org.motionproguard.app"
APP_NAME = "MotionPro Guard OSS"
VERSION = "1.6.1"


def configuration(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) != {"gateway"}:
        raise ValueError("Config must contain only gateway; never put credentials here")
    host = value["gateway"]
    if (not isinstance(host, str) or len(host) > 253
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host)
            or any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                   for label in host.split("."))):
        raise ValueError("gateway must be a DNS hostname, without URL, port or credentials")
    return host.lower()


def run(args):
    subprocess.run(args, check=True)


def write_plist(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(plistlib.dumps(value))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Local gateway-only JSON")
    parser.add_argument("--test-only", action="store_true")
    signing = parser.add_mutually_exclusive_group()
    signing.add_argument("--signing-identity", help="Your own certificate SHA-1 fingerprint")
    signing.add_argument("--ad-hoc", action="store_true", help="Explicit development build; not enrollable")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("Swift app/tests require macOS with Xcode Command Line Tools")
    if not args.test_only and not (args.signing_identity or args.ad_hoc):
        parser.error("Choose --signing-identity or explicit --ad-hoc")
    if args.signing_identity and not re.fullmatch(r"[0-9a-fA-F]{40}", args.signing_identity):
        parser.error("Use a certificate SHA-1 fingerprint, not a certificate file or private key")
    path = args.config or (ROOT / "project.example.json" if args.test_only or args.ad_hoc else ROOT / "project.local.json")
    try:
        gateway = configuration(path)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    fingerprint = args.signing_identity.upper() if args.signing_identity else ""
    sdk = subprocess.check_output(["xcrun", "--sdk", "macosx", "--show-sdk-path"], text=True).strip()
    architecture = platform.machine()
    if architecture not in ("arm64", "x86_64"):
        parser.error("Unsupported build architecture")
    with tempfile.TemporaryDirectory(prefix="motionpro-guard-oss-build-") as directory:
        stage = Path(directory)
        # Copy bytes only. No local signatures, xattrs, runtime data or binaries.
        for folder in ("Sources", "Tests"):
            for source in (ROOT / folder).glob("*.swift"):
                data = source.read_bytes()
                if not data or b"\0" in data:
                    raise ValueError("Invalid source: " + source.name)
                target = stage / folder / source.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        (stage / "Sources/BuildConfiguration.swift").write_text(
            "// Generated only in temporary build directory.\n"
            "enum BuildConfiguration {\n"
            f"    static let gateway = {json.dumps(gateway)}\n"
            f"    static let signingCertificateSHA1 = {json.dumps(fingerprint)}\n"
            "}\n")
        base = ["xcrun", "swiftc", "-parse-as-library", "-swift-version", "5", "-O",
                "-target", architecture + "-apple-macosx14.0", "-sdk", sdk,
                "-module-cache-path", str(stage / "module-cache")]
        common = [str(stage / "Sources" / name) for name in
                  ("BuildConfiguration.swift", "Shared.swift", "Credentials.swift",
                   "RecoveryFlow.swift", "OfflineOTP.swift", "Reliability.swift", "OfficialProfile.swift")]
        headless = [str(stage / "Sources" / name) for name in
                    ("HeadlessGateway.swift", "NativeTunnel.swift", "HeadlessRecovery.swift")]
        for suite, dependencies in (("CoreTests", common), ("HeadlessTests", common + headless),
                                    ("OfficialProfileTests", common), ("LoginScheduleTests", common)):
            run(base + dependencies + [str(stage / "Tests" / (suite + ".swift")), "-o", str(stage / suite)])
            run([str(stage / suite)])
        if args.test_only:
            return
        app = stage / (APP_NAME + ".app")
        ext = app / "Contents/PlugIns/MotionProGuardWidget.appex"
        (app / "Contents/MacOS").mkdir(parents=True)
        (app / "Contents/Resources").mkdir()
        (ext / "Contents/MacOS").mkdir(parents=True)
        run(base + common + headless + [str(stage / "Sources" / name) for name in
            ("Engine.swift", "OTPEnrollment.swift", "GuardApp.swift", "GatewayProbe.swift", "Watchdog.swift")]
            + ["-o", str(app / "Contents/MacOS/MotionProGuard")])
        run(base + ["-application-extension", "-Xlinker", "-e", "-Xlinker", "_NSExtensionMain",
            str(stage / "Sources/BuildConfiguration.swift"), str(stage / "Sources/Shared.swift"),
            str(stage / "Sources/GuardWidget.swift"), "-o", str(ext / "Contents/MacOS/MotionProGuardWidget")])
        info = {"CFBundleInfoDictionaryVersion": "6.0", "CFBundleShortVersionString": VERSION,
                "CFBundleVersion": "18", "CFBundleDevelopmentRegion": "zh_CN",
                "LSMinimumSystemVersion": "14.0", "CFBundleSupportedPlatforms": ["MacOSX"]}
        write_plist(app / "Contents/Info.plist", dict(info, CFBundleIdentifier=BUNDLE,
            CFBundleName=APP_NAME, CFBundleDisplayName=APP_NAME, CFBundleExecutable="MotionProGuard",
            CFBundlePackageType="APPL", LSUIElement=True, NSHighResolutionCapable=True,
            NSPrincipalClass="NSApplication", GuardGateway=gateway, GuardSigningCertificateSHA1=fingerprint,
            NSAppleEventsUsageDescription="在 VPN 已断开时重新启动 MotionPro，使用新的动态口令登录。",
            NSAppTransportSecurity={"NSExceptionDomains": {gateway: {
                "NSExceptionRequiresForwardSecrecy": False, "NSExceptionMinimumTLSVersion": "TLSv1.2",
                "NSIncludesSubdomains": False, "NSExceptionAllowsInsecureHTTPLoads": False}}},
            CFBundleURLTypes=[{"CFBundleURLName": APP_NAME, "CFBundleURLSchemes": ["motionpro-guard-oss"]}]))
        write_plist(ext / "Contents/Info.plist", dict(info, CFBundleIdentifier=BUNDLE + ".widget",
            CFBundleName=APP_NAME, CFBundleDisplayName=APP_NAME, CFBundleExecutable="MotionProGuardWidget",
            CFBundlePackageType="XPC!", NSExtension={"NSExtensionPointIdentifier": "com.apple.widgetkit-extension"}))
        write_plist(stage / "widget.entitlements", {"com.apple.security.app-sandbox": True})
        write_plist(stage / "host.entitlements", {"com.apple.security.automation.apple-events": True})
        identity = fingerprint or "-"
        run(["codesign", "--force", "--sign", identity, "--timestamp=none", "--entitlements",
             str(stage / "widget.entitlements"), str(ext)])
        run(["codesign", "--force", "--sign", identity, "--timestamp=none", "--entitlements",
             str(stage / "host.entitlements"), str(app)])
        run(["codesign", "--verify", "--deep", "--strict", str(app)])
        if fingerprint:
            requirement = f'=identifier "{BUNDLE}" and certificate leaf = H"{fingerprint}"'
            run(["codesign", "--verify", "--strict", "-R", requirement, str(app)])
        output = args.output.resolve()
        output.mkdir(parents=True, exist_ok=True)
        target = output / app.name
        if target.exists():
            raise ValueError("Output app already exists; choose a fresh --output directory")
        shutil.copytree(app, target, copy_function=shutil.copy)
        # File-provider metadata is not part of a newly built signed bundle.
        # Clean only this output; installed and downloaded apps are untouched.
        run(["xattr", "-cr", str(target)])
        run(["codesign", "--verify", "--deep", "--strict", str(target)])
        print("Built and verified:", target)
        print("App staged only; no login jobs, Keychain changes or VPN operations performed.")


if __name__ == "__main__":
    main()
