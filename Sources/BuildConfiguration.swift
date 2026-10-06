// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 MotionPro Guard contributors

// Safe source defaults. build.py substitutes local values in a temporary copy.
enum BuildConfiguration {
    static let gateway = "vpn.example.org"
    static let signingCertificateSHA1 = ""
}
