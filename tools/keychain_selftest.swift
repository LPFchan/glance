// Signed, camera-free smoke test for KeychainManager.
// Compile this with glance/KeychainManager.swift, place the executable in
// an app bundle, and sign it with the app's generated entitlements and
// matching embedded provisioning profile. See tools/README.md.
// Only unique temporary accounts are used; no stored credentials are read.

import Foundation
import Security
import LocalAuthentication

@main struct KeychainCheck {
    enum Failure: Error {
        case roundTripMismatch
        case authenticationNotEnforced
    }

    static func main() throws {
        let plain = "signing-check-" + UUID().uuidString
        let gated = "signing-check-" + UUID().uuidString
        let payload = Data("temporary signing check".utf8)
        defer {
            try? KeychainManager.delete(account: plain)
            try? KeychainManager.delete(account: gated)
        }
        try KeychainManager.save(account: plain, data: payload)
        let result = try KeychainManager.read(account: plain)
        guard result == payload else { throw Failure.roundTripMismatch }
        print("PASS: Keychain save/read")
        let access = try KeychainManager.makeUserPresenceAccessControl()
        try KeychainManager.save(account: gated, data: payload, accessControl: access)
        print("PASS: user-presence protected Keychain save")
        let context = LAContext()
        context.interactionNotAllowed = true
        do {
            _ = try KeychainManager.read(account: gated, context: context)
            throw Failure.authenticationNotEnforced
        } catch KeychainError.osStatus(let status) where status == errSecInteractionNotAllowed {
            print("PASS: protected read requires user authentication")
        }
        try KeychainManager.delete(account: plain)
        try KeychainManager.delete(account: gated)
        print("PASS: temporary items removed")
    }
}
