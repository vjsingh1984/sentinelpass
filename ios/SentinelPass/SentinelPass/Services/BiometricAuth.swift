//
//  BiometricAuth.swift
//  SentinelPass
//
//  Biometric authentication service
//

import Foundation
import LocalAuthentication

@MainActor
class BiometricAuth: ObservableObject {
    @Published var isAvailable: Bool = false
    @Published var biometricType: LABiometricType = .none

    private let context = LAContext()

    init() {
        checkAvailability()
    }

    private func checkAvailability() {
        var error: NSError?
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        if available {
            isAvailable = true
            biometricType = context.biometryType
        } else {
            isAvailable = false
            biometricType = .none
        }
    }

    func authenticate() async -> Bool {
        guard isAvailable else { return false }

        let reason = biometricType == .faceID
            ? "Authenticate to access your password vault"
            : "Authenticate to access your password vault"

        do {
            return try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
        } catch {
            return false
        }
    }
}

extension LABiometricType {
    var displayName: String {
        switch self {
        case .none: return "None"
        case .touchID: return "Touch ID"
        case .faceID: return "Face ID"
        @unknown default: return "Biometric"
        }
    }
}
