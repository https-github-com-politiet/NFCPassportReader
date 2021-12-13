//
//  File.swift
//  
//
//  Created by Paul Philip Mitchell on 11/11/2021.
//

import Foundation

public enum DocumentType {
    case ordinaryPassport
    case nationalIdCard
    case unknown

    // Special case
    case norwegianEmergencyPassport

    public static func toDocumentType(code: String) -> DocumentType {
        if code.first == "P" {
            return .ordinaryPassport
        }
        return .unknown
    }

    public var description: String {
        switch self {
        case .ordinaryPassport: return "Passport"
        case .nationalIdCard: return "National ID Card"
        case .unknown: return "Unknown"
        case .norwegianEmergencyPassport: return "Norwegian Emergency Passport"
        }
    }
}
