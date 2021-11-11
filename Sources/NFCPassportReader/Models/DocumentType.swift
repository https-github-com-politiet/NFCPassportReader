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
    case visa
    case unknown

    // Special case
    case norwegianEmergencyPassport

    public static func toDocumentType(code: String) -> DocumentType {
        let firstLetter = code.first

        switch firstLetter {
        case "A", "C", "I", "X":
            return .nationalIdCard
        case "V":
            return .visa
        case "P":
            return .ordinaryPassport
        default:
            return .unknown
        }
    }

    public var description: String {
        switch self {
        case .ordinaryPassport: return "Passport"
        case .nationalIdCard: return "National ID Card"
        case .visa: return "Visa"
        case .unknown: return "Unknown"
        case .norwegianEmergencyPassport: return "Norwegian Emergency Passport"
        }
    }
}
