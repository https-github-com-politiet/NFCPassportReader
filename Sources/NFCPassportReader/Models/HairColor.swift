//
//  File.swift
//  
//
//  Created by Paul Philip Mitchell on 11/11/2021.
//

import Foundation

/** Implementation based on JMRTD, which in turn bases it on Section 5.5.4 of ISO 19794-5
 https://sourceforge.net/p/jmrtd/code/HEAD/tree/trunk/jmrtd/src/main/java/org/jmrtd/lds/iso19794/FaceImageInfo.java
 */
public enum HairColor: Int {
    case unspecified = 0x00
    case bald = 0x01
    case black = 0x02
    case blonde = 0x03
    case brown = 0x04
    case gray = 0x05
    case white = 0x06
    case red = 0x07
    case green = 0x08
    case blue = 0x09
    case unknown = 0xFF

    public static func toHairColor(_ num: Int) -> HairColor {
        if let hairColor = HairColor(rawValue: num) {
            return hairColor
        }

        return .unknown
    }

    public var description: String {
        switch self {
        case .unspecified:
            return "Unspecified"
        case .bald:
            return "Bald"
        case .black:
            return "Black"
        case .blonde:
            return "Blonde"
        case .brown:
            return "Brown"
        case .gray:
            return "Gray"
        case .white:
            return "White"
        case .red:
            return "Red"
        case .green:
            return "Green"
        case .blue:
            return "Blue"
        case .unknown:
            return "Unknown"
        }
    }
}
