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
public enum EyeColor: Int {
    case unspecified = 0x00
    case black = 0x01
    case blue = 0x02
    case brown = 0x03
    case gray = 0x04
    case green = 0x05
    case multiColored = 0x06
    case pink = 0x07
    case unknown = 0xFF

    public static func toEyeColor(_ num: Int) -> EyeColor {
        if let eyeColor = EyeColor(rawValue: num) {
            return eyeColor
        }

        return .unknown
    }

    public var description: String {
        switch self {
        case .unspecified:
            return "Unspecified"
        case .black:
            return "Black"
        case .blue:
            return "Blue"
        case .brown:
            return "Brown"
        case .gray:
            return "Gray"
        case .green:
            return "Green"
        case .multiColored:
            return "Multi-colored"
        case .pink:
            return "Pink"
        case .unknown:
            return "Unknown"
        }
    }
}
