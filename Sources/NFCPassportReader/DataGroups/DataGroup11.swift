//
//  DataGroup11.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation
import FirebaseCrashlytics

@available(iOS 13, macOS 10.15, *)
public class DataGroup11 : DataGroup {
    
    public private(set) var fullName : String?
    public private(set) var personalNumber : String?
    public private(set) var dateOfBirth : String?
    public private(set) var placeOfBirth : String?
    public private(set) var address : String?
    public private(set) var telephone : String?
    public private(set) var profession : String?
    public private(set) var title : String?
    public private(set) var personalSummary : String?
    public private(set) var proofOfCitizenship : String?
    public private(set) var tdNumbers : String?
    public private(set) var custodyInfo : String?
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .DG11
    }
    
    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        if tag != 0x5C {
            throw NFCPassportReaderError.InvalidResponse
        }
        _ = try getNextValue()
        
        repeat {
            tag = try getNextTag()
            let val = try getNextValue()
            let stringVal = String( bytes:val, encoding:.utf8)
            if tag == 0x5F0E {
                fullName = stringVal
            } else if tag == 0x5F10 {
                personalNumber = stringVal
            } else if tag == 0x5F11 {
                placeOfBirth = stringVal
            } else if tag == 0x5F2B {
                dateOfBirth = parseDateFromBCDOrASCII(value: val)
            } else if tag == 0x5F42 {
                address = stringVal
            } else if tag == 0x5F12 {
                telephone = stringVal
            } else if tag == 0x5F13 {
                profession = stringVal
            } else if tag == 0x5F14 {
                title = stringVal
            } else if tag == 0x5F15 {
                personalSummary = stringVal
            } else if tag == 0x5F16 {
                proofOfCitizenship = stringVal
            } else if tag == 0x5F17 {
                tdNumbers = stringVal
            } else if tag == 0x5F18 {
                custodyInfo = stringVal
            }
        } while pos < data.count
    }
}
