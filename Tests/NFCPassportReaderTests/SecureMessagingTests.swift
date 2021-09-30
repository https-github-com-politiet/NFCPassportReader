//
//  File.swift
//  
//
//  Created by Jenny Tellne on 2021-09-30.
//

@testable import NFCPassportReader
import XCTest
import Foundation
import NFCPassportReader

final class SecureMessagingTests: XCTestCase {
    let smKeyGenerator = SecureMessagingSessionKeyGenerator()
    
    func testGetHashWithDifferentAlgorithms() {
        let kmrz = "L898902C<369080619406236"
        let data = [UInt8](kmrz.data(using:.utf8)!)
        let hashedObjects: [String: [UInt8]] = [
            "sha1": hexRepToBin("239AB9CB282DAF66231DC5A4DF6BFBAEDF477565"),
            "sha256": hexRepToBin("13A1CDBFA0941F6F1C49BACDC31F354201B783D77D30215B98B7551AEBCC57A5"),
            "sha384": hexRepToBin("5E41BAA50B6E50005827E43500B945BAC8A93F8236C51373208B2DA43620C0F85EDCFE980AFDEEDAD24065F4A9E34E1F"),
            "sha512": hexRepToBin("C39EAF646BA2E5E466386D9B1F7FA079702B56DB15757092542C81005F49727BA21B5538F0B519002EADC8BFFF561C9BD2CBFC37D5FFD556B1A0FB40EEDAC97E")
        ]
        
        for hashedObject in hashedObjects {
            XCTAssertEqual(hashedObject.value, try smKeyGenerator.getHash(algo: hashedObject.key, dataElements: [Data(data)]))
        }
    }
    
    func testGetHashWithInvalidAlgorithmFails() {
        let kmrz = "L898902C<369080619406236"
        let data = [UInt8](kmrz.data(using:.utf8)!)
        let smKeyGenerator = SecureMessagingSessionKeyGenerator()
        XCTAssertThrowsError(try smKeyGenerator.getHash(algo: "Invalid", dataElements: [Data(data)])) { error in
            guard let error = error as? NFCPassportReaderError else {
                return XCTFail("Unexpected error returned")
            }
            XCTAssertEqual(error.value, "InvalidHashAlgorithmSpecified")
        }
    }
    
    func testReturnSha1ForValidDigestAlgAndKeyLength() {
        let cipherAlgsKeyLengths: [String: [Int]] = [
            "DESede": [128, 192, 256, 1],
            "AES-128": [128, 192, 256, 1],
            "AES": [128],
        ]
        
        for cipherAlg in cipherAlgsKeyLengths {
            for keyLength in cipherAlg.value {
                XCTAssertEqual("SHA1",try  smKeyGenerator.inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg: cipherAlg.key, keyLength: keyLength))
            }
        }
    }
    
    func testReturnSha256ForValidDigestAlgAndKeyLength() {
        let cipherAlgsKeyLengths: [String: [Int]] = [
            "AES-256": [128, 192, 256, 1],
            "AES-192": [128, 192, 256, 1],
            "AES": [192, 256],
        ]
        
        for cipherAlg in cipherAlgsKeyLengths {
            for keyLength in cipherAlg.value {
                XCTAssertEqual("SHA256",try  smKeyGenerator.inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg: cipherAlg.key, keyLength: keyLength))
            }
        }
    }
    
    func testThrowsForInvalidDigestAlgAndKeyLength() {
        let cipherAlgsKeyLengths: [String: [Int]] = [
            "InvalidAlg": [128, 192, 256, 1],
            "AES": [1, 257, -100],
        ]

        for cipherAlg in cipherAlgsKeyLengths {
            for keyLength in cipherAlg.value {
                XCTAssertThrowsError(try smKeyGenerator.inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg: cipherAlg.key, keyLength: keyLength)) { error in
                    guard case NFCPassportReaderError.InvalidDataPassed(let message) = error else {
                        return XCTFail()
                    }
                    
                    XCTAssertEqual(message, "Unsupported cipher algorithm or key length")
                }
            }
        }
    }
    
    func testDeriveKeyValidCipherAlgInvalidKeyLengthThrows() {
        let kseed = generateRandomUInt8Array(16)
        let AEScipherAlgs = ["AES-128", "AES-256", "AES-192"]
        let smKeyGenerator = SecureMessagingSessionKeyGenerator()
        
        XCTAssertThrowsError(try smKeyGenerator.deriveKey(keySeed: kseed, cipherAlgName: "DESede", keyLength: 1, mode: .ENC_MODE)) { error in
            guard case NFCPassportReaderError.InvalidDataPassed(let message) = error else {
                return XCTFail()
            }
            XCTAssertEqual(message, "Can only use DESede with 128-but key length")
        }
        
        for cipherAlg in AEScipherAlgs {
            XCTAssertThrowsError(try smKeyGenerator.deriveKey(keySeed: kseed, cipherAlgName: cipherAlg, keyLength: 1, mode: .ENC_MODE)) { error in
                guard case NFCPassportReaderError.InvalidDataPassed(let message) = error else {
                    return XCTFail()
                }
                XCTAssertEqual(message, "Can only use AES with 128-bit, 192-bit key or 256-bit length")
            }
        }
        
    }
}
