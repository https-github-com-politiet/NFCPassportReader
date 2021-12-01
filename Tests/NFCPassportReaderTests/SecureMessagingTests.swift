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
#if (canImport(CoreNFC))
import CoreNFC
#endif

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

    #if (canImport(CoreNFC))
    // ICAO docs part 11 appendix D
    func testSecureMessagingSpec_Part1() {
        let ksEnc = hexRepToBin("979EC13B1CBFE9DCD01AB0FED307EAE5")
        let ksMac = hexRepToBin("F1CB1F1FB5ADF208806B89DC579DC1F8")
        let ssc = hexRepToBin("887022120C06C226")
        let sm = SecureMessaging(ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
        
        let data: [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E]
        let apdu = NFCISO7816APDU(data: Data(data))!
        // Step a
        let paddedCommandHeader = sm.maskClassAndPad(apdu: apdu)
        let expectedPaddedHeader = hexRepToBin("0CA4020C80000000")
        XCTAssertEqual(expectedPaddedHeader, paddedCommandHeader)
        // Step b-c
        let generatedEncryptedData = sm.padAndEncryptData(apdu)
        let expectedEncryptedData = hexRepToBin("6375432908C044F6")
        XCTAssertEqual(expectedEncryptedData, generatedEncryptedData)
        // Step d
        let generatedDo87 = try! sm.buildD087(apdu: apdu)
        let expectedDo87 = hexRepToBin("8709016375432908C044F6")
        XCTAssertEqual(expectedDo87, generatedDo87)
        // Step e
        let generatedM = paddedCommandHeader + generatedDo87
        let expectedM = hexRepToBin("0CA4020C800000008709016375432908C044F6")
        XCTAssertEqual(generatedM, expectedM)
        // Step f-h
        let protectedApdu = try! sm.protect(apdu: apdu)
        let expectedProtectedApdu = NFCISO7816APDU(data: Data(
            hexRepToBin("0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800")))!
        XCTAssertEqual(expectedProtectedApdu.data, protectedApdu.data)
        // Step i
        let rApdu = ResponseAPDU(data: hexRepToBin("990290008E08FA855A5D4C50A8ED9000"), sw1: 0x90, sw2: 0x00)
        XCTAssertNoThrow(try sm.unprotect(rapdu: rApdu))
    }
    #endif

    #if (canImport(CoreNFC))
    // ICAO docs part 11 appendix D
    func testSecureMessagingSpec_Part2() {
        let ksEnc = hexRepToBin("979EC13B1CBFE9DCD01AB0FED307EAE5")
        let ksMac = hexRepToBin("F1CB1F1FB5ADF208806B89DC579DC1F8")
        let ssc = hexRepToBin("887022120C06C228")
        let sm = SecureMessaging(ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
        
        let data: [UInt8] = [0x00, 0xB0, 0x00, 0x00, 0x04]
        let apdu = NFCISO7816APDU(data: Data(data))!
        // Step a
        let paddedCommandHeader = sm.maskClassAndPad(apdu: apdu)
        let expectedPaddedHeader = hexRepToBin("0CB0000080000000")
        XCTAssertEqual(expectedPaddedHeader, paddedCommandHeader)
        // Step b
        let generatedDo97 = try! sm.buildD097(apdu: apdu)
        let expectedDo97 = hexRepToBin("970104")
        XCTAssertEqual(expectedDo97, generatedDo97)
        // Step c
        let generatedM = paddedCommandHeader + generatedDo97
        let expectedM = hexRepToBin("0CB0000080000000970104")
        XCTAssertEqual(generatedM, expectedM)
        // Step d-f
        let protectedApdu = try! sm.protect(apdu: apdu)
        let expectedProtectedApdu = NFCISO7816APDU(data: Data(
            hexRepToBin("0CB000000D9701048E08ED6705417E96BA5500")))!
        XCTAssertEqual(expectedProtectedApdu.data!, protectedApdu.data!)
        // Step h
        let rApdu = ResponseAPDU(data: hexRepToBin("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED9000"), sw1: 0x90, sw2: 0x00)
        let unprotectedApdu = try! sm.unprotect(rapdu: rApdu)
        // Step i
        let expectedDecryptedDo87 = hexRepToBin("60145F01")
        XCTAssertEqual(unprotectedApdu.data, expectedDecryptedDo87)
        // Step j
        // TODO: Determine length of structure: L = '14' + 2 = 22 bytes
    }
    #endif

    #if (canImport(CoreNFC))
    // ICAO docs part 11 appendix D
    func testSecureMessagingSpec_Part3() {
        let ksEnc = hexRepToBin("979EC13B1CBFE9DCD01AB0FED307EAE5")
        let ksMac = hexRepToBin("F1CB1F1FB5ADF208806B89DC579DC1F8")
        let ssc = hexRepToBin("887022120C06C22A")
        let sm = SecureMessaging(ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
        
        let data: [UInt8] = [0x00, 0xB0, 0x00, 0x04, 0x12]
        let apdu = NFCISO7816APDU(data: Data(data))!
        // Step a
        let paddedCommandHeader = sm.maskClassAndPad(apdu: apdu)
        let expectedPaddedHeader = hexRepToBin("0CB0000480000000")
        XCTAssertEqual(expectedPaddedHeader, paddedCommandHeader)
        // Step b
        let generatedDo97 = try! sm.buildD097(apdu: apdu)
        let expectedDo97 = hexRepToBin("970112")
        XCTAssertEqual(expectedDo97, generatedDo97)
        // Step c
        let generatedM = paddedCommandHeader + generatedDo97
        let expectedM = hexRepToBin("0CB0000480000000970112")
        XCTAssertEqual(generatedM, expectedM)
        // Step d-f
        let protectedApdu = try! sm.protect(apdu: apdu)
        let expectedProtectedApdu = NFCISO7816APDU(data: Data(
            hexRepToBin("0CB000040D9701128E082EA28A70F3C7B53500")))!
        XCTAssertEqual(expectedProtectedApdu.data!, protectedApdu.data!)
        // Step g-h
        let rApdu = ResponseAPDU(data: hexRepToBin("871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A990290008E08C8B2787EAEA07D749000"), sw1: 0x90, sw2: 0x00)
        let unprotectedApdu = try! sm.unprotect(rapdu: rApdu)
        // Step i
        let expectedDecryptedDo87 = hexRepToBin("04303130365F36063034303030305C026175")
        XCTAssertEqual(unprotectedApdu.data, expectedDecryptedDo87)
    }
    #endif
}
