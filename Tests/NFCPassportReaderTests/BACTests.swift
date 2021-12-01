//
//  File 2.swift
//  
//
//  Created by Jenny Tellne on 2021-09-27.
//

@testable import NFCPassportReader
import XCTest
import Foundation

// ICAO docs part 11 appendix D
final class BACTests: XCTestCase {
    let mrzKey = "L898902C<369080619406236"
    let kEnc = hexRepToBin("AB94FDECF2674FDFB9B391F85D7F76F2")
    let kMac = hexRepToBin("7962D9ECE03D1ACD4C76089DCE131543")
    let rndIC = hexRepToBin("4608F91988702212")
    let rndIFD = hexRepToBin("781723860C06C226")
    let kIFD = hexRepToBin("0B795240CB7049B01C19B33E32804F0B")
    let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
    var bacHandler = BACHandler()
    
    override func setUp() {
        bacHandler = BACHandler()
        bacHandler.rnd_ifd = rndIFD
        bacHandler.rnd_icc = rndIC
        bacHandler.kifd = kIFD
        bacHandler.ksenc = kEnc
        bacHandler.ksmac = kMac
    }

    func testComputeKSeed() {
        let expectedKSeed = hexRepToBin("239AB9CB282DAF66231DC5A4DF6BFBAE")
        let generatedKSeed = bacHandler.generateInitialKseed(kmrz: mrzKey)
        XCTAssertEqual(expectedKSeed, generatedKSeed)
    }
    
    func testGetBasicAccessKeys() {
        // Not using expected KEnc and KMac from Appendix D since adjusting parity is optional and not implemented here
        // Expected keys used are Ka and Kb concatenated (Without adjusted parity bits)
        let expectedKEnc = hexRepToBin("AB94FCEDF2664EDFB9B291F85D7F77F2")
        let expectedKMac = hexRepToBin("7862D9ECE03C1BCD4D77089DCF131442")
        do {
            let (generatedKEnc, generatedKMac) = try bacHandler.deriveDocumentBasicAccessKeys(mrz: mrzKey)
            XCTAssertEqual(expectedKEnc, generatedKEnc)
            XCTAssertEqual(expectedKMac, generatedKMac)
        } catch {
            XCTFail("Could not derive Document Basic Access keys")
        }
    }
    
    func testAuthAndEstablishmentOfSessionKeys_inspectionSystem_Part1() {
        let s = rndIFD + rndIC + kIFD
        let generatedEIFD = tripleDESEncrypt(key: kEnc, message: s, iv: iv)
        let expectedEIFD = hexRepToBin("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2")
        XCTAssertEqual(expectedEIFD, generatedEIFD)

        let generatedMIFD = mac(algoName: .DES, key: kMac, msg: pad(generatedEIFD, blockSize:8))
        let expectedMIFD = hexRepToBin("5F1448EEA8AD90A7")
        XCTAssertEqual(expectedMIFD, generatedMIFD)

        let generatedResponseData = generatedEIFD + generatedMIFD
        let expectedResponseData = hexRepToBin("72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F25F1448EEA8AD90A7")
        XCTAssertEqual(expectedResponseData, generatedResponseData)
    }
    
    func testAuthAndEstablishmentOfSessionKeys_inspectionSystem_Part2() {
        let responseData = hexRepToBin("46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F2F2D235D074D7449")
        // Not using expected KSEnc and KSMac from Appendix D since adjusting parity is optional and not implemented here
        // TODO: Check that these "expected" keys are actually the corresponding keys without adjusting parity bits
        let expectedKsEnc = hexRepToBin("969EC03B1CBFE9DDD11AB1FED206EBE4")
        let expectedKsMac = hexRepToBin("F0CA1E1EB5ADF208816B88DD579CC1F8")
        let expectedSSC = hexRepToBin("887022120C06C226")
        do {
            let (generatedKsEnc, generatedKsMac, ssc) = try bacHandler.sessionKeys(data: responseData)
            XCTAssertEqual(expectedKsEnc, generatedKsEnc)
            XCTAssertEqual(expectedKsMac, generatedKsMac)
            XCTAssertEqual(expectedSSC, ssc)
        } catch {
            XCTFail("Could not derive Document Basic Access keys")
        }
    }
}
