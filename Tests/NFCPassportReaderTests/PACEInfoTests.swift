//
//  PACEInfoTests.swift
//  NFCPassportReaderAppTests
//
//  Created by Paul Philip Mitchell on 29/09/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

import Foundation
import XCTest
import OpenSSL

@testable import NFCPassportReader

final class PACEInfoTests: XCTestCase {
    func testPACEInfo() {
        let paceInfo = PACEInfo(oid: PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, version: 2, parameterId: PACEInfo.PARAM_ID_ECP_NIST_P256_R1)

        XCTAssertEqual(PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256, paceInfo.getObjectIdentifier())
        XCTAssertEqual("id-PACE-ECDH-GM-AES-CBC-CMAC-256", paceInfo.getProtocolOIDString())
        XCTAssertEqual(PACEInfo.PARAM_ID_ECP_NIST_P256_R1, paceInfo.getParameterId())
        XCTAssertEqual(12, paceInfo.getParameterId())
        XCTAssertEqual(2, paceInfo.getVersion())
    }

    func testPACEInfoGetProtocolOIDString() {
        testPACEInfoGetProtocolOIDString(str: "id-PACE-DH-GM-3DES-CBC-CBC", oid: PACEInfo.ID_PACE_DH_GM_3DES_CBC_CBC);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-DH-GM-AES-CBC-CMAC-128", oid: PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-DH-GM-AES-CBC-CMAC-192", oid: PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-DH-GM-AES-CBC-CMAC-256", oid: PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-DH-IM-3DES-CBC-CBC", oid: PACEInfo.ID_PACE_DH_IM_3DES_CBC_CBC);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-DH-IM-AES-CBC-CMAC-128", oid: PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-DH-IM-AES-CBC-CMAC-192", oid: PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-DH-IM-AES-CBC-CMAC-256", oid: PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-GM-3DES-CBC-CBC", oid: PACEInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-GM-AES-CBC-CMAC-128", oid: PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-GM-AES-CBC-CMAC-192", oid: PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-GM-AES-CBC-CMAC-256", oid: PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-IM-3DES-CBC-CBC", oid: PACEInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-IM-AES-CBC-CMAC-128", oid: PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-IM-AES-CBC-CMAC-192", oid: PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-IM-AES-CBC-CMAC-256", oid: PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-CAM-AES-CBC-CMAC-128", oid: PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-CAM-AES-CBC-CMAC-192", oid: PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192);
        testPACEInfoGetProtocolOIDString(str: "id-PACE-ECDH-CAM-AES-CBC-CMAC-256", oid: PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256);
    }

    func testGetParameterSpec() {
        for stdDomainParam in 0...2 {
            testGetParameterSpec(stdDomainParam, shouldThrow: false)
        }

        for stdDomainParam in 3...7 {
            testGetParameterSpec(stdDomainParam, shouldThrow: true)
        }

        for stdDomainParam in 8...18 {
            testGetParameterSpec(stdDomainParam, shouldThrow: false)
        }
    }

    func testGetMappingType() {
        let oidMappingType: [String: PACEMappingType] = [
            PACEInfo.ID_PACE_DH_GM_3DES_CBC_CBC: .GM,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128: .GM,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192: .GM,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256: .GM,
            PACEInfo.ID_PACE_DH_IM_3DES_CBC_CBC: .IM,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128: .IM,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192: .IM,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256: .IM,
            PACEInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC: .GM,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128: .GM,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192: .GM,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256: .GM,
            PACEInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC: .IM,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128: .IM,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192: .IM,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256: .IM,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: .CAM,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: .CAM,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: .CAM
        ]

        for o in oidMappingType {
            let paceInfo = PACEInfo(oid: o.key, version: 2, parameterId: 0)
            XCTAssertNoThrow(try paceInfo.getMappingType())
            XCTAssertEqual(try! paceInfo.getMappingType(), o.value)
        }

        let paceInfo = PACEInfo(oid: "InvalidTestOID", version: 2, parameterId: 0)
        XCTAssertThrowsError(try paceInfo.getMappingType())
    }

    func testGetKeyAgreementAlgorithm() {
        let oidKeyAgreement: [String: String] = [
            PACEInfo.ID_PACE_DH_GM_3DES_CBC_CBC: "DH",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128: "DH",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192: "DH",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256: "DH",
            PACEInfo.ID_PACE_DH_IM_3DES_CBC_CBC: "DH",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128: "DH",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192: "DH",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256: "DH",
            PACEInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC: "ECDH",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128: "ECDH",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192: "ECDH",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256: "ECDH",
            PACEInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC: "ECDH",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128: "ECDH",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192: "ECDH",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256: "ECDH",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: "ECDH",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: "ECDH",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: "ECDH"
        ]

        for o in oidKeyAgreement {
            let paceInfo = PACEInfo(oid: o.key, version: 2, parameterId: 0)
            XCTAssertNoThrow(try paceInfo.getKeyAgreementAlgorithm())
            XCTAssertEqual(try! paceInfo.getKeyAgreementAlgorithm(), o.value)
        }

        let paceInfo = PACEInfo(oid: "InvalidTestOID", version: 2, parameterId: 0)
        XCTAssertThrowsError(try paceInfo.getKeyAgreementAlgorithm())
    }

    func testGetCipherAlgorithm() {
        let oidCipherAlgorithm: [String: String] = [
            PACEInfo.ID_PACE_DH_GM_3DES_CBC_CBC: "DESede",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128: "AES",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192: "AES",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256: "AES",
            PACEInfo.ID_PACE_DH_IM_3DES_CBC_CBC: "DESede",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128: "AES",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192: "AES",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256: "AES",
            PACEInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC: "DESede",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128: "AES",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192: "AES",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256: "AES",
            PACEInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC: "DESede",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128: "AES",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192: "AES",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256: "AES",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: "AES",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: "AES",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: "AES"
        ]

        for o in oidCipherAlgorithm {
            let paceInfo = PACEInfo(oid: o.key, version: 2, parameterId: 0)
            XCTAssertNoThrow(try paceInfo.getCipherAlgorithm())
            XCTAssertEqual(try! paceInfo.getCipherAlgorithm(), o.value)
        }

        let paceInfo = PACEInfo(oid: "InvalidTestOID", version: 2, parameterId: 0)
        XCTAssertThrowsError(try paceInfo.getCipherAlgorithm())
    }

    func testGetDigestAlgorithm() {
        let oidDigestAlgorithm: [String: String] = [
            PACEInfo.ID_PACE_DH_GM_3DES_CBC_CBC: "SHA-1",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128: "SHA-1",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192: "SHA-256",
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256: "SHA-256",
            PACEInfo.ID_PACE_DH_IM_3DES_CBC_CBC: "SHA-1",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128: "SHA-1",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192: "SHA-256",
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256: "SHA-256",
            PACEInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC: "SHA-1",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128: "SHA-1",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192: "SHA-256",
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256: "SHA-256",
            PACEInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC: "SHA-1",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128: "SHA-1",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192: "SHA-256",
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256: "SHA-256",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: "SHA-1",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: "SHA-256",
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: "SHA-256"
        ]

        for o in oidDigestAlgorithm {
            let paceInfo = PACEInfo(oid: o.key, version: 2, parameterId: 0)
            XCTAssertNoThrow(try paceInfo.getDigestAlgorithm())
            XCTAssertEqual(try! paceInfo.getDigestAlgorithm(), o.value)
        }

        let paceInfo = PACEInfo(oid: "InvalidTestOID", version: 2, parameterId: 0)
        XCTAssertThrowsError(try paceInfo.getDigestAlgorithm())
    }

    func testGetKeyLength() {
        let oidKeyLength: [String: Int] = [
            PACEInfo.ID_PACE_DH_GM_3DES_CBC_CBC: 128,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128: 128,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192: 192,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256: 256,
            PACEInfo.ID_PACE_DH_IM_3DES_CBC_CBC: 128,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128: 128,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192: 192,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256: 256,
            PACEInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC: 128,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128: 128,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192: 192,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256: 256,
            PACEInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC: 128,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128: 128,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192: 192,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256: 256,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: 128,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: 192,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: 256
        ]

        for o in oidKeyLength {
            let paceInfo = PACEInfo(oid: o.key, version: 2, parameterId: 0)
            XCTAssertNoThrow(try paceInfo.getKeyLength())
            XCTAssertEqual(try! paceInfo.getKeyLength(), o.value)
        }

        let paceInfo = PACEInfo(oid: "InvalidTestOID", version: 2, parameterId: 0)
        XCTAssertThrowsError(try paceInfo.getKeyLength())
    }

    func testCreateMappingKey_WithDhOid_WithValidParameterId_DoesNotThrow() {
        let dhOids = [
            PACEInfo.ID_PACE_DH_GM_3DES_CBC_CBC,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256,
            PACEInfo.ID_PACE_DH_IM_3DES_CBC_CBC,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256,
        ]

        let validParametersForDhOids = [
            PACEInfo.PARAM_ID_GFP_1024_160,
            PACEInfo.PARAM_ID_GFP_2048_224,
            PACEInfo.PARAM_ID_GFP_2048_256
        ]

        for dh in dhOids {
            for p in validParametersForDhOids {
                let paceInfo = PACEInfo(oid: dh, version: 1, parameterId: p)
                XCTAssertNoThrow(try paceInfo.createMappingKey()) { mappingKey in
                    EVP_PKEY_free(mappingKey)
                }
            }
        }
    }

    func testCreateMappingKey_WithDhOid_WithInvalidParameterId_Throws() {
        let dhOids = [
            PACEInfo.ID_PACE_DH_GM_3DES_CBC_CBC,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_DH_GM_AES_CBC_CMAC_256,
            PACEInfo.ID_PACE_DH_IM_3DES_CBC_CBC,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_DH_IM_AES_CBC_CMAC_256,
        ]

        let invalidParametersForDhOids = [
            PACEInfo.PARAM_ID_ECP_NIST_P192_R1, PACEInfo.PARAM_ID_ECP_NIST_P224_R1, PACEInfo.PARAM_ID_ECP_NIST_P256_R1,
            PACEInfo.PARAM_ID_ECP_NIST_P384_R1, PACEInfo.PARAM_ID_ECP_NIST_P521_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P192_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P224_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P320_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P384_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P512_R1
        ]

        for dh in dhOids {
            for p in invalidParametersForDhOids {
                let paceInfo = PACEInfo(oid: dh, version: 1, parameterId: p)
                XCTAssertThrowsError(try paceInfo.createMappingKey()) { error in
                    guard case NFCPassportReaderError.InvalidDataPassed(let message) = error else {
                        return XCTFail()
                    }

                    XCTAssertEqual(message, "Unable to create DH mapping key")
                }
            }
        }
    }

    func testCreateMappingKey_WithEcdhOid_WithValidParameterId_DoesNotThrow() {
        let ecdhOids = [
            PACEInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
            PACEInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256,
        ]

        let validParametersForEcdhOids = [
            PACEInfo.PARAM_ID_ECP_NIST_P192_R1, PACEInfo.PARAM_ID_ECP_NIST_P224_R1, PACEInfo.PARAM_ID_ECP_NIST_P256_R1,
            PACEInfo.PARAM_ID_ECP_NIST_P384_R1, PACEInfo.PARAM_ID_ECP_NIST_P521_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P192_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P224_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P320_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P384_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P512_R1
        ]

        for ecdh in ecdhOids {
            for p in validParametersForEcdhOids {
                let paceInfo = PACEInfo(oid: ecdh, version: 1, parameterId: p)
                XCTAssertNoThrow(try paceInfo.createMappingKey()) { mappingKey in
                    EVP_PKEY_free(mappingKey)
                }
            }
        }
    }

    func testCreateMappingKey_WithEcdhOid_WithInvalidParameterId_Throws() {
        let ecdhOids = [
            PACEInfo.ID_PACE_ECDH_GM_3DES_CBC_CBC,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
            PACEInfo.ID_PACE_ECDH_IM_3DES_CBC_CBC,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192,
            PACEInfo.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256,
        ]

        let invalidParametersForEcdhOids = [
            PACEInfo.PARAM_ID_GFP_1024_160,
            PACEInfo.PARAM_ID_GFP_2048_224,
            PACEInfo.PARAM_ID_GFP_2048_256
        ]

        for ecdh in ecdhOids {
            for p in invalidParametersForEcdhOids {
                let paceInfo = PACEInfo(oid: ecdh, version: 1, parameterId: p)
                XCTAssertThrowsError(try paceInfo.createMappingKey()) { error in
                    guard case NFCPassportReaderError.InvalidDataPassed(let message) = error else {
                        return XCTFail()
                    }

                    XCTAssertEqual(message, "Unable to create EC mapping key")
                }
            }
        }
    }

    // MARK: - Utility testing functions

    private func testPACEInfoGetProtocolOIDString(str: String, oid: String) {
        let parameterIds = [
            PACEInfo.PARAM_ID_ECP_NIST_P192_R1, PACEInfo.PARAM_ID_ECP_NIST_P224_R1, PACEInfo.PARAM_ID_ECP_NIST_P256_R1,
            PACEInfo.PARAM_ID_ECP_NIST_P384_R1, PACEInfo.PARAM_ID_ECP_NIST_P521_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P192_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P224_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P320_R1,
            PACEInfo.PARAM_ID_ECP_BRAINPOOL_P384_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P512_R1, PACEInfo.PARAM_ID_GFP_1024_160,
            PACEInfo.PARAM_ID_GFP_2048_224, PACEInfo.PARAM_ID_GFP_2048_256
        ]

        for parameterId in parameterIds {
            let paceInfo = PACEInfo(oid: oid, version: 2, parameterId: parameterId)
            XCTAssertEqual(str, paceInfo.getProtocolOIDString())
        }
    }

    private func testGetParameterSpec(_ stdDomainParams: Int, shouldThrow: Bool) {
        let paceInfo = PACEInfo(oid: "test", version: 2, parameterId: stdDomainParams)

        if shouldThrow {
            XCTAssertThrowsError(try paceInfo.getParameterSpec())
        } else {
            XCTAssertNoThrow(try paceInfo.getParameterSpec())
        }
    }
}
