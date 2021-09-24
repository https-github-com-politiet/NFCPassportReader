//
//  PACEHandler.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 03/03/2021.
//

import Foundation
import OpenSSL
import CryptoTokenKit

#if !os(macOS)
import CoreNFC
import CryptoKit

@available(iOS 13, *)
private enum PACEHandlerError {
    case DHKeyAgreementError(String)
    case ECDHKeyAgreementError(String)
    
    var value: String {
        switch self {
            case .DHKeyAgreementError(let errMsg): return errMsg
            case .ECDHKeyAgreementError(let errMsg): return errMsg

        }
    }
}

@available(iOS 13, *)
extension PACEHandlerError: LocalizedError {
    public var errorDescription: String? {
        return NSLocalizedString(value, comment: "PACEHandlerError")
    }
}

@available(iOS 13, *)
public class PACEHandler {
    
    
    private static let MRZ_PACE_KEY_REFERENCE : UInt8 = 0x01
    private static let CAN_PACE_KEY_REFERENCE : UInt8 = 0x02 // Not currently supported
    private static let PIN_PACE_KEY_REFERENCE : UInt8 = 0x03 // Not currently supported
    private static let CUK_PACE_KEY_REFERENCE : UInt8 = 0x04 // Not currently supported

    var tagReader : TagReader
    var paceInfo : PACEInfo
    
    var completedHandler : ((Bool)->())?
    var isPACESupported : Bool = false
    var paceError : String = ""
    
    // Params used
    private var paceKey : [UInt8] = []
    private var paceKeyType : UInt8 = 0
    private var paceOID : String = ""
    private var parameterSpec : Int32 = -1
    private var mappingType : PACEMappingType!
    private var agreementAlg : String = ""
    private var cipherAlg : String = ""
    private var digestAlg : String = ""
    private var keyLength : Int = -1
    
    public init(cardAccess : CardAccess, tagReader: TagReader) throws {
        self.tagReader = tagReader
        
        guard let pi = cardAccess.paceInfo else {
            throw NFCPassportReaderError.NotYetSupported( "PACE not supported" )
        }

        self.paceInfo = pi
        isPACESupported = true
    }
    
    public func doPACE( mrzKey : String, completed: @escaping (Bool)->() ) {
        guard isPACESupported else {
            completed( false )
            return
        }

        self.completedHandler = completed
        
        do {
            Log.info( "Performing PACE with \(paceInfo.getProtocolOIDString())" )
            
            paceOID = paceInfo.getObjectIdentifier()
            parameterSpec = try paceInfo.getParameterSpec()
            
            mappingType = try paceInfo.getMappingType()  // Either GM, CAM, or IM.
            agreementAlg = try paceInfo.getKeyAgreementAlgorithm()  // Either DH or ECDH.
            cipherAlg  = try paceInfo.getCipherAlgorithm()  // Either DESede or AES.
            digestAlg = try paceInfo.getDigestAlgorithm()  // Either SHA-1 or SHA-256.
            keyLength = try paceInfo.getKeyLength()  // Get key length  the enc cipher. Either 128, 192, or 256.

            paceKeyType = PACEHandler.MRZ_PACE_KEY_REFERENCE
            paceKey = try createPaceKey( from: mrzKey )
            
            // Temporary logging
            Log.verbose("doPace - inpit parameters" )
            Log.verbose("paceOID - \(paceOID)" )
            Log.verbose("parameterSpec - \(parameterSpec)" )
            Log.verbose("mappingType - \(mappingType!)" )
            Log.verbose("agreementAlg - \(agreementAlg)" )
            Log.verbose("cipherAlg - \(cipherAlg)" )
            Log.verbose("digestAlg - \(digestAlg)" )
            Log.verbose("keyLength - \(keyLength)" )
            Log.verbose("keyLength - \(mrzKey)" )
            Log.verbose("paceKey - \(binToHexRep(paceKey, asArray:true))" )

            // First start the initial auth call
            tagReader.sendMSESetATMutualAuth(oid: paceOID, keyType: paceKeyType, completed: { [unowned self] response, error in
                if let error = error {
                    return handleError( "MSESatATMutualAuth", "Error - \(error.localizedDescription)" )
                }
                
                self.doStep1()
            })
            
        } catch {
            return handleError( "doPACE", "Error - \(error.localizedDescription)" )
        }
    }
    
    /// Handles an error during the PACE process
    /// Logs and stoes the error and returns false to the caller
    /// - Parameters:
    ///   - stage: Where in the PACE process the error occurred
    ///   - error: The error message
    func handleError( _ stage: String, _ error: String, needToTerminateGA: Bool = false ) {
        Log.error( "PACEHandler: \(stage) - \(error)" )
        Log.error( "   OpenSSLError: \(OpenSSLUtils.getOpenSSLError())" )
        self.paceError = "\(stage) - \(error)"
        self.completedHandler?( false )

/*
        if needToTerminateGA {
            // This is to fix some passports that don't automatically terminate command chaining!
            // No idea if this is the correct way to do it but testing.....
            let terminateGA = wrapDO(b:0x83, arr:[0x00])
            tagReader.sendGeneralAuthenticate(data:terminateGA, isLast:true, completed: { [weak self] response, error in
                self?.completedHandler?( false )
            })
        } else {
            self.completedHandler?( false )
        }
*/
    }
    
    /// Performs PACE Step 1- receives an encrypted nonce from the passport and decypts it with the  PACE key - derived from MRZ, CAN (not yet supported)
    func doStep1() {
        Log.debug("Doing PACE Step1...")
        tagReader.sendGeneralAuthenticate(data: [], isLast: false, completed: { [unowned self] response, error in
            if let error = error {
                return handleError( "Step1", "Failed to send General Authenticate Step1 - \(error.localizedDescription)" )
            }
            
            do {
                let data = response!.data
                let encryptedNonce = try unwrapDO(tag: 0x80, wrappedData: data)
                Log.verbose( "Encrypted nonce - \(binToHexRep(encryptedNonce, asArray:true))" )

                let decryptedNonce: [UInt8]
                if self.cipherAlg == "DESede" {
                    let iv = [UInt8](repeating:0, count: 8)
                    decryptedNonce = tripleDESDecrypt(key: self.paceKey, message: encryptedNonce, iv: iv)
                } else if self.cipherAlg == "AES" {
                    let iv = [UInt8](repeating:0, count: 16)
                    decryptedNonce = AESDecrypt(key: self.paceKey, message: encryptedNonce, iv: iv)
                } else {
                    return self.handleError( "Step1", "Unsupported cipher algorithm requested - \(cipherAlg)" )
                }

                Log.verbose( "Decrypted nonce - \(binToHexRep(decryptedNonce, asArray:true) )" )
                
                self.doStep2(passportNonce: decryptedNonce)

            } catch {
                return handleError( "Step1", "Unable to get encryptedNonce - \(error.localizedDescription)" )
            }
        })
    }
    
    
    /// Performs PACE Step 2 - computes ephemeral parameters by mapping the nonce received from the passport
    ///  (and if IM used the nonce generated by us)
    ///
    /// Using the supported
    /// - Parameters:
    ///   - passportNonce: The decrypted nonce received from the passport
    func doStep2( passportNonce: [UInt8]) {
        Log.debug( "Doing PACE Step2...")
        switch(mappingType) {
            case .CAM, .GM:
                Log.debug( "   Using General Mapping (GM)...")
                return doPACEStep2GM(passportNonce: passportNonce)
            case .IM:
                Log.debug( "   Using Integrated Mapping (IM)...")
                return doPACEStep2IM(passportNonce: passportNonce)
            default:
                return self.handleError( "doStep2", "Unsupported mapping type" )
        }

    }
    
    /// Performs PACEStep 2 using Generic Mapping
    ///
    /// Using the supported
    /// - Parameters:
    ///   - passportNonce: The decrypted nonce received from the passport
    func doPACEStep2GM(passportNonce : [UInt8]) {
        
        let mappingKey : OpaquePointer
        do {
            mappingKey = try self.paceInfo.createMappingKey( )
        } catch {
            return self.handleError( "Step2GM", "Error - \(error.localizedDescription)" )
        }

        guard let pcdMappingEncodedPublicKey = OpenSSLUtils.getPublicKeyData(from: mappingKey) else {
            return self.handleError( "Step2GM", "Unable to get public key from mapping key" )
        }
        Log.verbose( "public mapping key - \(binToHexRep(pcdMappingEncodedPublicKey, asArray:true))")


        Log.debug( "Sending public mapping key to passport..")
        let step2Data = wrapDO(b:0x81, arr:pcdMappingEncodedPublicKey)
        tagReader.sendGeneralAuthenticate(data:step2Data, isLast:false, completed: { [weak self] response, error in
            guard let sself = self else { return }
            
            if let error = error {
                return sself.handleError( "Step2GM", "Error - \(error)" )
            }

            guard let step2Response = response?.data,
                  let piccMappingEncodedPublicKey = try? unwrapDO(tag: 0x82, wrappedData: step2Response) else { //,
                return sself.handleError( "Step2GM", "Unable to decode passport public mapping key" )
            }
            
            Log.debug( "Received passports public mapping key")
            Log.verbose( "   public mapping key - \(binToHexRep(piccMappingEncodedPublicKey, asArray: true))")

            // Do mapping agreement

            // First, Convert nonce to BIGNUM
            guard let bn_nonce = BN_bin2bn(passportNonce, Int32(passportNonce.count), nil) else {
                return sself.handleError( "Step2GM", "Unable to convert picc nonce to bignum" )
            }
            defer { BN_free(bn_nonce) }

            // ephmeralParams are free'd in stage 3
            let ephemeralParams : OpaquePointer
            do {
                if sself.agreementAlg == "DH" {
                    Log.debug( "Doing DH Mapping agreement")
                    ephemeralParams = try sself.doDHMappingAgreement(mappingKey: mappingKey, passportPublicKeyData: piccMappingEncodedPublicKey, nonce: bn_nonce )
                } else if sself.agreementAlg == "ECDH" {
                    Log.debug( "Doing ECDH Mapping agreement")
                    ephemeralParams = try sself.doECDHMappingAgreement(mappingKey: mappingKey, passportPublicKeyData: piccMappingEncodedPublicKey, nonce: bn_nonce )
                } else {
                    return sself.handleError( "Step2GM", "Unsupport agreement algorithm" )
                }
            } catch {
                return sself.handleError( "Step2GM", "Error - \(error.localizedDescription)" )
            }

            // Need to free the mapping key we created now
            EVP_PKEY_free(mappingKey)
            sself.doStep3KeyExchange(ephemeralParams: ephemeralParams)
        })
    }
    
    func doPACEStep2IM( passportNonce: [UInt8] ) {
        // Not implemented yet
        let pcdNonce: [UInt8]
        do {
            pcdNonce = try randb(numBytes: EVP_CIPHER_key_length(try get_cipher()))
        } catch {
            return self.handleError("Step2IM", "ERROR WHEN GENERATING RANDOM BYTES")
        }

        let mappingKey : OpaquePointer
        do {
            mappingKey = try self.paceInfo.createMappingKey( )
        } catch {
            return self.handleError( "Step2IM", "Error - \(error.localizedDescription)" )
        }

        let step2Data = wrapDO(b: 0x81, arr: pcdNonce)

        tagReader.sendGeneralAuthenticate(data:step2Data, isLast:false, completed: { [weak self] response, error in
            guard let sself = self else { return }

            if let error = error {
                return sself.handleError( "Step2IM", "Error - \(error)" )
            }

            // Ephemeral params
            let ephemeralParams : OpaquePointer
            do {
                //                if sself.agreementAlg == "DH" {
                //                    Log.debug( "Doing DH Mapping agreement")
                ////                    ephemeralParams = try sself.doDHMappingAgreement(mappingKey: mappingKey, passportPublicKeyData: piccMappingEncodedPublicKey, nonce: bn_nonce )
                //                } else
                if sself.agreementAlg == "ECDH" {
                    Log.debug( "Doing ECDH IM Mapping agreement")
                    ephemeralParams = try sself.doECDHIMMappingAgreement(mappingKey: mappingKey, piccNonce: passportNonce, pcdNonce: pcdNonce)
                } else {
                    return sself.handleError( "Step2IM", "Unsupport agreement algorithm" )
                }
            } catch {
                return sself.handleError( "Step2IM", "Error - \(error.localizedDescription)" )
            }

            sself.doStep3KeyExchange(ephemeralParams: ephemeralParams)
        })
    }
    
    /// Generates an ephemeral public/private key pair based on mapping parameters from step 2, and then sends
    /// the public key to the passport and receives its ephmeral public key in exchange
    /// - Parameters:
    ///   - ephemeralParams: The ehpemeral mapping keys generated by step2
    func doStep3KeyExchange(ephemeralParams: OpaquePointer) {
        Log.debug( "Doing PACE Step3 - Key Exchange")

        // Generate ephemeral keypair from ephemeralParams
        var ephKeyPair : OpaquePointer? = nil
        let pctx = EVP_PKEY_CTX_new(ephemeralParams, nil)
        EVP_PKEY_keygen_init(pctx)
        EVP_PKEY_keygen(pctx, &ephKeyPair)
        EVP_PKEY_CTX_free(pctx)
                
        guard let ephemeralKeyPair = ephKeyPair else {
            return self.handleError( "Step3 KeyEx", "Unable to get create ephermeral key pair" )
        }
        
        Log.debug( "Generated Ephemeral key pair")

        // We've finished with the ephemeralParams now - we can now free it
        EVP_PKEY_free( ephemeralParams )

        guard let publicKey = OpenSSLUtils.getPublicKeyData( from: ephemeralKeyPair ) else {
            return self.handleError( "Step3 KeyEx", "Unable to get public key from ephermeral key pair" )
        }
        Log.verbose( "Ephemeral public key - \(binToHexRep(publicKey, asArray: true))")

        // exchange public keys
        Log.debug( "Sending ephemeral public key to passport")
        let step3Data = wrapDO(b:0x83, arr:publicKey)
        tagReader.sendGeneralAuthenticate(data:step3Data, isLast:false, completed: { [weak self] response, error in
            guard let sself = self else { return }
            
            if let error = error {
                return sself.handleError( "Step3 KeyEx", "Error - \(error.localizedDescription)" )
            }

            let step3Response = response!.data
            let passportEncodedPublicKey = try? unwrapDO(tag: 0x84, wrappedData: step3Response)
            guard let passportPublicKey = OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: passportEncodedPublicKey!, params: ephemeralKeyPair) else {
                return sself.handleError( "Step3 KeyEx", "Unable to decode passports ephemeral key" )
            }

            Log.verbose( "Received passports ephemeral public key - \(binToHexRep(passportEncodedPublicKey!, asArray: true))" )

            sself.doStep3KeyAgreement( pcdKeyPair: ephemeralKeyPair, passportPublicKey: passportPublicKey)
        })
    }
    
    /// This performs PACE Step 4 - Key Agreement.
    /// Here the shared secret is computed from our ephemeral private key and the passports ephemeral public key
    /// The new secure messaging (ksEnc and ksMac) keys are computed from the shared secret
    /// An authentication token is generated from the passports public key and the computed ksMac key
    /// Then, the authetication token is send to the passport, it returns its own computed authentication token
    /// We then compute an expected authentication token from the ksMac key and our ephemeral public key
    /// Finally we compare the recieved auth token to the expected token and if they are the same then PACE has succeeded!
    /// - Parameters:
    ///   - pcdKeyPair: our ephemeral key pair
    ///   - passportPublicKey: passports ephemeral public key
    func doStep3KeyAgreement( pcdKeyPair: OpaquePointer, passportPublicKey: OpaquePointer) {
        Log.debug( "Doing PACE Step3 Key Agreement...")

        Log.debug( "Computing shared secret...")
        let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair: pcdKeyPair, publicKey: passportPublicKey)
        Log.verbose( "Shared secret - \(binToHexRep(sharedSecret, asArray:true))")

        Log.debug( "Deriving ksEnc and ksMac keys from shared secret")
        let gen = SecureMessagingSessionKeyGenerator()
        let encKey = try! gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let macKey = try! gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        Log.verbose( "encKey - \(binToHexRep(encKey, asArray:true))")
        Log.verbose( "macKey - \(binToHexRep(macKey, asArray:true))")

        // Step 4 - generate authentication token
        Log.debug( "Generating authentication token")
        guard let pcdAuthToken = try? generateAuthenticationToken( publicKey: passportPublicKey, macKey: macKey) else {
            return self.handleError( "Step3 KeyAgreement", "Unable to generate authentication token using passports public key" )
        }
        Log.verbose( "authentication token - \(pcdAuthToken)")

        Log.debug( "Sending auth token to passport")
        let step4Data = wrapDO(b:0x85, arr:pcdAuthToken)
        tagReader.sendGeneralAuthenticate(data:step4Data, isLast:true, completed: { [weak self] response, error in
            guard let sself = self else { return }

            if let error = error {
                // Error
                return sself.handleError( "Step3 KeyAgreement", "Error - \(error.localizedDescription)" )
            }
            
            let tvlResp = TKBERTLVRecord.sequenceOfRecords(from: Data(response!.data))!
            if tvlResp[0].tag != 0x86 {
                Log.warning("Was expecting tag 0x86, found: \(binToHex(UInt8(tvlResp[0].tag)))")
            }
            // Calculate expected authentication token
            guard let expectedPICCToken = try? sself.generateAuthenticationToken( publicKey: pcdKeyPair, macKey: macKey) else {
                return sself.handleError( "Step3 KeyAgreement", "Unable to generate authentication token using our ephemeral key" )
            }
            Log.verbose( "Expecting authentication token from passport - \(expectedPICCToken)")

            let piccToken = [UInt8](tvlResp[0].value)
            Log.verbose( "Received authentication token from passport - \(piccToken)")

            guard piccToken == expectedPICCToken else {
                Log.error( "Error PICC Token mismatch!\npicToken - \(piccToken)\nexpectedPICCToken - \(expectedPICCToken)" )
                sself.completedHandler?(false)
                return sself.handleError( "Step3 KeyAgreement", "Error PICC Token mismatch!\npicToken - \(piccToken)\nexpectedPICCToken - \(expectedPICCToken)" )
            }
            
            Log.debug( "Auth token from passport matches expected token!" )
            
            // This will be added for CAM when supported
            // var encryptedChipAuthenticationData : [UInt8]? = nil
            // if (sself.mappingType == PACEMappingType.CAM) {
            //    if tvlResp[1].tag != 0x8A {
            //        Log.warning("CAM: Was expecting tag 0x86, found: \(binToHex(UInt8(tvlResp[1].tag)))")
            //    }
            //    encryptedChipAuthenticationData = [UInt8](tvlResp[1].value)
            // }
            
            // We're done!
            sself.paceCompleted( ksEnc: encKey, ksMac: macKey )
        })
    }
    
    /// Called once PACE has completed with the newly generated ksEnc and ksMac keys for restarting secure messaging
    /// - Parameters:
    ///   - ksEnc: the computed encryption key derived from the key agreement
    ///   - ksMac: the computed mac key derived from the key agreement
    func paceCompleted( ksEnc: [UInt8], ksMac: [UInt8] ) {
        // Restart secure messaging
        let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
        if (cipherAlg.hasPrefix("DESede")) {
            Log.info( "Restarting secure messaging using DESede encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .DES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader.secureMessaging = sm
        } else if (cipherAlg.hasPrefix("AES")) {
            Log.info( "Restarting secure messaging using AES encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader.secureMessaging = sm
        } else {
            return self.handleError( "PACECompleted", "Not restarting secure messaging as unsupported cipher algorithm requested - \(cipherAlg)" )
        }
        completedHandler?(true)
    }
}

// MARK - PACEHandler Utility functions
@available(iOS 13, *)
extension PACEHandler {
    func get_cipher() throws -> OpaquePointer {
        let cipher: OpaquePointer

        if cipherAlg == "DESede" {
            cipher = EVP_des_ede_cbc()
        } else if cipherAlg == "AES" {
            switch (keyLength) {
            case 128:
                cipher = EVP_aes_128_cbc()
                break
            case 192:
                cipher = EVP_aes_192_cbc()
                break
            case 256:
                cipher = EVP_aes_256_cbc()
                break
            default:
                throw PACEHandlerError.ECDHKeyAgreementError("Unsupported key length when creating AES cipher: \(keyLength)")
            }
        } else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unsupported cipher algorithm: \(cipherAlg)")
        }

        return cipher
    }

    func cipher_no_pad(cipher: OpaquePointer, key_enc: [UInt8], data: [UInt8], enc: Int) throws -> [UInt8] {
        guard let ctx = EVP_CIPHER_CTX_new() else {
            throw PACEHandlerError.ECDHKeyAgreementError("Could not instantiate new cipher context")
        }

//        let ivLength = EVP_CIPHER_iv_length(cipher)
        let ivLength = EVP_CIPHER_block_size(cipher)
        var iv: [UInt8] = Array(repeating: 0, count: Int(ivLength))
        guard RAND_bytes(&iv, ivLength) > 0 else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to generate iv")
        }

        guard EVP_CipherInit_ex(ctx, cipher, nil, key_enc, iv, 1) == 1,
              EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to init cipher or set padding")
        }

        let out = try cipherFunc(ctx: ctx, cipher: cipher, key: key_enc, iv: iv, enc: enc, in: data)

        return out
    }

    func randb(numBytes: Int32) throws -> [UInt8] {
        var out: [UInt8] = Array(repeating: 0, count: Int(numBytes))
        guard RAND_bytes(&out, numBytes) == 1 else {
            print("ROOOOFL")
            throw PACEHandlerError.ECDHKeyAgreementError("Could not generate random bytes")
        }

        print(out)
        return out
    }

    func cipherFunc(ctx: OpaquePointer, cipher: OpaquePointer, key: [UInt8], iv: [UInt8], enc: Int, in data: [UInt8]) throws -> [UInt8] {
        guard EVP_CIPHER_CTX_cipher(ctx) != nil else {
            throw PACEHandlerError.ECDHKeyAgreementError("Could not do stuff")
        }

        let flags = EVP_CIPHER_flags(EVP_CIPHER_CTX_cipher(ctx))
        var i: Int32
        if flags == 1 && EVP_CIPH_NO_PADDING == 1 {
            i = Int32(data.count)
            guard i % EVP_CIPHER_block_size(cipher) == 0 else {
                throw PACEHandlerError.ECDHKeyAgreementError("Data is not of blocklength")
            }
        } else {
            i = Int32(data.count) + Int32(EVP_CIPHER_block_size(cipher))
        }

        var out = Array(repeating: UInt8(0), count: Int(i))

        guard EVP_CipherUpdate(ctx, &out, &i, data, Int32(data.count)) == 1 else {
            throw PACEHandlerError.ECDHKeyAgreementError("Could not do EVP_CipherUpdate")
        }

        out.append(contentsOf: Array(repeating: 0, count: Int(i)))

        guard EVP_CipherFinal_ex(ctx, &out, &i) == 1 else {
            throw PACEHandlerError.ECDHKeyAgreementError("Could not do EVP_CipherFinal_ex")
        }

        return out
    }

    func doECDHIMMappingAgreement(mappingKey: OpaquePointer, piccNonce: [UInt8], pcdNonce: [UInt8]) throws -> OpaquePointer {
        guard let static_key = EVP_PKEY_get1_EC_KEY(mappingKey) else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to get ECDH mapping key")
        }

        let bn_ctx = BN_CTX_new()
        BN_CTX_start(bn_ctx)

        let a = BN_CTX_get(bn_ctx)
        let b = BN_CTX_get(bn_ctx);
        let p = BN_CTX_get(bn_ctx);
        let x = BN_CTX_get(bn_ctx);
        let y = BN_CTX_get(bn_ctx);
        let v = BN_CTX_get(bn_ctx);
        let two = BN_CTX_get(bn_ctx);
        let three = BN_CTX_get(bn_ctx);
        let four = BN_CTX_get(bn_ctx);
        let six = BN_CTX_get(bn_ctx);
        let twentyseven = BN_CTX_get(bn_ctx);
        let tmp = BN_CTX_get(bn_ctx);
        let tmp2 = BN_CTX_get(bn_ctx);
        let bn_inv = BN_CTX_get(bn_ctx);

        // TODO
        // Encrypt the Nonce using the symmetric key in
        // x_mem = cipher_no_pad(ctx->ka_ctx, NULL, in, s, 1);
//        let cipher = try get_cipher()
//        let x_mem = try cipher_no_pad(cipher: cipher, key_enc: pcdNonce, data: piccNonce, enc: 1)

        let iv = [UInt8](repeating: 0, count: 16)
        let x_mem = AESEncrypt(key: pcdNonce, message: piccNonce, iv: iv)

        guard EC_GROUP_get_curve_GFp(EC_KEY_get0_group(static_key), p, a, b, bn_ctx) == 1 else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to get EC group curve")
        }

        // Assign constants
        guard BN_set_word(two, 2) == 1,
              BN_set_word(three, 3) == 1,
              BN_set_word(four, 4) == 1,
              BN_set_word(six, 6) == 1,
              BN_set_word(twentyseven, 27) == 1
        else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to set BIGNUM words")
        }

        // Check prerequisites for curve parameters
        guard
            // p > 3
            BN_cmp(p, three) == 1,
            // p mod 3 = 2; (p has the form p=q^n, q prime)
            BN_nnmod(tmp, p, three, bn_ctx) == 1,
            BN_cmp(tmp, two) == 0
        else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unsuited curve")
        }

        // Convert encrypted nonce to BIGNUM
        // TODO
        let u = BN_bin2bn(x_mem, Int32(x_mem.count), nil)

        // icart point encoding
        guard
            // v = (3a - u^4) / 6u mod p
            BN_mod_mul(tmp, three, a, p, bn_ctx) == 1,
            BN_mod_exp(tmp2, u, four, p, bn_ctx) == 1,
            BN_mod_sub(v, tmp, tmp2, p, bn_ctx) == 1,
            BN_mod_mul(tmp, u, six, p, bn_ctx) == 1,

            // For division within a galois field we need to compute
            // the multiplicative inverse of a number
            BN_mod_inverse(bn_inv, tmp, p, bn_ctx) != nil,
            BN_mod_mul(v, v, bn_inv, p, bn_ctx) == 1,

            // x = (v^2 - b - ((u^6)/27))
            BN_mod_sqr(tmp, v, p, bn_ctx) == 1,
            BN_mod_sub(tmp2, tmp, b, p, bn_ctx) == 1,
            BN_mod_exp(tmp, u, six, p, bn_ctx) == 1,
            BN_mod_inverse(bn_inv, twentyseven, p, bn_ctx) != nil,
            BN_mod_mul(tmp, tmp, bn_inv, p, bn_ctx) == 1,
            BN_mod_sub(x, tmp2, tmp, p, bn_ctx) == 1,

            // x -> x^(1/3) = x^((2p^n -1)/3)
            BN_mul(tmp, two, p, bn_ctx) == 1,
            BN_sub(tmp, tmp, BN_value_one()) == 1,

            // Division is defined, because p^n = 2 mod 3
            BN_div(tmp, y, tmp, three, bn_ctx) == 1,
            BN_mod_exp(tmp2, x, tmp, p, bn_ctx) == 1,
            BN_copy(x, tmp2) != nil,

            // x += (u^2)/3
            BN_mod_sqr(tmp, u, p, bn_ctx) == 1,
            BN_mod_inverse(bn_inv, three, p, bn_ctx) != nil,
            BN_mod_mul(tmp2, tmp, bn_inv, p, bn_ctx) == 1,
            BN_mod_add(tmp, x, tmp2, p, bn_ctx) == 1,
            BN_copy(x, tmp) != nil,

            // y = ux + v
            BN_mod_mul(y, u, x, p, bn_ctx) == 1,
            BN_mod_add(tmp, y, v, p, bn_ctx) == 1,
            BN_copy(y, tmp) != nil
        else {
            throw PACEHandlerError.ECDHKeyAgreementError("Could not do super complex calculation")
        }

        guard let ephemeralParams = EVP_PKEY_new() else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to create ephemeral params")
        }

        let ephemeral_key = EC_KEY_dup(static_key)
        defer { EC_KEY_free(ephemeral_key) }

        guard EVP_PKEY_set1_EC_KEY(ephemeralParams, ephemeral_key) == 1 else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to configure new EC_KEY")
        }

        guard let g = EC_POINT_new(EC_KEY_get0_group(ephemeral_key)) else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to get point g")
        }

        guard EC_POINT_set_affine_coordinates(EC_KEY_get0_group(ephemeral_key), g, x, y, bn_ctx) == 1 else {
            throw PACEHandlerError.ECDHKeyAgreementError("Unable to set affine coordinates")
        }

        return ephemeralParams

    }
    
    /// Does the DH key Mapping agreement
    /// - Parameter mappingKey - Pointer to an EVP_PKEY structure containing the mapping key
    /// - Parameter passportPublicKeyData - byte array containing the publick key read from the passport
    /// - Parameter nonce - Pointer to an BIGNUM structure containing the unencrypted nonce
    /// - Returns the EVP_PKEY containing the mapped ephemeral parameters
    func doDHMappingAgreement( mappingKey : OpaquePointer, passportPublicKeyData: [UInt8], nonce: OpaquePointer ) throws -> OpaquePointer {
        guard let dh_mapping_key = EVP_PKEY_get1_DH(mappingKey) else {
            // Error
            throw PACEHandlerError.DHKeyAgreementError( "Unable to get DH mapping key" )
        }
        
        // Compute the shared secret using the mapping key and the passports public mapping key
        let bn = BN_bin2bn(passportPublicKeyData, Int32(passportPublicKeyData.count), nil)
        defer { BN_free( bn ) }
        
        var secret = [UInt8](repeating: 0, count: Int(DH_size(dh_mapping_key)))
        DH_compute_key( &secret, bn, dh_mapping_key)
        
        // Convert the secret to a bignum
        let bn_h = BN_bin2bn(secret, Int32(secret.count), nil)
        defer { BN_clear_free(bn_h) }
        
        // Initialize ephemeral parameters with parameters from the mapping key
        guard let ephemeral_key = DHparams_dup(dh_mapping_key) else {
            // Error
            throw PACEHandlerError.DHKeyAgreementError("Unable to get initialise ephemeral parameters from DH mapping key")
        }
        defer{ DH_free(ephemeral_key) }
        
        var p : OpaquePointer? = nil
        var q : OpaquePointer? = nil
        var g : OpaquePointer? = nil
        DH_get0_pqg(dh_mapping_key, &p, &q, &g)
        
        // map to new generator
        guard let bn_g = BN_new() else {
            throw PACEHandlerError.DHKeyAgreementError( "Unable to create bn_g" )
        }
        defer{ BN_free(bn_g) }
        guard let new_g = BN_new() else {
            throw PACEHandlerError.DHKeyAgreementError( "Unable to create new_g" )
        }
        defer{ BN_free(new_g) }
        
        // bn_g = g^nonce mod p
        // ephemeral_key->g = bn_g mod p * h  => (g^nonce mod p) * h mod p
        let bn_ctx = BN_CTX_new()
        guard BN_mod_exp(bn_g, g, nonce, p, bn_ctx) == 1,
              BN_mod_mul(new_g, bn_g, bn_h, p, bn_ctx) == 1 else {
            // Error
            throw PACEHandlerError.DHKeyAgreementError( "Failed to generate new parameters" )
        }
        
        guard DH_set0_pqg(ephemeral_key, BN_dup(p), BN_dup(q), BN_dup(new_g)) == 1 else {
            // Error
            throw PACEHandlerError.DHKeyAgreementError( "Unable to set DH pqg paramerters" )
        }
        
        // Set the ephemeral params
        guard let ephemeralParams = EVP_PKEY_new() else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create ephemeral params" )
        }

        guard EVP_PKEY_set1_DH(ephemeralParams, ephemeral_key) == 1 else {
            // Error
            EVP_PKEY_free( ephemeralParams )
            throw PACEHandlerError.DHKeyAgreementError( "Unable to set ephemeral parameters" )
        }
        return ephemeralParams
    }
    
    /// Does the ECDH key Mapping agreement
    /// - Parameter mappingKey - Pointer to an EVP_PKEY structure containing the mapping key
    /// - Parameter passportPublicKeyData - byte array containing the publick key read from the passport
    /// - Parameter nonce - Pointer to an BIGNUM structure containing the unencrypted nonce
    /// - Returns the EVP_PKEY containing the mapped ephemeral parameters
    func doECDHMappingAgreement( mappingKey : OpaquePointer, passportPublicKeyData: [UInt8], nonce: OpaquePointer ) throws -> OpaquePointer {

        let ec_mapping_key = EVP_PKEY_get1_EC_KEY(mappingKey)
        
        guard let group = EC_GROUP_dup(EC_KEY_get0_group(ec_mapping_key)) else {
            // Error
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to get EC group" )
        }
        defer { EC_GROUP_free(group) }
        
        guard let order = BN_new() else {
            // Error
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create order bignum" )
        }
        defer { BN_free( order ) }
        
        guard let cofactor = BN_new() else {
            // error
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create cofactor bignum" )
        }
        defer { BN_free( cofactor ) }
        
        guard EC_GROUP_get_order(group, order, nil) == 1 ||
                EC_GROUP_get_cofactor(group, cofactor, nil) == 1 else {
            // Handle error
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to get order or cofactor from group" )
        }
        
        // Create the shared secret in the form of a ECPoint

        // Ideally I'd use OpenSSLUtls.computeSharedSecret for this but for reasons as yet unknown, it only returns the first 32 bytes
        // NOT the full 64 bytes (would then convert to 65 with e header of 4 for uncompressed)
        guard let sharedSecretMappingPoint = self.computeECDHMappingKeyPoint(privateKey: mappingKey, inputKey: passportPublicKeyData) else {
            // Error
            throw PACEHandlerError.ECDHKeyAgreementError( "Failed to compute new shared secret mapping point from mapping key and passport public mapping key" )
        }
        defer { EC_POINT_free( sharedSecretMappingPoint ) }

        // Map the nonce using Generic mapping to get the new parameters (inc a new generator)
        guard let newGenerater = EC_POINT_new(group) else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create new mapping generator point" )
        }
        defer{ EC_POINT_free(newGenerater) }
        
        // g = (generator * nonce) + (sharedSecretMappingPoint * 1)
        guard EC_POINT_mul(group, newGenerater, nonce, sharedSecretMappingPoint, BN_value_one(), nil) == 1 else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Failed to map nonce to get new generator params" )
        }
        
        // Initialize ephemeral parameters with parameters from the mapping key
        guard let ephemeralParams = EVP_PKEY_new() else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create ephemeral params" )
        }

        let ephemeral_key = EC_KEY_dup(ec_mapping_key)
        defer{ EC_KEY_free(ephemeral_key) }
        
        // configure the new EC_KEY
        guard EVP_PKEY_set1_EC_KEY(ephemeralParams, ephemeral_key) == 1,
              EC_GROUP_set_generator(group, newGenerater, order, cofactor) == 1,
              EC_GROUP_check(group, nil) == 1,
              EC_KEY_set_group(ephemeral_key, group) == 1 else {
            // Error

            EVP_PKEY_free( ephemeralParams )
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to configure new ephemeral params" )
        }
        return ephemeralParams
    }
    
    /// Generate Authentication token from a publicKey and and a mac key
    /// - Parameters:
    ///   - publicKey: An EVP_PKEY structure containing a public key data which will be used to generate the auth code
    ///   - macKey: The mac key derived from the key agreement
    /// - Throws: An error if we are unable to encode the public key data
    /// - Returns: The authentication token (8 bytes)
    func generateAuthenticationToken( publicKey: OpaquePointer, macKey: [UInt8] ) throws -> [UInt8] {
        var encodedPublicKeyData = try encodePublicKey(oid:self.paceOID, key:publicKey)
        
        if cipherAlg == "DESede" {
            // If DESede (3DES), we need to pad the data
            encodedPublicKeyData = pad(encodedPublicKeyData, blockSize: 8)
        }
        
        Log.verbose( "Generating Authentication Token" )
        Log.verbose( "EncodedPubKey = \(binToHexRep(encodedPublicKeyData, asArray: true))" )
        Log.verbose( "macKey = \(binToHexRep(macKey, asArray: true))" )

        let maccedPublicKeyDataObject = mac(algoName: cipherAlg == "DESede" ? .DES : .AES, key: macKey, msg: encodedPublicKeyData)

        // Take 8 bytes for auth token
        let authToken = [UInt8](maccedPublicKeyDataObject[0..<8])
        Log.verbose( "Generated authToken = \(binToHexRep(authToken, asArray: true))" )
        return authToken
    }
    
    /// Encodes a PublicKey as an TLV strucuture based on TR-SAC 1.01 4.5.1 and 4.5.2
    /// - Parameters:
    ///   - oid: The object identifier specifying the key type
    ///   - key: The ECP_PKEY public key to encode
    /// - Throws: Error if unable to encode
    /// - Returns: the encoded public key in tlv format
    func encodePublicKey( oid : String, key : OpaquePointer ) throws -> [UInt8] {
        let encodedOid = oidToBytes(oid:oid, replaceTag: false)
        guard let pubKeyData = OpenSSLUtils.getPublicKeyData(from: key) else {
            Log.error( "PACEHandler: encodePublicKey() - Unable to get public key data" )
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data")
        }

        let keyType = EVP_PKEY_base_id( key )
        let tag : TKTLVTag
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            tag = 0x84
        } else {
            tag = 0x86
        }

        guard let encOid = TKBERTLVRecord(from: Data(encodedOid)) else {
            throw NFCPassportReaderError.InvalidASN1Value
        }
        let encPub = TKBERTLVRecord(tag:tag, value: Data(pubKeyData))
        let record = TKBERTLVRecord(tag: 0x7F49, records:[encOid, encPub])
        let data = record.data

        return [UInt8](data)
    }

    /// Computes a key seed based on an MRZ key
    /// - Parameter the mrz key
    /// - Returns a encoded key based on the mrz key that can be used for PACE
    func createPaceKey( from mrzKey: String ) throws -> [UInt8] {
        let buf: [UInt8] = Array(mrzKey.utf8)
        let hash = calcSHA1Hash(buf)
        
        let smskg = SecureMessagingSessionKeyGenerator()
        let key = try smskg.deriveKey(keySeed: hash, cipherAlgName: cipherAlg, keyLength: keyLength, nonce: nil, mode: .PACE_MODE, paceKeyReference: paceKeyType)
        return key
    }
    
    /// Performs the ECDH PACE GM key agreement protocol by multiplying a private key with a public key
    /// - Parameters:
    ///   - key: an EVP_PKEY structure containng a ECDH private key
    ///   - inputKey: a public key
    /// - Returns: a new EC_POINT
    func computeECDHMappingKeyPoint( privateKey : OpaquePointer, inputKey : [UInt8] ) -> OpaquePointer? {
        
        let ecdh = EVP_PKEY_get1_EC_KEY(privateKey)
        defer { EC_KEY_free(ecdh) }

        let privateECKey = EC_KEY_get0_private_key(ecdh) // BIGNUM

        // decode public key
        guard let group = EC_KEY_get0_group(ecdh) else{ return nil }
        guard let ecp = EC_POINT_new(group) else { return nil }
        defer { EC_POINT_free(ecp) }
        guard EC_POINT_oct2point(group, ecp, inputKey, inputKey.count,nil) != 0 else { return nil }
                
        // create our output point
        let output = EC_POINT_new(group)

        // Multiply our private key with the passports public key to get a new point
        EC_POINT_mul(group, output, nil, ecp, privateECKey, nil)
        
        return output
    }
}

#endif
