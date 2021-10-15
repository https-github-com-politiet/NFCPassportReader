//
//  NFCViewDisplayMessage.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 09/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum NFCViewDisplayMessage {
    case requestPresentPassport
    case authenticatingWithPassport(Int)
    case readingDataGroupProgress(DataGroupId, Int)
    case error(NFCPassportReaderError)
    case successfulRead
}

@available(iOS 13, macOS 10.15, *)
extension NFCViewDisplayMessage {
    public var description: String {
        switch self {
            case .requestPresentPassport:
                return NSLocalizedString("pit.idk-ios-nfcreader.scan.requestPresentPassport", bundle: .main, comment: "")
            case .authenticatingWithPassport(let progress), .readingDataGroupProgress(let _, let progress):
                let progressString = handleProgress(percentualProgress: progress)
                return NSLocalizedString("pit.idk-ios-nfcreader.scan.inProgress", bundle: .main, comment: "") + "...\n\n\(progressString)"
            case .error(let tagError):
                switch tagError {
                    case NFCPassportReaderError.TagNotValid:
                        return NSLocalizedString("pit.idk-ios-nfcreader.scan.error.TagNotValid", bundle: .main, comment: "")
                    case NFCPassportReaderError.MoreThanOneTagFound:
                        return NSLocalizedString("pit.idk-ios-nfcreader.scan.error.MoreThanOneTagFound", bundle: .main, comment: "")
                    case NFCPassportReaderError.ConnectionError:
                        return NSLocalizedString("pit.idk-ios-nfcreader.scan.error.ConnectionError", bundle: .main, comment: "")
                    case NFCPassportReaderError.InvalidMRZKey:
                        return NSLocalizedString("pit.idk-ios-nfcreader.scan.error.InvalidMRZKey", bundle: .main, comment: "")
                    case NFCPassportReaderError.ResponseError(let description, let sw1, let sw2):
                        return NSLocalizedString("pit.idk-ios-nfcreader.scan.error.responseError", bundle: .main, comment: "") + " \(description) - (0x\(sw1), 0x\(sw2)"
                    default:
                        return NSLocalizedString("pit.idk-ios-nfcreader.scan.error.default", bundle: .main, comment: "")
                }
            case .successfulRead:
                return NSLocalizedString("pit.idk-ios-nfcreader.scan.success", bundle: .main, comment: "")
        }
    }
    
    func handleProgress(percentualProgress: Int) -> String {
        let p = (percentualProgress/20)
        let full = String(repeating: "🟢 ", count: p)
        let empty = String(repeating: "⚪️ ", count: 5-p)
        return "\(full)\(empty)"
    }
}
