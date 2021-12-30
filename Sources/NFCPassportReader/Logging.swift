//
//  Logging.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import Logging

public struct Log {
    private static var sharedInstance = Logger(label: "idk-ios-nfcreader")

    public static func setSharedInstance(logger: Logger) {
        sharedInstance = logger
    }

    public static func setMetadata(_ metadata: Logger.Metadata) {
        metadata.forEach { key, value in
            sharedInstance[metadataKey: key] = value
        }
    }

    static func verbose(_ message: Logger.Message, metadata: Logger.Metadata? = nil) {
        sharedInstance.trace(message, metadata: metadata)
    }

    static func debug(_ message: Logger.Message, metadata: Logger.Metadata? = nil) {
        sharedInstance.debug(message, metadata: metadata)
    }

    static func info(_ message: Logger.Message, metadata: Logger.Metadata? = nil) {
        sharedInstance.info(message, metadata: metadata)
    }

    static func warning(_ message: Logger.Message, metadata: Logger.Metadata? = nil) {
        sharedInstance.warning(message, metadata: metadata)
    }

    static func error(_ message: Logger.Message, metadata: Logger.Metadata? = nil) {
        sharedInstance.error(message, metadata: metadata)
    }

    static func error(_ message: Logger.Message, _ error: Error) {
        let metadata: Logger.Metadata = ["error": "\(error)"]
        sharedInstance.error(message, metadata: metadata)
    }
}


// TODO: Quick log functions - will move this to something better
public enum LogLevel : Int, CaseIterable {
    case verbose = 0
    case debug = 1
    case info = 2
    case warning = 3
    case error = 4
}

public class Log2 {
    public static var logLevel : LogLevel = .info
    public static var storeLogs = false
    public static var logData = [String]()

    public static var isEmpty: Bool {
        return logData.count == 0
    }

    public class func verbose( _ msg : @autoclosure () -> String ) {
        log( .verbose, msg )
    }
    public class func debug( _ msg : @autoclosure () -> String ) {
        log( .debug, msg )
    }
    public class func info( _ msg : @autoclosure () -> String ) {
        log( .info, msg )
    }
    public class func warning( _ msg : @autoclosure () -> String ) {
        log( .warning, msg )
    }
    public class func error( _ msg : @autoclosure () -> String ) {
        log( .error, msg )
    }

    public class func clearStoredLogs() {
        logData.removeAll()
    }

    class func log( _ logLevel : LogLevel, _ msg : () -> String ) {
        if self.logLevel.rawValue <= logLevel.rawValue {
            let message = msg()
            print( message )

            if storeLogs {
                logData.append( message )
            }
        }
    }
}
