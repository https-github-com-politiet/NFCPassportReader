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

    static func verbose(
        _ message: Logger.Message,
        metadata: Logger.Metadata? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        sharedInstance.trace(message, metadata: metadata, file: file, function: function, line: line)
    }

    static func debug(
        _ message: Logger.Message,
        metadata: Logger.Metadata? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        sharedInstance.debug(message, metadata: metadata, file: file, function: function, line: line)
    }

    static func info(
        _ message: Logger.Message,
        metadata: Logger.Metadata? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        sharedInstance.info(message, metadata: metadata, file: file, function: function, line: line)
    }

    static func warning(
        _ message: Logger.Message,
        metadata: Logger.Metadata? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        sharedInstance.warning(message, metadata: metadata, file: file, function: function, line: line)
    }

    static func error(
        _ message: Logger.Message,
        metadata: Logger.Metadata? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        sharedInstance.error(message, metadata: metadata, file: file, function: function, line: line)
    }

    static func error(
        _ message: Logger.Message,
        _ error: Error,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        let metadata: Logger.Metadata = ["error": "\(error)"]
        sharedInstance.error(message, metadata: metadata, file: file, function: function, line: line)
    }
}
