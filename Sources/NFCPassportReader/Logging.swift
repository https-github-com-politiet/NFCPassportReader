//
//  Logging.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import FirebaseCrashlytics

public struct Log {
    private static let label = "idk-ios-nfcreader"

    static func debug(
        _ message: String,
        metadata: [String: String]? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        if Env.isDev || Env.isDebug {
            print("DEBUG: \(label)/\(file):\(function)(line: \(line)): \(message), \(String(describing: metadata))")
        }
    }

    static func warning(
        _ message: String,
        metadata: [String: String]? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        Crashlytics.crashlytics().log("WARNING: \(label)/\(file):\(function)(line: \(line)): \(message), \(String(describing: metadata))")
    }

    static func error(
        _ message: String,
        metadata: [String: String]? = nil,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        Crashlytics.crashlytics().log("ERROR: \(label)/\(file):\(function)(line: \(line)): \(message), \(String(describing: metadata))")
    }

    static func error(
        _ message: String,
        _ error: Error,
        file: String = #fileID,
        function: String = #function,
        line: UInt = #line
    ) {
        Crashlytics.crashlytics().log("ERROR: \(label)/\(file):\(function)(line: \(line)): \(message), Error: \(error)")
    }
}
