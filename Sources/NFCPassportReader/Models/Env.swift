//
//  File.swift
//  
//
//  Created by Jenny Tellne on 2022-01-28.
//

import Foundation

public enum Env {
    static let isDev: Bool = {
        #if DEV
            return true
        #else
            return false
        #endif
    }()
    
    static let isStaging: Bool = {
        #if STAGING
            return true
        #else
            return false
        #endif
    }()
    
    static let isDebug: Bool = {
        #if DEBUG
            return true
        #else
            return false
        #endif
    }()
}
