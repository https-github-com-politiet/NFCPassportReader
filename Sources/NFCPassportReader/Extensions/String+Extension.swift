//
//  File.swift
//  
//
//  Created by Jenny Tellne on 2022-01-10.
//

import Foundation

extension String {
    func trimWhitespacesAndNewlines() -> String {
        let pattern = #"^\s+|\s+$"#
        if let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) {
            let range = NSRange(location: 0, length: count)
            let trimmedString = regex.stringByReplacingMatches(in: self, options: [], range: range, withTemplate: "")
            return trimmedString
        }
        return self
    }
}
