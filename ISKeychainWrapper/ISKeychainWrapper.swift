//
//  ISKeychainWrapper.swift
//  ISKeychainWrapper
//
//  Created by Ishmeet Singh Sethi on 2016-07-07.
//  Copyright © 2016 Ishmeet. All rights reserved.
//

import UIKit
import Security

class ISKeychainWrapper: NSObject {
    
    var accessGroupName: String!
    
    init(accessGroup: String) {
        accessGroupName = accessGroup
    }
    
    func addValue(value: AnyObject, forKey key: String) -> Void {
        let valueData: NSData = value.dataUsingEncoding(NSUTF8StringEncoding)!
        
        let keychainQuery: NSMutableDictionary = [
            kSecClass as String : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecValueData as String : valueData,
            kSecAttrAccessible as String : kSecAttrAccessibleAlways,
            kSecAttrAccessGroup as String : accessGroupName
        ]
        
        let result = SecItemAdd(keychainQuery, nil)
        
        if result != noErr {
            print("ISKeychain Wrapper: Error saving value for key \(key) to keychain.")
        }
    }
    
    func addMultipleValues(values: [AnyObject], forKeys keys: [String]) -> Void {
        for (key, value) in zip(keys, values) {
            let valueData: NSData = value.dataUsingEncoding(NSUTF8StringEncoding)!
            
            let keychainQuery: NSMutableDictionary = [
                kSecClass as String : kSecClassGenericPassword,
                kSecAttrAccount as String : key,
                kSecValueData as String : valueData,
                kSecAttrAccessible as String : kSecAttrAccessibleAlways,
                kSecAttrAccessGroup as String : accessGroupName
            ]
            
            let result = SecItemAdd(keychainQuery, nil)
            
            if result != noErr {
                print("ISKeychain Wrapper: Error saving value for key \(key) to keychain.")
            }
        }
    }
    
    func deleteMultipleValues(forKeys keys: [String]) {
        for key in keys {
            let deleteKeychainQuery = [
                kSecClass as String : kSecClassGenericPassword,
                kSecAttrAccount as String : key,
                kSecAttrAccessGroup as String : accessGroupName
            ]
            let result = SecItemDelete(deleteKeychainQuery)
            if result != noErr {
                print("ISKeychain Wrapper: Error deleting value for key \(key) from keychain.")
            }
        }
    }
    
    func deleteValue(forKey key: String) {
        let deleteKeychainQuery = [
            kSecClass as String : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecAttrAccessGroup as String : accessGroupName
        ]
        let result = SecItemDelete(deleteKeychainQuery)
        if result != noErr {
            print("ISKeychain Wrapper: Error deleting value for key \(key) from keychain.")
        }
    }
    
    func getValue(forKey key: String) -> String? {
        let getValueQuery = [
            kSecClass as String : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecReturnData as String : kCFBooleanTrue,
            kSecMatchLimit as String : kSecMatchLimitOne,
            kSecAttrAccessGroup as String : accessGroupName
        ]
        
        var result: AnyObject?
        
        let resultCodeLoad = withUnsafeMutablePointer(&result) {
            SecItemCopyMatching(getValueQuery, UnsafeMutablePointer($0))
        }
        
        if resultCodeLoad == noErr {
            if let result = result as? NSData, keyvalue = NSString(data: result, encoding: NSUTF8StringEncoding) as? String {
                return keyvalue
            }
        }
        
        return nil
    }
    
}
