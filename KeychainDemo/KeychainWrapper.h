//
//  KeychainWrapper.h
//  KeychainDemo
//
//  Created by BILLY HO on 11/13/14.
//  Copyright (c) 2014 BILLY HO. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonHMAC.h>




@interface KeychainWrapper : NSObject


// Simple method to compare a passed in hash value with what is stored in the keychain.
// Optionally, we could adjust this method to take in the keychain key to look up the value.
+ (BOOL)compareKeychainValueForMatchingPINValue:(NSString *)pinValue withAccount:(NSString *)account forService:(NSString *)service;

// Default initializer to store a value in the keychain.
// Associated properties are handled for you - setting Data Protection Access, Company Identifer (to uniquely identify string, etc).
+ (BOOL)createKeychainValue:(NSString *)value withAccount:(NSString *)account forService:(NSString *)service;

// Updates a value in the keychain. If you try to set the value with createKeychainValue: and it already exists,
// this method is called instead to update the value in place.
+ (BOOL)updateKeychainValue:(NSString *)value withAccount:(NSString *)account forService:(NSString *)service;

// Delete a value in the keychain.
+ (BOOL)deleteItemFromKeychainWithwithAccount:(NSString *)account forService:(NSString *)service;

// Generates an SHA256 (much more secure than MD5) hash.
+ (NSString *)securedSHA256DigestHashForPIN:(NSString *)pinValue withAccount:(NSString *)account;

@end
