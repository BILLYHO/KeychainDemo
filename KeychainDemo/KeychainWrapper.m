//
//  KeychainWrapper.m
//  KeychainDemo
//
//  Created by BILLY HO on 11/13/14.
//  Copyright (c) 2014 BILLY HO. All rights reserved.
//

#import "KeychainWrapper.h"

// Used to help secure the PIN.
// Ideally, this is randomly generated, but to avoid the unnecessary complexity and overhead of storing the Salt separately, we will standardize on this key.
// !!KEEP IT A SECRET!!
#define SALT_HASH @"FvTivqTqZXsgLLx1v3P8TGRyVHaSOB1pvfm02wvGadj7RLHV8GrfxaZ84oGA8RsKdNRpxdAojXYg9iAj"

@implementation KeychainWrapper
// *** NOTE *** This class is ARC compliant - any references to CF classes must be paired with a "__bridge" statement to
// cast between Objective-C and Core Foundation Classes.  WWDC 2011 Video "Introduction to Automatic Reference Counting" explains this.
// *** END NOTE ***
+ (NSMutableDictionary *)setupSearchDirectoryForAccount:(NSString *)account forService:(NSString *)service{
 
	// Setup dictionary to access keychain.
	NSMutableDictionary *searchDictionary = [[NSMutableDictionary alloc] init];
	// Specify we are using a password (rather than a certificate, internet password, etc).
	[searchDictionary setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
	// Uniquely identify this keychain accessor.
	[searchDictionary setObject:service forKey:(__bridge id)kSecAttrService];
 
	// Uniquely identify the account who will be accessing the keychain.
	NSData *encodedAccount = [account dataUsingEncoding:NSUTF8StringEncoding];
	[searchDictionary setObject:encodedAccount forKey:(__bridge id)kSecAttrGeneric];
	[searchDictionary setObject:encodedAccount forKey:(__bridge id)kSecAttrAccount];
 
	return searchDictionary;
}

+ (NSData *)searchKeychainCopyMatchingAccount:(NSString *)account forService:(NSString *)service
{
 
	NSMutableDictionary *searchDictionary = [self setupSearchDirectoryForAccount:account forService:service];
	// Limit search results to one.
	[searchDictionary setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
 
	// Specify we want NSData/CFData returned.
	[searchDictionary setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
 
	// Search.
	NSData *result = nil;
	CFTypeRef foundDict = NULL;
	OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)searchDictionary, &foundDict);
 
	if (status == noErr) {
		result = (__bridge_transfer NSData *)foundDict;
	} else {
		result = nil;
	}
 
	return result;
}


+ (BOOL)compareKeychainValueForMatchingPINValue:(NSString *)pinValue withAccount:(NSString *)account forService:(NSString *)service;
{
	NSData *resultData = [self searchKeychainCopyMatchingAccount:account forService:service];
	if (resultData)
	{
		NSString *resultValue = [[NSString alloc] initWithData:resultData
												encoding:NSUTF8StringEncoding];
		return [resultValue isEqualToString:pinValue];
	}
	return NO;
}



+ (BOOL)createKeychainValue:(NSString *)value withAccount:(NSString *)account forService:(NSString *)service;
{
 
	NSMutableDictionary *dictionary = [self setupSearchDirectoryForAccount:account forService:service];
	NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];
	[dictionary setObject:valueData forKey:(__bridge id)kSecValueData];
 
	// Protect the keychain entry so it's only valid when the device is unlocked.
	[dictionary setObject:(__bridge id)kSecAttrAccessibleWhenUnlocked forKey:(__bridge id)kSecAttrAccessible];
 
	// Add.
	OSStatus status = SecItemAdd((__bridge CFDictionaryRef)dictionary, NULL);
 
	// If the addition was successful, return. Otherwise, attempt to update existing key or quit (return NO).
	if (status == errSecSuccess) {
		return YES;
	} else if (status == errSecDuplicateItem){
		return [self updateKeychainValue:value withAccount:account forService:service];
	} else {
		return NO;
	}
}

+ (BOOL)updateKeychainValue:(NSString *)value withAccount:(NSString *)account forService:(NSString *)service;
{
 
	NSMutableDictionary *searchDictionary = [self setupSearchDirectoryForAccount:account forService:service];
	NSMutableDictionary *updateDictionary = [[NSMutableDictionary alloc] init];
	NSData *valueData = [value dataUsingEncoding:NSUTF8StringEncoding];
	[updateDictionary setObject:valueData forKey:(__bridge id)kSecValueData];
 
	// Update.
	OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)searchDictionary,
									(__bridge CFDictionaryRef)updateDictionary);
 
	if (status == errSecSuccess) {
		return YES;
	} else {
		return NO;
	}
}

+ (BOOL)deleteItemFromKeychainWithwithAccount:(NSString *)account forService:(NSString *)service;
{
	NSMutableDictionary *searchDictionary = [self setupSearchDirectoryForAccount:account forService:service];
	CFDictionaryRef dictionary = (__bridge CFDictionaryRef)searchDictionary;
 
	//Delete.
	OSStatus status = SecItemDelete(dictionary);
	
	if (status == errSecSuccess){
		return YES;
	} else {
		return NO;
	}
}




// This is where most of the magic happens (the rest of it happens in computeSHA256DigestForString: method below).
// Here we are passing in the hash of the PIN that the user entered so that we can avoid manually handling the PIN itself.
// Then we are extracting the username that the user supplied during setup, so that we can add another unique element to the hash.
// From there, we mash the user name, the passed-in PIN hash, and the secret key (from ChristmasConstants.h) together to create
// one long, unique string.
// Then we send that entire hash mashup into the SHA256 method below to create a "Digital Digest," which is considered
// a one-way encryption algorithm. "One-way" means that it can never be reverse-engineered, only brute-force attacked.
// The algorthim we are using is Hash = SHA256(Name + Salt + (Hash(PIN))). This is called "Digest Authentication."
+ (NSString *)securedSHA256DigestHashForPIN:(NSString *)pinValue withAccount:(NSString *)account;
{
	NSUInteger pinHash = [pinValue hash];
	// 1
	account = [account stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
	// 2
	NSString *computedHashString = [NSString stringWithFormat:@"%@%lu%@", account, (unsigned long)pinHash, SALT_HASH];
	// 3
	NSString *finalHash = [self computeSHA256DigestForString:computedHashString];
	NSLog(@"** Computed hash: %@ for SHA256 Digest: %@", computedHashString, finalHash);
	return finalHash;
}

// This is where the rest of the magic happens.
// Here we are taking in our string hash, placing that inside of a C Char Array, then parsing it through the SHA256 encryption method.
+ (NSString*)computeSHA256DigestForString:(NSString*)input
{
 
	const char *cstr = [input cStringUsingEncoding:NSUTF8StringEncoding];
	NSData *data = [NSData dataWithBytes:cstr length:input.length];
	uint8_t digest[CC_SHA256_DIGEST_LENGTH];
 
	// This is an iOS5-specific method.
	// It takes in the data, how much data, and then output format, which in this case is an int array.
	CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
 
	// Setup our Objective-C output.
	NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
 
	// Parse through the CC_SHA256 results (stored inside of digest[]).
	for(int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
		[output appendFormat:@"%02x", digest[i]];
	}
 
	return output;
}

@end