//
//  Constants.h
//  KeychainDemo
//
//  Created by BILLY HO on 11/13/14.
//  Copyright (c) 2014 BILLY HO. All rights reserved.
//

#ifndef KeychainDemo_Constants_h
#define KeychainDemo_Constants_h

// Used for saving to NSUserDefaults that a PIN has been set, and is the unique identifier for the Keychain.
#define PIN_SAVED @"hasSavedPIN"

// Used for saving the user's name to NSUserDefaults.
#define USERNAME [[NSUserDefaults standardUserDefaults] stringForKey:@"username"]

// Used to specify the application used in accessing the Keychain.
#define APP_NAME [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"]




// Typedefs just to make it a little easier to read in code.
typedef enum {
	kAlertTypePIN = 0,
	kAlertTypeSetup
} AlertTypes;

typedef enum {
	kTextFieldPIN = 1,
	kTextFieldName,
	kTextFieldPassword
} TextFieldTypes;

#endif
