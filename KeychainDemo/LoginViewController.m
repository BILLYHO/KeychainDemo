//
//  LoginViewController.m
//  KeychainDemo
//
//  Created by BILLY HO on 11/13/14.
//  Copyright (c) 2014 BILLY HO. All rights reserved.
//

#import "LoginViewController.h"
#import "ViewController.h"
#import "KeychainWrapper.h"

@implementation LoginViewController

#pragma mark - View lifecycle
- (void)viewDidLoad
{
	[super viewDidLoad];
	self.pinValidated = NO;
}

- (void)viewDidAppear:(BOOL)animated
{
	[super viewDidAppear:animated];
	[self presentAlertViewForPassword];
	
	NSLog(@"%@",[[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"]);
}

- (void)presentAlertViewForPassword
{
 
	// 1
	BOOL hasPin = [[NSUserDefaults standardUserDefaults] boolForKey:PIN_SAVED];
 
	// 2
	if (hasPin) {
		// 3
		NSString *user = USERNAME;
		NSString *message = [NSString stringWithFormat:@"What is %@'s password?", user];
		UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Enter Password"
														message:message
													   delegate:self
											  cancelButtonTitle:@"Cancel"
											  otherButtonTitles:@"Done", nil];
		// 4
		[alert setAlertViewStyle:UIAlertViewStyleSecureTextInput]; // Gives us the password field
		alert.tag = kAlertTypePIN;
		// 5
		UITextField *pinField = [alert textFieldAtIndex:0];
		pinField.delegate = self;
		pinField.autocapitalizationType = UITextAutocapitalizationTypeWords;
		pinField.tag = kTextFieldPIN;
		[alert show];
	} else {
		UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Setup Credentials"
														message:@"Secure your Christmas list!"
													   delegate:self
											  cancelButtonTitle:@"Cancel"
											  otherButtonTitles:@"Done", nil];
		// 6
		[alert setAlertViewStyle:UIAlertViewStyleLoginAndPasswordInput];
		alert.tag = kAlertTypeSetup;
		UITextField *nameField = [alert textFieldAtIndex:0];
		nameField.autocapitalizationType = UITextAutocapitalizationTypeWords;
		nameField.placeholder = @"Name"; // Replace the standard placeholder text with something more applicable
		nameField.delegate = self;
		nameField.tag = kTextFieldName;
		UITextField *passwordField = [alert textFieldAtIndex:1]; // Capture the Password text field since there are 2 fields
		passwordField.delegate = self;
		passwordField.tag = kTextFieldPassword;
		[alert show];
	}
}

- (void)alertView:(UIAlertView *)alertView didDismissWithButtonIndex:(NSInteger)buttonIndex
{
	if (alertView.tag == kAlertTypePIN) {
		if (buttonIndex == 1 && self.pinValidated) { // User selected "Done"
			ViewController *mainview = [[ViewController alloc]init];
			[self.navigationController pushViewController:mainview animated:YES];
			self.pinValidated = NO;
		} else { // User selected "Cancel"
			[self presentAlertViewForPassword];
		}
	} else if (alertView.tag == kAlertTypeSetup) {
		if (buttonIndex == 1 && [self credentialsValidated]) { // User selected "Done"
			ViewController *mainview = [[ViewController alloc]init];
			[self.navigationController pushViewController:mainview animated:YES];

		} else { // User selected "Cancel"
			[self presentAlertViewForPassword];
		}
	}
}

// Helper method to congregate the Name and PIN fields for validation.
- (BOOL)credentialsValidated
{
	NSString *name = USERNAME;
	BOOL pin = [[NSUserDefaults standardUserDefaults] boolForKey:PIN_SAVED];
	if (name && pin) {
		return YES;
	} else {
		return NO;
	}
}

#pragma mark - Text Field + Alert View Methods
- (void)textFieldDidEndEditing:(UITextField *)textField
{
	// 1
	switch (textField.tag)
	{
		case kTextFieldPIN: // We go here if this is the 2nd+ time used (we've already set a PIN at Setup).
			NSLog(@"User entered PIN to validate");
			if ([textField.text length] > 0)
			{
				// 2
				//NSString *securedPin = textField.text;
				NSString *securedPin = [KeychainWrapper securedSHA256DigestHashForPIN:textField.text withAccount:[[NSUserDefaults standardUserDefaults] stringForKey:USERNAME]];
				// 3
				if ([KeychainWrapper compareKeychainValueForMatchingPINValue:securedPin withAccount:USERNAME forService:APP_NAME]) { // Compare them
					NSLog(@"** User Authenticated!!");
					self.pinValidated = YES;
				} else {
					NSLog(@"** Wrong Password :(");
					self.pinValidated = NO;
				}
			}
			break;
		case kTextFieldName: // 1st part of the Setup flow.
			NSLog(@"User entered name");
			if ([textField.text length] > 0)
			{
				[[NSUserDefaults standardUserDefaults] setValue:textField.text forKey:@"username"];
				[[NSUserDefaults standardUserDefaults] synchronize];
			}
			break;
		case kTextFieldPassword: // 2nd half of the Setup flow.
			NSLog(@"User entered PIN");
			if ([textField.text length] > 0)
			{
				//NSString *securedPin = textField.text;
				NSString *securedPin = [KeychainWrapper securedSHA256DigestHashForPIN:textField.text withAccount:[[NSUserDefaults standardUserDefaults] stringForKey:USERNAME]];

				// Save PIN hash to the keychain (NEVER store the direct PIN)
				if ([KeychainWrapper createKeychainValue:securedPin withAccount:USERNAME forService:APP_NAME]) {
					[[NSUserDefaults standardUserDefaults] setBool:YES forKey:PIN_SAVED];
					[[NSUserDefaults standardUserDefaults] synchronize];
					NSLog(@"** Key saved successfully to Keychain!!");
				}
			}
			break;
		default:
			break;
	}
}

@end
