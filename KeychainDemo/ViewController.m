//
//  ViewController.m
//  KeychainDemo
//
//  Created by BILLY HO on 11/13/14.
//  Copyright (c) 2014 BILLY HO. All rights reserved.
//

#import "ViewController.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
	[super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
	
	
	UILabel *label = [[UILabel alloc] initWithFrame:CGRectMake(50, 100, 200, 50)];
	label.text = @"Main";
	
	[self.view addSubview:label];
	
}

- (void)didReceiveMemoryWarning {
	[super didReceiveMemoryWarning];
	// Dispose of any resources that can be recreated.
}

@end
