//
//  DMPasscode.m
//  DMPasscode
//
//  Created by Dylan Marriott on 20/09/14.
//  Copyright (c) 2014 Dylan Marriott. All rights reserved.
//

#import "DMPasscode.h"
#import "DMPasscodeInternalNavigationController.h"
#import "DMPasscodeInternalViewController.h"
#import "SSKeychain.h"
#import "NSString+md5Digest.h"

#ifdef __IPHONE_8_0
#import <LocalAuthentication/LocalAuthentication.h>
#endif

static DMPasscode* instance;

@interface DMPasscode () <DMPasscodeInternalViewControllerDelegate>
@end

@implementation DMPasscode {
    PasscodeCompletionBlock _completion;
    DMPasscodeInternalViewController* _passcodeViewController;
    int _mode; // 0 = setup, 1 = input
    int _count;
    NSString* _prevCode;
    DMPasscodeConfig* _config;
    NSString* _userName;
    NSString* _service;
}

+ (void)initialize {
    [super initialize];
    instance = [[DMPasscode alloc] init];
}

- (instancetype)init {
    if (self = [super init]) {
        _config = [[DMPasscodeConfig alloc] init];
    }
    return self;
}

#pragma mark - Public
+ (void)setupPasscodeInViewController:(UIViewController *)viewController
                          serviceName:(NSString*)serviceName
                             userName:(NSString*)userName
                           completion:(PasscodeCompletionBlock)completion {
    [instance setupPasscodeInViewController:viewController
                                serviceName:serviceName
                                   userName:userName
                                 completion:completion];
}

+ (void)showPasscodeInViewController:(UIViewController *)viewController
                         serviceName:(NSString*)serviceName
                            userName:(NSString*)userName
                          completion:(PasscodeCompletionBlock)completion {
    [instance showPasscodeInViewController:viewController
                               serviceName:serviceName
                                  userName:userName
                                completion:completion];
}

+ (void)removePasscodeForServiceName:(NSString*)serviceName userName:(NSString*)userName {
    [SSKeychain deletePasswordForService:serviceName account:userName];
}

+ (void)setConfig:(DMPasscodeConfig *)config {
    [instance setConfig:config];
}

#pragma mark - Instance methods
- (void)setupPasscodeInViewController:(UIViewController *)viewController
                          serviceName:(NSString*)serviceName
                             userName:(NSString*)userName
                           completion:(PasscodeCompletionBlock)completion {
    _userName = userName;
    _service = serviceName;
    _completion = completion;
    [self openPasscodeWithMode:0 viewController:viewController];
}


- (void)showPasscodeInViewController:(UIViewController *)viewController
                         serviceName:(NSString*)serviceName
                            userName:(NSString*)userName
                          completion:(PasscodeCompletionBlock)completion {
    _userName = userName;
    _service = serviceName;
    NSAssert([self.class userHashForServiceName:serviceName userName:userName], @"No passcode set");
    _completion = completion;
    
    LAContext* context = [[LAContext alloc] init];
    if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil]) {
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:NSLocalizedString(@"Authenticate to access locked feature.", nil) reply:^(BOOL success, NSError* error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (error) {
                    switch (error.code) {
                        case LAErrorUserCancel:
                        case LAErrorSystemCancel:
                        case LAErrorAuthenticationFailed:
                            _completion(NO);
                            break;
                        case LAErrorPasscodeNotSet:
                        case LAErrorTouchIDNotEnrolled:
                        case LAErrorTouchIDNotAvailable:
                        case LAErrorUserFallback:
                            [self openPasscodeWithMode:1 viewController:viewController];
                            break;
                    }
                } else {
                    _completion(success);
                }
            });
        }];
    } else {
        // no touch id available
        [self openPasscodeWithMode:1 viewController:viewController];
    }
}

+ (NSString*)userHashForServiceName:(NSString*)serviceName userName:(NSString*)userName {
    NSError* error = nil;
    NSString* pass = [SSKeychain passwordForService:serviceName account:userName error:&error];
    if (error) {
        NSLog(@"error retrieving password");
    }
    return pass;
}

- (void)setConfig:(DMPasscodeConfig *)config {
    _config = config;
}

#pragma mark - Private
- (void)openPasscodeWithMode:(int)mode viewController:(UIViewController *)viewController {
    _mode = mode;
    _count = 0;
    _passcodeViewController = [[DMPasscodeInternalViewController alloc] initWithDelegate:self config:_config];
    DMPasscodeInternalNavigationController* nc = [[DMPasscodeInternalNavigationController alloc] initWithRootViewController:_passcodeViewController];
    [viewController presentViewController:nc animated:YES completion:nil];
    if (_mode == 0) {
        [_passcodeViewController setInstructions:NSLocalizedString(@"Enter new code", nil)];
    } else if (_mode == 1) {
        [_passcodeViewController setInstructions:NSLocalizedString(@"Enter code to unlock", nil)];
    }
}

- (void)closeAndNotify:(BOOL)success {
    [_passcodeViewController dismissViewControllerAnimated:YES completion:^() {
        _completion(success);
    }];
}

#pragma mark - DMPasscodeInternalViewControllerDelegate
- (void)enteredCode:(NSString *)code {
    if (_mode == 0) {
        if (_count == 0) {
            _prevCode = code;
            [_passcodeViewController setInstructions:NSLocalizedString(@"Repeat code", nil)];
            [_passcodeViewController reset];
        } else if (_count == 1) {
            if ([code isEqualToString:_prevCode]) {
                NSError* keyChainError = nil;
                BOOL success = [SSKeychain setPassword:[self.class userHashWithCode:code userName:_userName]
                                            forService:_service
                                               account:_userName
                                                 error:&keyChainError];
                
                if (keyChainError) {
                    NSLog(@"failed to create password");
                }
            
                [self closeAndNotify:success];
            } else {
                UIAlertView* errorAlert = [[UIAlertView alloc] initWithTitle:NSLocalizedString(@"Codes did not match, please try again.", nil) message:nil delegate:nil cancelButtonTitle:nil otherButtonTitles:NSLocalizedString(@"Okay", nil), nil];
                [errorAlert show];
                [self closeAndNotify:NO];
            }
        }
    } else if (_mode == 1) {
        NSString* existingHash = [self.class userHashForServiceName:_service userName:_userName];
        NSString* thisHash = [self.class userHashWithCode:code userName:_userName];
        if ([thisHash isEqualToString:existingHash]) {
            [self closeAndNotify:YES];
        } else {
            [_passcodeViewController setErrorMessage:[NSString stringWithFormat:NSLocalizedString(@"%i attempts left", nil), 2 - _count]];
            [_passcodeViewController reset];
            if (_count >= 2) { // max 3 attempts
                [self closeAndNotify:NO];
            }
        }
    }
    _count++;
}

- (void)canceled {
    _completion(NO);
}

+ (NSString*)userHashWithCode:(NSString*)code userName:(NSString*)userName {
    NSString* string = [NSString stringWithFormat:@"%@%@2987diuh;^y", code, userName];
    return [string MD5String];
}

@end
