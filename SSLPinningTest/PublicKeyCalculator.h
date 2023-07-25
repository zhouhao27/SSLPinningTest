//
//  PublicKeyCalculator.h
//  SSLPinningTest
//
//  Created by Zhou Hao on 25/7/23.
//

#ifndef PublicKeyCalculator_h
#define PublicKeyCalculator_h

#import <Foundation/Foundation.h>

@interface PublicKeyCalculator: NSObject

+(NSString*)getPublicKeyHash:(SecKeyRef)secKey;

@end

#endif /* PublicKeyCalculator_h */
