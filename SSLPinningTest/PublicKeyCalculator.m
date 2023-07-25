//
//  PublicKeyCalculator.m
//  SSLPinningTest
//
//  Created by Zhou Hao on 25/7/23.
//

#import <Foundation/Foundation.h>
#include <CommonCrypto/CommonDigest.h>

#import "PublicKeyCalculator.h"

@implementation PublicKeyCalculator

#pragma mark public key

static const unsigned char rsa2048PublicKeyInfoASN1Header[] = { 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00 };

static const unsigned char rsa4096PublicKeyInfoASN1Header[] = { 0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00 };

static const unsigned char ecdsasecp256r1PublicKeyInfoASN1Header[] = { 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00 };

static const unsigned char ecdsasecp384r1PublicKeyInfoASN1Header[] = { 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00 };

static const unsigned char *asn1PublicKeyInfoHeaderBytes(NSString *publicKeyType, NSUInteger publicKeySize)
{
  if ([publicKeyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA] && publicKeySize == 2048) {
    return rsa2048PublicKeyInfoASN1Header;
  }
  else if ([publicKeyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA] && publicKeySize == 4096) {
    return rsa4096PublicKeyInfoASN1Header;
  }
  else if ([publicKeyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom] && publicKeySize == 256) {
    return ecdsasecp256r1PublicKeyInfoASN1Header;
  }
  else if ([publicKeyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom] && publicKeySize == 384) {
    return ecdsasecp384r1PublicKeyInfoASN1Header;
  }
    
  return nil;
}

static size_t asn1PublicKeyInfoHeaderSize(NSString *publicKeyType, NSUInteger publicKeySize)
{
  if ([publicKeyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA] && publicKeySize == 2048) {
    return sizeof(rsa2048PublicKeyInfoASN1Header);
  }
  else if ([publicKeyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA] && publicKeySize == 4096) {
    return sizeof(rsa4096PublicKeyInfoASN1Header);
  }
  else if ([publicKeyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom] && publicKeySize == 256) {
    return sizeof(ecdsasecp256r1PublicKeyInfoASN1Header);
  }
  else if ([publicKeyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom] && publicKeySize == 384) {
    return sizeof(ecdsasecp384r1PublicKeyInfoASN1Header);
  }
    
  return 0;
}

#pragma mark public interface

+(NSString*) getPublicKeyHash:(SecKeyRef)secKey {
    
    NSData *leafPublicKeyData = (__bridge_transfer NSData *)SecKeyCopyExternalRepresentation(secKey, NULL); // 5. Convert the public key into its data representation
    NSDictionary *leafPublicKeyAttributes = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(secKey); // 6. Get the pubic key's attributes
    NSString *leafKeyType = leafPublicKeyAttributes[(__bridge NSString *)kSecAttrKeyType]; // 7. Get the type of the key
    NSUInteger leafKeySize = ((NSNumber *)leafPublicKeyAttributes[(__bridge NSString *)kSecAttrKeySizeInBits]).unsignedIntegerValue; // 8. Get the size of the key
    
    const unsigned char *headerBytes = asn1PublicKeyInfoHeaderBytes(leafKeyType, leafKeySize); // 9. Get the SubjectPublicKeyInfo header
    size_t headerSize = asn1PublicKeyInfoHeaderSize(leafKeyType, leafKeySize); // 10. Get the SubjectPublicKeyInfo header size
    
    NSMutableData *publicKeyInfoHash = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH]; // 11. Create a data object to store the result of the SHA-256 computation
    NSMutableData *publicKeyAndHeaderData = [NSMutableData dataWithBytes:headerBytes length:headerSize]; // 12. Combine the key and header data
    [publicKeyAndHeaderData appendData:leafPublicKeyData];
    
    CC_SHA256(publicKeyAndHeaderData.bytes, (CC_LONG)publicKeyAndHeaderData.length, (unsigned char *)publicKeyInfoHash.bytes); // 13. Compute the SHA-256 hash
    
    NSString *computedHash = [publicKeyInfoHash base64EncodedStringWithOptions:kNilOptions]; // 14. Encode the hash as a Base64 string
    return computedHash;
}

@end
