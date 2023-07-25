#  SSL Pinning

There are different ways to implement SSL Pinning in iOS. The easiest way is to use **Info.plist** which in my **SSLPinningTest-Info** target. The other two methods are **certificate pinning** and **public key pinning**.

I struggled a lot and found a few youtube videos and articles about SSL Public Key Pinning in Swift. Unfortunately none of them are working. Normally they're using the following way to calculate the public key hash:

```
    private static let rsa2048Asn1Header:[UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ];
    
    static func sha256(data : Data) -> String {
        
        var keyWithHeader = Data(Hasher.rsa2048Asn1Header)
        keyWithHeader.append(data)
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        keyWithHeader.withUnsafeBytes { buffer in
            _ = CC_SHA256(buffer.baseAddress!, CC_LONG(buffer.count), &hash)
        }
        return Data(hash).base64EncodedString()
    }
```

I created a Objective-C class `PublicKeyCalculator` for this purpose. And it works!


## Basic knowledge of certificate

- Certificate (public) may not be the same for https://google.com and https://www.google.com. The common name in certificate will be the domain name.
- There are different types of certificate, such as root, intermediate and leaf certificate. 
- Certificate has different format: **DER** or **CER**(PEM). To verify if it's the correct format, can use the following commands:

**For PEM**:
`openssl x509 -in cert.cer -text -noout`

**For DER**:
`openssl x509 -in certificate.der -inform der -text -noout`

- Convert **PEM** to **DER**

```
openssl x509 -in cert.crt -outform der -out cert.der
```

- Convert **DER** to **PEM**

```
openssl x509 -in certificate.der -outform pem -out certificate.pem
```

## Download DER certificate

```
openssl s_client -connect jsonplaceholder.typicode.com:443 -showcerts < /dev/null | openssl x509 -outform der > certificate.der
```

## Download PEM certificate

```
openssl s_client -showcerts -connect jsonplaceholder.typicode.com:443 </dev/null 2>/dev/null|openssl x509 -outform PEM >certificate.pem
```

## Get the public key

From **PEM** certificate:

```
cat certificate.pem |
      openssl x509 -inform pem -noout -outform pem -pubkey |
      openssl pkey -pubin -inform pem -outform der |
      openssl dgst -sha256 -binary |
      openssl enc -base64
```

From **DER** certificate: Convert to **PEM** then use the above mentioned method to get the public key

In one command line, to download and get the public key:

```
openssl s_client -showcerts -servername jsonplaceholder.typicode.com -connect jsonplaceholder.typicode.com:443 </dev/null 2>/dev/null|openssl x509 -outform PEM | openssl x509 -inform pem -noout -outform pem -pubkey | openssl pkey -pubin -inform pem -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

## Testing

### Test Info.plist SSL Pinning

Get the public key and replace it or append in `SSLPinningTest-Info-Info.plist`. To test the pinning is working, just change the `SPKI-SHA256-BASE64` to a wrong key. 

### Certificate Pinning or Public Key pinning

Download the certifcate.der (**DER** format) and add to project for certificate pinning.
Get the public key and replace the `localPublicKey` in `Hasher` class for public key pinning.



