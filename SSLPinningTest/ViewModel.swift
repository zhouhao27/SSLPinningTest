//
//  ViewModel.swift
//  SSLPinningTest
//
//  Created by Zhou Hao on 25/7/23.
//

import Foundation
import Observation
import CommonCrypto

extension Array {
    
    init(_ array: CFArray) {
        self = (0..<CFArrayGetCount(array)).map {
            unsafeBitCast(
                CFArrayGetValueAtIndex(array, $0),
                to: Element.self
            )
        }
    }
}

@Observable
class UserViewModel: NSObject {
    var username = ""
    var email = ""
    var loading = false
    @ObservationIgnored var isPublicKeyPinning = false
    
    func reloadData(publicKeyPinning: Bool = false) async {
        defer {
            loading = false
        }
        
        isPublicKeyPinning = publicKeyPinning
        loading = true
        let randomInt = Int.random(in: 1..<10)
        guard let url = URL(string: "https://jsonplaceholder.typicode.com/users/\(randomInt)") else {
            return
        }
        
        do {
#if INFO
            print("Info.plist pinning")
            let session = URLSession.shared
#else
            print("Certificate/Public Key pinning")
            let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
            print(publicKeyPinning ? "Public key pinning" : "Certificate pinning")
#endif
            
            let (data, response) = try await session.data(from: url)
            
            guard let response = response as? HTTPURLResponse, response.statusCode == 200 else {
                print("Failed to get http response")
                return
            }
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase
            let user = try decoder.decode(User.self, from: data)
            username = user.username
            email = user.email
            
        } catch {
            print("Failed to load data: \(error.localizedDescription)")
        }
    }
}

extension UserViewModel: URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust, let certificateArray = SecTrustCopyCertificateChain(serverTrust) else {
            completionHandler(.cancelAuthenticationChallenge, nil);
            return
        }
        
        let serverCertificates = [SecCertificate](certificateArray)
        
        guard serverCertificates.count > 0 else {
            completionHandler(.cancelAuthenticationChallenge, nil);
            return
        }
        
        // Here I only work on leaf certificate, 1 - intermediate certificate, 2 - root certificate
        let leafCertificate = serverCertificates[0]
        
        if isPublicKeyPinning {
            if publicKeyPinning(certificate: leafCertificate) {
                print("Public key pinning success!")
                completionHandler(.useCredential, URLCredential(trust:serverTrust))
            } else {
                print("Public key pinning failed!")
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        } else {
            if certificatePinning(challenge: challenge, serverTrust: serverTrust, certificate: leafCertificate) {
                print("Certificate pinning success!")
                completionHandler(.useCredential, URLCredential(trust:serverTrust))
            } else {
                print("Certificate pinning failed!")
                completionHandler(.cancelAuthenticationChallenge,nil)
            }
        }
        
    }
    
    private func certificatePinning(challenge: URLAuthenticationChallenge, serverTrust: SecTrust, certificate: SecCertificate) -> Bool {
        
        // SSL Policies for domain name check
        let policy = NSMutableArray()
        policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
        
        //Evaluate server certifiacte
        let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
        
        //Local and Remote certificates Data
        let remoteCertificateData:NSData =  SecCertificateCopyData(certificate)
        
        let pathToCertificate = Bundle.main.resourcePath! + "/\(Hasher.localCertificateFile)"
        let localCertificateData:NSData = NSData(contentsOfFile: pathToCertificate)!
        
        //Compare certificates
        return isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)
    }
    
    private func publicKeyPinning(certificate: SecCertificate) -> Bool {
        var success = false
                
        // Server public key
        if let serverPublicKey = SecCertificateCopyKey(certificate) {
                        
//            if let attributes = SecKeyCopyAttributes(serverPublicKey) as? [CFString: Any],
//                let keyType = attributes[kSecAttrKeyType] as? String {
//                let isRSA = keyType == (kSecAttrKeyTypeRSA as String)
//            }

            // This doesn't work!!!
/*
            // Server public key Data
            let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey, nil )!
            let data:Data = serverPublicKeyData as Data
            
            // Server Hash key
            let serverHashKey = Hasher.sha256(data: data)
            // Local Hash Key
            let publickKeyLocal = Hasher.localPublicKey
            
            print("serverHash = \(serverHashKey), localHash=\(publickKeyLocal)")
            
            if (serverHashKey == publickKeyLocal) {
                success = true
                print("SSL Pinnig with Public key is successfully completed")
            }
*/
            
            let serverHashKey = PublicKeyCalculator.getPublicKeyHash(serverPublicKey)
            if (serverHashKey == Hasher.localPublicKey) {
                success = true
                print("SSL Pinnig with Public key is successfully completed")
            }
            
        }
        
        return success
    }
}

// This doesn't work. I guess the reason is Swift is using different encryption type other than RSA. 
final class Hasher {
    
    public static let localPublicKey = "pBFMLdJPHlDAMeMLz1oVJqseO92HqTu456/X+TGJqOU="
    public static let localCertificateFile = "certificate.der"
    
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
}
