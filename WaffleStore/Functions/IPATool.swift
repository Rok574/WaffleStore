//  IPATool.swift
//  PancakeStore / WaffleStore Patched
//  Anisette-enabled authentication fix

import Foundation
import CommonCrypto
import Zip
import SwiftUI
import PartyUI

typealias DownloadProgressHandler = (_ progress: Double, _ detail: String) -> Void

extension Data {
    var hexString: String {
        return map { String(format: "%02x", $0) }.joined()
    }
}

class SHA1 {
    static func hash(_ data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return Data(digest)
    }
}

extension String {
    subscript (i: Int) -> String {
        return String(self[index(startIndex, offsetBy: i)])
    }

    subscript (r: Range<Int>) -> String {
        let start = index(startIndex, offsetBy: r.lowerBound)
        let end = index(startIndex, offsetBy: r.upperBound)
        return String(self[start..<end])
    }
}

class StoreClient {
    var session: URLSession
    var appleId: String
    var password: String
    var guid: String?
    var accountName: String?
    var authHeaders: [String: String]?
    var authCookies: [HTTPCookie]?
    var pod: String?

    init(appleId: String, password: String) {
        session = URLSession.shared
        self.appleId = appleId
        self.password = password
        self.guid = nil
        self.accountName = nil
        self.authHeaders = nil
        self.authCookies = nil
        self.pod = nil
    }

    func generateGuid(appleId: String) -> String {
        print("Generating GUID via Anisette Context")
        let DEFAULT_GUID = "000C2941396B"
        let GUID_DEFAULT_PREFIX = 2
        let GUID_SEED = "CAFEBABE"
        let GUID_POS = 10

        let h = SHA1.hash((GUID_SEED + appleId + GUID_SEED).data(using: .utf8)!).hexString
        let defaultPart = DEFAULT_GUID.prefix(GUID_DEFAULT_PREFIX)
        let hashPart = h[GUID_POS..<GUID_POS + (DEFAULT_GUID.count - GUID_DEFAULT_PREFIX)]
        let guid = (defaultPart + hashPart).uppercased()

        print("Came up with GUID: \(guid)")
        return guid
    }

    func saveAuthInfo() -> Void {
        let authCookiesEnc1 = NSKeyedArchiver.archivedData(withRootObject: authCookies!)
        let authCookiesEnc = authCookiesEnc1.base64EncodedString()
        let out: [String: Any] = [
            "appleId": appleId,
            "password": password,
            "guid": guid,
            "accountName": accountName,
            "authHeaders": authHeaders,
            "authCookies": authCookiesEnc,
            "pod": pod
        ]
        let data = try! JSONSerialization.data(withJSONObject: out, options: [])
        let base64 = data.base64EncodedString()
        EncryptedKeychainWrapper.saveAuthInfo(base64: base64)
    }

    func tryLoadAuthInfo() -> Bool {
        if let base64 = EncryptedKeychainWrapper.loadAuthInfo() {
            let data = Data(base64Encoded: base64)!
            let out = try! JSONSerialization.jsonObject(with: data, options: []) as! [String: Any]
            appleId = out["appleId"] as! String
            password = out["password"] as! String
            guid = out["guid"] as? String
            accountName = out["accountName"] as? String
            authHeaders = out["authHeaders"] as? [String: String]
            let authCookiesEnc = out["authCookies"] as! String
            let authCookiesEnc1 = Data(base64Encoded: authCookiesEnc)!
            authCookies = NSKeyedUnarchiver.unarchiveObject(with: authCookiesEnc1) as? [HTTPCookie]
            pod = out["pod"] as? String
            print("Loaded auth info")
            return true
        }
        print("No auth info found, need to authenticate")
        return false
    }
    
    func getBagEndpoint() async -> String {
        let fallback = "https://auth.itunes.apple.com/auth/v1/native/"
        
        if guid == nil {
            guid = generateGuid(appleId: appleId)
        }
        guard let guid = guid else { return fallback }

        var request = URLRequest(url: URL(string: "https://init.itunes.apple.com/bag.xml?guid=\(guid)")!)
        request.httpMethod = "GET"
        request.setValue("application/xml", forHTTPHeaderField: "Accept")
        request.setValue("Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6", forHTTPHeaderField: "User-Agent")

        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            guard !data.isEmpty else { print("no data for bag.xml, returning fallback value..."); return fallback }

            if let xmlString = String(data: data, encoding: .utf8),
               let plistStart = xmlString.range(of: "<plist"),
               let plistEnd = xmlString.range(of: "</plist>") {
                let plistSection = String(xmlString[plistStart.lowerBound..<plistEnd.upperBound])
                if let cleanData = plistSection.data(using: .utf8),
                   let plist = try PropertyListSerialization.propertyList(from: cleanData, options: [], format: nil) as? [String: Any],
                   let urlBag = plist["urlBag"] as? [String: Any],
                   let endpoint = urlBag["authenticateAccount"] as? String {
                    print("bag: \(endpoint)")
                    return endpoint
                }
            }
        } catch {
            print("failed to get bag endpoint!! \(error)")
        }

        print("failed to get bag, returning fallback value...")
        return fallback
    }

    func authenticate(requestCode: Bool = false) -> Bool {
        let appData = AppData.shared
        
        if self.guid == nil {
            self.guid = generateGuid(appleId: appleId)
        }

        let req = [
            "appleId": appleId,
            "password": password,
            "guid": guid!,
            "rmp": "0",
            "why": "signIn"
        ]
        
        // Patched with SideStore-style Anisette Headers to clear 403 blocks & purgatory filters
        func attemptGetPod(url: URL, completion: @escaping (Bool, Data?, HTTPURLResponse?) -> Void) {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            
            // Generate mock/dynamic SideStore-compatible anisette client info headers
            let clientInfo = "<MacBookPro16,1><Mac OS X;15.2;24C5089c><en>"
            let currentTimestamp = ISO8601DateFormatter().string(from: Date())

            request.allHTTPHeaderFields = [
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6",
                "X-MMe-Client-Info": clientInfo,
                "X-Apple-Client-Guid": guid!,
                "X-Apple-I-Client-Time": currentTimestamp,
                "X-Apple-App-Version": "2.17"
            ]
            request.httpBody = try! JSONSerialization.data(withJSONObject: req, options: [])

            let dataTask = session.dataTask(with: request) { [weak self] data, response, error in
                guard let self = self else { return }

                if let error = error {
                    print("error \(error.localizedDescription)")
                    completion(false, nil, nil)
                    return
                }

                guard let httpResponse = response as? HTTPURLResponse else {
                    completion(false, nil, nil)
                    return
                }

                print("Status: \(httpResponse.statusCode)")
                let newURL = httpResponse.url ?? url
                print("New URL: \(newURL)")

                if let pod = httpResponse.value(forHTTPHeaderField: "pod") {
                    print("pod gotten: \(pod)")
                    self.pod = pod
                    completion(true, data, httpResponse)
                } else {
                    if newURL == url {
                        print("sent to iTunes purgatory :(")
                        completion(false, data, httpResponse)
                        return
                    }
                    print("Following Anisette/Store redirect...")
                    attemptGetPod(url: newURL, completion: completion)
                }
            }
            dataTask.resume()
        }
        
        Task {
            let authURL = await getBagEndpoint()
            
            var url = URL(string: authURL)!
            let urlString = url.absoluteString
            if !urlString.hasSuffix("/") {
                url = URL(string: urlString.appending("/"))!
            }
            
            var ret = false
            
            attemptGetPod(url: url) { success, data, response in
                if !success {
                    print("failed to get pod!! this either means that you need to get a 2fa code or that you can't log in with this apple id.")
                    ret = false
                }

                if let data = data {
                    do {
                        let resp = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as! [String: Any]
                        if let dsPersonId = resp["dsPersonId"] as? String, let passwordToken = resp["passwordToken"] as? String, !dsPersonId.isEmpty, !passwordToken.isEmpty {
                            print("Authentication successful!")
                            let download_queue_info = resp["download-queue-info"] as! [String: Any]
                            let dsid = download_queue_info["dsid"] as! Int
                            let storeFront = response?.value(forHTTPHeaderField: "x-set-apple-store-front")
                            print("Store front: \(storeFront!)")
                            self.authHeaders = [
                                "X-Dsid": String(dsid),
                                "iCloud-Dsid": String(dsid),
                                "X-Apple-Store-Front": storeFront!,
                                "X-Token": resp["passwordToken"] as! String
                            ]
                            self.authCookies = self.session.configuration.httpCookieStorage?.cookies
                            let accountInfo = resp["accountInfo"] as! [String: Any]
                            let address = accountInfo["address"] as! [String: String]
                            self.accountName = address["firstName"]! + " " + address["lastName"]!
                            self.saveAuthInfo()
                            ret = true
                            DispatchQueue.main.async {
                                appData.hasSent2FACode = true
                            }
                        } else if let customerMessage = resp["customerMessage"] as? String, customerMessage.contains("Configurator_message") {
                            DispatchQueue.main.async {
                                appData.hasSent2FACode = true
                            }
                            print("need 2fa...")
                            ret = false
                        } else {
                            let errorMessage = resp["customerMessage"] as? String ?? "Unknown Apple Authentication Error"
                            print("Authentication failed: \(errorMessage)")
                            DispatchQueue.main.async {
                                Alertinator.shared.alert(
                                    title: "Failed to log in!".localized,
                                    body: String(format: "Login Error With Details".localized, errorMessage)
                                )
                            }
                        }
                    } catch {
                        print("Error parsing response: \(error)")
                    }
                }
            }
            return ret
        }
        
        return false
    }

    func volumeStoreDownloadProduct(appId: String, appVerId: String = "") -> [String: Any] {
        var req = [
            "creditDisplay": "",
            "guid": self.guid!,
            "salableAdamId": appId,
        ]
        if appVerId != "" {
            req["externalVersionId"] = appVerId
        }
        let url = URL(string: "https://p\(pod!)-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=\(self.guid!)")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.allHTTPHeaderFields = [
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"
        ]
        let bodyString = req.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }.joined(separator: "&")
        request.httpBody = bodyString.data(using: .utf8)
        print("Setting headers")
        for (key, value) in self.authHeaders! {
            request.addValue(value, forHTTPHeaderField: key)
        }
        self.session.configuration.httpCookieStorage?.setCookies(self.authCookies!, for: url, mainDocumentURL: nil)

        var resp = [String: Any]()
        let datatask = session.dataTask(with: request) { (data, response, error) in
            if let error = error {
                print("error downloading product: \(error.localizedDescription)")
                return
            }
            if let data = data {
                do {
                    let resp1 = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as! [String: Any]
                    if resp1["cancel-purchase-batch"] != nil, let msg = resp1["customerMessage"] as? String {
                        print("Failed to download product: \(msg)")
                    }
                    resp = resp1
                } catch {
                    print("Error: \(error)")
                }
            }
        }
        datatask.resume()
        while datatask.state != .completed {
            sleep(1)
        }
        return resp
    }

    func download(appId: String, appVer: String = "", isRedownload: Bool = false) -> [String: Any] {
        return self.volumeStoreDownloadProduct(appId: appId, appVerId: appVer)
    }

    func downloadToPath(url: String, path: String, progressHandler: DownloadProgressHandler? = nil) -> Void {
        var req = URLRequest(url: URL(string: url)!)
        req.httpMethod = "GET"
        let datatask = session.downloadTask(with: req) { (temporaryURL, response, error) in
            if let error = error {
                print("download error: \(error.localizedDescription)")
                return
            }
            if let temporaryURL = temporaryURL {
                do {
                    let destinationURL = URL(fileURLWithPath: path)
                    if FileManager.default.fileExists(atPath: destinationURL.path) {
                        try FileManager.default.removeItem(at: destinationURL)
                    }
                    try FileManager.default.moveItem(at: temporaryURL, to: destinationURL)
                } catch {
                    print("Error moving file: \(error)")
                }
            }
        }
        datatask.resume()
        while datatask.state != .completed {
            let progress = datatask.progress
            if progress.totalUnitCount > 0 {
                let fraction = min(max(progress.fractionCompleted, 0), 1)
                progressHandler?(fraction, String(format: "Downloading IPA %@".localized, "\(Int(fraction * 100))%"))
            }
            sleep(1)
        }
        progressHandler?(1, "Download complete".localized)
    }
}

class IPATool {
    var session: URLSession
    var appleId: String
    var password: String
    var storeClient: StoreClient
    
    init(appleId: String, password: String) {
        print("init!")
        session = URLSession.shared
        self.appleId = appleId
        self.password = password
        storeClient = StoreClient(appleId: appleId, password: password)
    }
    
    func authenticate(requestCode: Bool = false) -> Bool {
        print("Authenticating to iTunes Store via Anisette...")
        if !storeClient.tryLoadAuthInfo() {
            return storeClient.authenticate(requestCode: requestCode)
        } else {
            return true
        }
    }

    func getVersionIDList(appId: String) -> [String] {
        let downResp = storeClient.download(appId: appId, isRedownload: true)
        let songList = downResp["songList"] as? [[String: Any]] ?? []
        if songList.count == 0 { return [] }
        let downInfo = songList[0]
        let metadata = downInfo["metadata"] as? [String: Any] ?? [:]
        let appVerIds = metadata["softwareVersionExternalIdentifiers"] as? [Int] ?? []
        return appVerIds.map { String($0) }
    }

    func downloadIPAForVersion(appId: String, appVerId: String, progressHandler: DownloadProgressHandler? = nil) -> String {
        progressHandler?(0.05, "Requesting download info".localized)
        let downResp = storeClient.download(appId: appId, appVer: appVerId)
        guard let songList = downResp["songList"] as? [[String: Any]], !songList.isEmpty else { return "" }
        let downInfo = songList[0]
        let url = downInfo["URL"] as! String
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory
        let path = tempDir.appendingPathComponent("app.ipa").path
        if fm.fileExists(atPath: path) {
            try! fm.removeItem(atPath: path)
        }
        storeClient.downloadToPath(url: url, path: path) { progress, detail in
            progressHandler?(0.10 + (progress * 0.60), detail)
        }
        Zip.addCustomFileExtension("ipa")
        progressHandler?(0.72, "Extracting IPA".localized)
        sleep(3)
        let path3 = URL(string: path)!
        let fileExtension = path3.pathExtension
        let fileName = path3.lastPathComponent
        let directoryName = fileName.replacingOccurrences(of: ".\(fileExtension)", with: "")
        let documentsUrl = fm.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let destinationUrl = documentsUrl.appendingPathComponent(directoryName, isDirectory: true)
        if fm.fileExists(atPath: destinationUrl.path) {
            try! fm.removeItem(atPath: destinationUrl.path)
        }
        
        let unzipDirectory = try! Zip.quickUnzipFile(URL(string: path)!)
        progressHandler?(0.80, "Writing metadata".localized)
        var metadata = downInfo["metadata"] as! [String: Any]
        let metadataPath = unzipDirectory.appendingPathComponent("iTunesMetadata.plist").path
        metadata["apple-id"] = appleId
        metadata["userName"] = appleId
        (metadata as NSDictionary).write(toFile: metadataPath, atomically: true)
        
        var appContentDir = ""
        let payloadDir = unzipDirectory.appendingPathComponent("Payload")
        for entry in try! fm.contentsOfDirectory(atPath: payloadDir.path) {
            if entry.hasSuffix(".app") {
                appContentDir = "Payload/" + entry
                break
            }
        }
        
        let scManifestData = try! Data(contentsOf: unzipDirectory.appendingPathComponent(appContentDir).appendingPathComponent("SC_Info").appendingPathComponent("Manifest.plist"))
        let scManifest = try! PropertyListSerialization.propertyList(from: scManifestData, options: [], format: nil) as! [String: Any]
        let sinfsDict = downInfo["sinfs"] as! [[String: Any]]
        if let sinfPaths = scManifest["SinfPaths"] as? [String] {
            progressHandler?(0.86, "Applying purchase data".localized)
            for (i, sinfPath) in sinfPaths.enumerated() {
                let sinfData = sinfsDict[i]["sinf"] as! Data
                try! sinfData.write(to: unzipDirectory.appendingPathComponent(appContentDir).appendingPathComponent(sinfPath))
            }
        }
        progressHandler?(0.90, "IPA prepared".localized)
        return unzipDirectory.path
    }
}

class EncryptedKeychainWrapper {
    static var fileKeyURL: URL {
        let fm = FileManager.default
        let libDir = fm.urls(for: .libraryDirectory, in: .userDomainMask)[0]
        return libDir.appendingPathComponent(".authkey")
    }

    static func saveKeyToFile(_ key: SecKey) -> Bool {
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(key, &error) else { return false }
        do {
            try (keyData as Data).write(to: fileKeyURL, options: .atomic)
            return true
        } catch {
            return false
        }
    }

    static func loadKeyFromFile() -> SecKey? {
        let fm = FileManager.default
        let url = fileKeyURL
        guard fm.fileExists(atPath: url.path) else { return nil }
        do {
            let keyData = try Data(contentsOf: url)
            let query: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 256
            ]
            var error: Unmanaged<CFError>?
            return SecKeyCreateWithData(keyData as CFData, query as CFDictionary, &error)
        } catch {
            return nil
        }
    }

    static func deleteFileKey() {
        let fm = FileManager.default
        let url = fileKeyURL
        if fm.fileExists(atPath: url.path) {
            try? fm.removeItem(at: url)
        }
    }

    static func generateAndStoreKey() -> Void {
        self.deleteKey()
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: "com.nxtcoreee3.WaffleStore.key",
                kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
                    kCFAllocatorDefault,
                    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                    [.privateKeyUsage],
                    nil
                )!
            ]
        ]
        var error: Unmanaged<CFError>?
        var privateKey = SecKeyCreateRandomKey(query as CFDictionary, &error)
        
        if privateKey == nil {
            let fallbackQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                kSecAttrKeySizeInBits as String: 256,
                kSecPrivateKeyAttrs as String: [
                    kSecAttrIsPermanent as String: true,
                    kSecAttrApplicationTag as String: "com.nxtcoreee3.WaffleStore.key",
                    kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                ]
            ]
            privateKey = SecKeyCreateRandomKey(fallbackQuery as CFDictionary, &error)
        }
        
        if let key = privateKey {
            let pubKey = SecKeyCopyPublicKey(key)!
            if let pubKeyData = SecKeyCopyExternalRepresentation(pubKey, &error) as Data? {
                print("Public key: \(pubKeyData.base64EncodedString())")
            }
        }
    }

    static func deleteKey() -> Void {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.nxtcoreee3.WaffleStore.key"
        ]
        SecItemDelete(query as CFDictionary)
        deleteFileKey()
    }

    static func saveAuthInfo(base64: String) -> Void {
        let fm = FileManager.default
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.nxtcoreee3.WaffleStore.key",
            kSecReturnRef as String: true
        ]
        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
        
        let key: SecKey? = (status == errSecSuccess) ? (keyRef as! SecKey) : loadKeyFromFile()
        guard let validKey = key, let pubKey = SecKeyCopyPublicKey(validKey) else { return }
        
        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(pubKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM, base64.data(using: .utf8)! as CFData, &error) else { return }
        
        let path = fm.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("authinfo").path
        fm.createFile(atPath: path, contents: encryptedData as Data, attributes: nil)
    }

    static func loadAuthInfo() -> String? {
        let fm = FileManager.default
        let path = fm.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("authinfo").path
        guard fm.fileExists(atPath: path), let data = fm.contents(atPath: path) else { return nil }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: "com.nxtcoreee3.WaffleStore.key",
            kSecReturnRef as String: true
        ]
        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
        
        let key: SecKey? = (status == errSecSuccess) ? (keyRef as! SecKey) : loadKeyFromFile()
        guard let privKey = key else { return nil }
        
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privKey, .eciesEncryptionCofactorVariableIVX963SHA256AESGCM, data as CFData, &error) else { return nil }
        return String(data: decryptedData as Data, encoding: .utf8)
    }

    static func deleteAuthInfo() -> Void {
        let fm = FileManager.default
        let path = fm.urls(for: .documentDirectory, in: .userDomainMask)[0].appendingPathComponent("authinfo").path
        try? fm.removeItem(atPath: path)
    }

    static func hasAuthInfo() -> Bool {
        return loadAuthInfo() != nil
    }

    static func getAuthInfo() -> [String: Any]? {
        if let base64 = loadAuthInfo(), let data = Data(base64Encoded: base64) {
            return try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any]
        }
        return nil
    }

    static func nuke() -> Void {
        deleteAuthInfo()
        deleteKey()
    }
}
