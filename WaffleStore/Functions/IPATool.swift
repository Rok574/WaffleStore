//
//  IPATool.swift
//  PancakeStore / WaffleStore Patched
//  Anisette-enabled authentication fix (Refactored)
//

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
        self.session = URLSession.shared
        self.appleId = appleId
        self.password = password
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

    func saveAuthInfo() {
        guard let authCookies = authCookies else { return }
        let authCookiesEnc1 = NSKeyedArchiver.archivedData(withRootObject: authCookies)
        let authCookiesEnc = authCookiesEnc1.base64EncodedString()
        let out: [String: Any] = [
            "appleId": appleId,
            "password": password,
            "guid": guid ?? "",
            "accountName": accountName ?? "",
            "authHeaders": authHeaders ?? [:],
            "authCookies": authCookiesEnc,
            "pod": pod ?? ""
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: out, options: []) else { return }
        let base64 = data.base64EncodedString()
        EncryptedKeychainWrapper.saveAuthInfo(base64: base64)
    }

    func tryLoadAuthInfo() -> Bool {
        if let base64 = EncryptedKeychainWrapper.loadAuthInfo(),
           let data = Data(base64Encoded: base64),
           let out = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any] {
            appleId = out["appleId"] as? String ?? appleId
            password = out["password"] as? String ?? password
            guid = out["guid"] as? String
            accountName = out["accountName"] as? String
            authHeaders = out["authHeaders"] as? [String: String]
            if let authCookiesEnc = out["authCookies"] as? String,
               let authCookiesEnc1 = Data(base64Encoded: authCookiesEnc),
               let cookies = NSKeyedUnarchiver.unarchiveObject(with: authCookiesEnc1) as? [HTTPCookie] {
                authCookies = cookies
            }
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
            guard !data.isEmpty else { return fallback }

            if let xmlString = String(data: data, encoding: .utf8),
               let plistStart = xmlString.range(of: "<plist"),
               let plistEnd = xmlString.range(of: "</plist>") {
                let plistSection = String(xmlString[plistStart.lowerBound..<plistEnd.upperBound])
                if let cleanData = plistSection.data(using: .utf8),
                   let plist = try PropertyListSerialization.propertyList(from: cleanData, options: [], format: nil) as? [String: Any],
                   let urlBag = plist["urlBag"] as? [String: Any],
                   let endpoint = urlBag["authenticateAccount"] as? String {
                    return endpoint
                }
            }
        } catch {
            print("Failed to get bag endpoint: \(error)")
        }

        return fallback
    }

    func authenticate(requestCode: Bool = false) async -> Bool {
        let appData = AppData.shared
        
        if self.guid == nil {
            self.guid = generateGuid(appleId: appleId)
        }

        let reqDict = [
            "appleId": appleId,
            "password": password,
            "guid": guid!,
            "rmp": "0",
            "why": "signIn"
        ]
        
        let authURLString = await getBagEndpoint()
        guard var url = URL(string: authURLString) else { return false }
        if !url.absoluteString.hasSuffix("/") {
            url = URL(string: url.absoluteString + "/")!
        }

        let clientInfo = "<MacBookPro16,1><Mac OS X;15.2;24C5089c><en>"
        let currentTimestamp = ISO8601DateFormatter().string(from: Date())

        var currentURL = url
        var redirectCount = 0
        let maxRedirects = 5

        while redirectCount < maxRedirects {
            var request = URLRequest(url: currentURL)
            request.httpMethod = "POST"
            request.allHTTPHeaderFields = [
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6",
                "X-MMe-Client-Info": clientInfo,
                "X-Apple-Client-Guid": guid!,
                "X-Apple-I-Client-Time": currentTimestamp,
                "X-Apple-App-Version": "2.17"
            ]
            request.httpBody = try? JSONSerialization.data(withJSONObject: reqDict, options: [])

            do {
                let (data, response) = try await session.data(for: request)
                guard let httpResponse = response as? HTTPURLResponse else { return false }

                let newURL = httpResponse.url ?? currentURL

                if let podHeader = httpResponse.value(forHTTPHeaderField: "pod") {
                    self.pod = podHeader
                    
                    let resp = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as! [String: Any]
                    if let dsPersonId = resp["dsPersonId"] as? String,
                       let passwordToken = resp["passwordToken"] as? String,
                       !dsPersonId.isEmpty, !passwordToken.isEmpty {
                        
                        let queueInfo = resp["download-queue-info"] as? [String: Any] ?? [:]
                        let dsid = queueInfo["dsid"] as? Int ?? 0
                        let storeFront = httpResponse.value(forHTTPHeaderField: "x-set-apple-store-front") ?? ""
                        
                        self.authHeaders = [
                            "X-Dsid": String(dsid),
                            "iCloud-Dsid": String(dsid),
                            "X-Apple-Store-Front": storeFront,
                            "X-Token": passwordToken
                        ]
                        self.authCookies = self.session.configuration.httpCookieStorage?.cookies
                        
                        if let accountInfo = resp["accountInfo"] as? [String: Any],
                           let address = accountInfo["address"] as? [String: String],
                           let firstName = address["firstName"], let lastName = address["lastName"] {
                            self.accountName = "\(firstName) \(lastName)"
                        }
                        
                        self.saveAuthInfo()
                        await MainActor.run { appData.hasSent2FACode = true }
                        return true
                    } else if let customerMessage = resp["customerMessage"] as? String, customerMessage.contains("Configurator_message") {
                        await MainActor.run { appData.hasSent2FACode = true }
                        return false
                    } else {
                        let errorMessage = resp["customerMessage"] as? String ?? "Unknown Apple Authentication Error"
                        await MainActor.run {
                            Alertinator.shared.alert(
                                title: "Failed to log in!".localized,
                                body: String(format: "Login Error With Details".localized, errorMessage)
                            )
                        }
                        return false
                    }
                } else {
                    if newURL == currentURL {
                        return false
                    }
                    currentURL = newURL
                    redirectCount += 1
                }
            } catch {
                print("Authentication error: \(error)")
                return false
            }
        }
        return false
    }

    func volumeStoreDownloadProduct(appId: String, appVerId: String = "") async -> [String: Any] {
        var req = [
            "creditDisplay": "",
            "guid": self.guid!,
            "salableAdamId": appId,
        ]
        if !appVerId.isEmpty {
            req["externalVersionId"] = appVerId
        }
        
        guard let pod = pod, let url = URL(string: "https://p\(pod)-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/volumeStoreDownloadProduct?guid=\(self.guid!)") else {
            return [:]
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.allHTTPHeaderFields = [
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"
        ]
        
        if let authHeaders = authHeaders {
            for (key, value) in authHeaders {
                request.addValue(value, forHTTPHeaderField: key)
            }
        }
        
        if let cookies = authCookies {
            session.configuration.httpCookieStorage?.setCookies(cookies, for: url, mainDocumentURL: nil)
        }

        let bodyString = req.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }.joined(separator: "&")
        request.httpBody = bodyString.data(using: .utf8)

        do {
            let (data, _) = try await session.data(for: request)
            if let resp1 = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
                if resp1["cancel-purchase-batch"] != nil, let msg = resp1["customerMessage"] as? String {
                    print("Failed to download product: \(msg)")
                }
                return resp1
            }
        } catch {
            print("Error downloading product: \(error)")
        }
        return [:]
    }

    func download(appId: String, appVer: String = "", isRedownload: Bool = false) async -> [String: Any] {
        return await self.volumeStoreDownloadProduct(appId: appId, appVerId: appVer)
    }

    func downloadToPath(url: String, path: String, progressHandler: DownloadProgressHandler? = nil) async {
        guard let downloadURL = URL(string: url) else { return }
        
        do {
            let (temporaryURL, _) = try await session.download(from: downloadURL)
            let destinationURL = URL(fileURLWithPath: path)
            if FileManager.default.fileExists(atPath: destinationURL.path) {
                try FileManager.default.removeItem(at: destinationURL)
            }
            try FileManager.default.moveItem(at: temporaryURL, to: destinationURL)
            progressHandler?(1, "Download complete".localized)
        } catch {
            print("Download error: \(error.localizedDescription)")
        }
    }
}

class IPATool {
    var session: URLSession
    var appleId: String
    var password: String
    var storeClient: StoreClient
    
    init(appleId: String, password: String) {
        self.session = URLSession.shared
        self.appleId = appleId
        self.password = password
        storeClient = StoreClient(appleId: appleId, password: password)
    }
    
    func authenticate(requestCode: Bool = false) async -> Bool {
        print("Authenticating to iTunes Store via Anisette...")
        if !storeClient.tryLoadAuthInfo() {
            return await storeClient.authenticate(requestCode: requestCode)
        } else {
            return true
        }
    }

    func getVersionIDList(appId: String) async -> [String] {
        let downResp = await storeClient.download(appId: appId, isRedownload: true)
        guard let songList = downResp["songList"] as? [[String: Any]], !songList.isEmpty else { return [] }
        let downInfo = songList[0]
        let metadata = downInfo["metadata"] as? [String: Any] ?? [:]
        let appVerIds = metadata["softwareVersionExternalIdentifiers"] as? [Int] ?? []
        return appVerIds.map { String($0) }
    }

    func downloadIPAForVersion(appId: String, appVerId: String, progressHandler: DownloadProgressHandler? = nil) async -> String {
        progressHandler?(0.05, "Requesting download info".localized)
        let downResp = await storeClient.download(appId: appId, appVer: appVerId)
        guard let songList = downResp["songList"] as? [[String: Any]], !songList.isEmpty else { return "" }
        let downInfo = songList[0]
        guard let url = downInfo["URL"] as? String else { return "" }
        
        let fm = FileManager.default
        let tempDir = fm.temporaryDirectory
        let path = tempDir.appendingPathComponent("app.ipa").path
        if fm.fileExists(atPath: path) {
            try? fm.removeItem(atPath: path)
        }
        
        await storeClient.downloadToPath(url: url, path: path) { progress, detail in
            progressHandler?(0.10 + (progress * 0.60), detail)
        }
        
        Zip.addCustomFileExtension("ipa")
        progressHandler?(0.72, "Extracting IPA".localized)
        
        guard let unzipDirectory = try? Zip.quickUnzipFile(URL(fileURLWithPath: path)) else { return "" }
        progressHandler?(0.80, "Writing metadata".localized)
        
        if var metadata = downInfo["metadata"] as? [String: Any] {
            let metadataPath = unzipDirectory.appendingPathComponent("iTunesMetadata.plist").path
            metadata["apple-id"] = appleId
            metadata["userName"] = appleId
            (metadata as NSDictionary).write(toFile: metadataPath, atomically: true)
        }
        
        var appContentDir = ""
        let payloadDir = unzipDirectory.appendingPathComponent("Payload")
        if let entries = try? fm.contentsOfDirectory(atPath: payloadDir.path) {
            for entry in entries {
                if entry.hasSuffix(".app") {
                    appContentDir = "Payload/" + entry
                    break
                }
            }
        }
        
        if !appContentDir.isEmpty,
           let scManifestData = try? Data(contentsOf: unzipDirectory.appendingPathComponent(appContentDir).appendingPathComponent("SC_Info").appendingPathComponent("Manifest.plist")),
           let scManifest = try? PropertyListSerialization.propertyList(from: scManifestData, options: [], format: nil) as? [String: Any],
           let sinfsDict = downInfo["sinfs"] as? [[String: Any]],
           let sinfPaths = scManifest["SinfPaths"] as? [String] {
            progressHandler?(0.86, "Applying purchase data".localized)
            for (i, sinfPath) in sinfPaths.enumerated() {
                if let sinfData = sinfsDict[i]["sinf"] as? Data {
                    try? sinfData.write(to: unzipDirectory.appendingPathComponent(appContentDir).appendingPathComponent(sinfPath))
                }
            }
        }
        
        progressHandler?(0.90, "IPA prepared".localized)
        return unzipDirectory.path
    }
}
