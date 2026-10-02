import CryptoKit
import Foundation
import OSLog
import Security
#if os(iOS)
import UIKit
#endif

/// Device pairing, ported from the validated Phase-0 spike (pairing-spike/).
///
/// Scope in the app: pairing establishes *identity* — each device keeps a
/// Curve25519 private key in its local keychain, exchanges public halves
/// through the shared-Apple-ID CloudKit private database, and the user
/// confirms a 6-digit code shown on both screens. The derived shared secret
/// then authenticates and encrypts the LAN channel (see Wire).
///
/// The same rendezvous record then carries the devices' address candidates,
/// so the cross-network transport (see Punch) has somewhere to meet without
/// a server of ours in the middle. Pairing itself needs none of that —
/// CloudKit is the rendezvous for both.
public enum Pairing {
    public static let cloudContainerID = "iCloud.com.timwilliams.opencodego"
    static let keychainService = "com.timwilliams.opencodego"
}

// MARK: - Roles and records

public enum DeviceRole: String, Codable, Sendable {
    case mac
    case phone

    /// The fixed record name of the pre-multi-peer scheme ("peer-mac" /
    /// "peer-phone"). Still written and read for `legacy` peers — a 1.1
    /// companion in the wild knows no other rendezvous.
    var recordName: String { "peer-\(rawValue)" }
    public var peer: DeviceRole { self == .mac ? .phone : .mac }

    /// The role this build plays.
    public static var current: DeviceRole {
        #if os(macOS)
        .mac
        #else
        .phone
        #endif
    }

    /// The word for a device of this role on someone else's screen.
    public var noun: String { self == .mac ? "Mac" : "iPhone" }
}

/// A stable identity per install, minted once. This is what lets any
/// number of devices share one Apple ID: each publishes its own
/// `device-<id>` record instead of fighting over a fixed name per role.
public enum DeviceID {
    static let key = "opencodego.deviceID"

    public static var current: String {
        if let id = PairingStore.defaults.string(forKey: key) { return id }
        let id = UUID().uuidString
        PairingStore.defaults.set(id, forKey: key)
        return id
    }

    /// The CloudKit record name for a device id.
    public static func recordName(for id: String) -> String { "device-\(id)" }
}

/// What this device calls itself on the other one's screen.
public enum DeviceIdentity {
    public static var name: String {
        #if os(macOS)
        Host.current().localizedName ?? "Mac"
        #else
        UIDevice.current.name
        #endif
    }
}

struct PeerRecord {
    var deviceName: String
    var role: DeviceRole
    var pubKeyAgreement: Data
    var pubKeySigning: Data
    var heartbeatAt: Date
    var approvedAt: Date?
    /// "ip:port" candidates this device can currently be reached at — its
    /// LAN addresses plus the reflexive one STUN reported. Empty until the
    /// device has published any.
    var endpoints: [String] = []
    /// Set by a client when it starts dialling, so the server knows to
    /// punch back now rather than at its next lazy poll.
    var connectRequestedAt: Date?
    /// The publisher's stable install id. Absent on records written by
    /// pre-multi-peer builds — which is exactly how a legacy peer is
    /// recognised during pairing.
    var deviceID: String?
}

public enum PairingError: Error, LocalizedError {
    case keychain(OSStatus)
    case notPaired
    case network(String)
    case unknownPairingCode

    public var errorDescription: String? {
        switch self {
        case let .keychain(s): return "keychain error \(s)"
        case .notPaired: return "No paired device."
        case let .network(m): return m
        case .unknownPairingCode:
            return "That is not a Remote for OpenCode pairing code."
        }
    }
}

// MARK: - Key material

/// Device-local key material. Private keys are generic-password keychain
/// items, non-synchronizable — only public halves ever reach CloudKit.
enum PairingKeyStore {
    static func agreementKey() throws -> Curve25519.KeyAgreement.PrivateKey {
        if let data = try read(tag: "pairing.agreement") {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
        }
        let key = Curve25519.KeyAgreement.PrivateKey()
        try write(tag: "pairing.agreement", data: key.rawRepresentation)
        return key
    }

    static func signingKey() throws -> Curve25519.Signing.PrivateKey {
        if let data = try read(tag: "pairing.signing") {
            return try Curve25519.Signing.PrivateKey(rawRepresentation: data)
        }
        let key = Curve25519.Signing.PrivateKey()
        try write(tag: "pairing.signing", data: key.rawRepresentation)
        return key
    }

    private static func query(tag: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Pairing.keychainService,
            kSecAttrAccount as String: tag,
        ]
    }

    private static func read(tag: String) throws -> Data? {
        var q = query(tag: tag)
        q[kSecReturnData as String] = true
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        // -25293: the item exists but this binary may not read it. On macOS
        // that means the keychain ACL was written by a differently-signed
        // build of this app — a re-sign, a move, an unsigned local build.
        //
        // An unreadable private key is a dead pairing by definition: the
        // channel key can't be derived, so nothing can authenticate with it
        // ever again. Holding onto it would leave the user stuck at an
        // error with no way forward, including through the re-pair that
        // would otherwise fix everything. So drop it and mint a fresh one;
        // the peer's records are rewritten by the next pairing anyway.
        if status == errSecAuthFailed || status == errSecInteractionNotAllowed {
            SecItemDelete(query(tag: tag) as CFDictionary)
            return nil
        }
        guard status == errSecSuccess else { throw PairingError.keychain(status) }
        return out as? Data
    }

    private static func write(tag: String, data: Data) throws {
        var q = query(tag: tag)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        var status = SecItemAdd(q as CFDictionary, nil)
        if status == errSecDuplicateItem {
            // A leftover we just failed to read, or a partial write. The
            // add is the authority here, so replace rather than keep.
            SecItemDelete(query(tag: tag) as CFDictionary)
            status = SecItemAdd(q as CFDictionary, nil)
        }
        guard status == errSecSuccess else {
            throw PairingError.keychain(status)
        }
    }

    /// Forget this device's key material entirely, so the next pairing
    /// starts from new keys. Used by unpair — a re-pair that reuses a key
    /// the peer has already rejected is not a fresh start.
    static func reset() {
        for tag in ["pairing.agreement", "pairing.signing"] {
            SecItemDelete(query(tag: tag) as CFDictionary)
        }
    }
}

// MARK: - Session crypto

/// X25519 → HKDF channel key, plus the 6-digit short-auth string both
/// screens display during pairing.
public struct PairingCrypto {
    public let channelKey: SymmetricKey
    public let sas: String

    init(myKey: Curve25519.KeyAgreement.PrivateKey, peerPub: Data) throws {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPub)
        let secret = try myKey.sharedSecretFromKeyAgreement(with: peer)
        channelKey = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("opencodego-v1".utf8),
            sharedInfo: Data("channel".utf8),
            outputByteCount: 32
        )
        sas = Self.shortAuthString(myKey.publicKey.rawRepresentation, peerPub)
    }

    /// Order-independent 6-digit code over both public keys. Matching
    /// numbers on both screens rules out a rendezvous-level MITM.
    static func shortAuthString(_ a: Data, _ b: Data) -> String {
        let sorted = [a, b].sorted { $0.lexicographicallyPrecedes($1) }
        let digest = SHA256.hash(data: sorted[0] + sorted[1])
        let n = digest.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        return String(format: "%06d", n % 1_000_000)
    }
}

// MARK: - Persisted pairing state

/// The pre-multi-peer persisted shape, kept for migration and for the few
/// call sites that still think in terms of "the" peer.
public struct PairedDevice: Codable, Equatable {
    public var name: String
    public var role: DeviceRole
    public var pubKeyAgreement: Data
    public var pairedAt: Date
}

/// One paired peer among possibly several. The peer's public key is public
/// data, so UserDefaults is fine; the channel key is re-derived from the
/// keychain private key on demand rather than stored.
public struct PairedPeer: Codable, Equatable, Identifiable, Sendable {
    /// The peer's `DeviceID`. Peers migrated from (or paired with) a
    /// pre-multi-peer build get a synthetic `legacy-<role>` id.
    public var id: String
    public var name: String
    public var role: DeviceRole
    public var pubKeyAgreement: Data
    public var pairedAt: Date
    /// True when this peer rendezvouses through the old fixed record names
    /// (`peer-mac`/`peer-phone`) because it runs a pre-multi-peer build.
    /// Dies naturally when the peer is re-paired after updating.
    public var legacy: Bool

    public init(
        id: String, name: String, role: DeviceRole,
        pubKeyAgreement: Data, pairedAt: Date, legacy: Bool = false
    ) {
        self.id = id
        self.name = name
        self.role = role
        self.pubKeyAgreement = pubKeyAgreement
        self.pairedAt = pairedAt
        self.legacy = legacy
    }
}

public enum PairingStore {
    /// Injectable for tests; the app never touches it.
    nonisolated(unsafe) static var defaults = UserDefaults.standard

    private static let legacyKey = "opencodego.pairedDevice"
    private static let peersKey = "opencodego.pairedPeers"
    private static let everKey = "opencodego.hasEverPaired"
    public static let changed = Notification.Name("PairingStore.changed")

    /// Whether this device has *ever* completed a pairing, which is not the
    /// same question as whether it is paired now and deliberately survives
    /// `clear()`.
    ///
    /// It exists to decide who needs selling to. Someone who has never paired
    /// may not know the Mac app exists, and the phone's connect screen is the
    /// only place that can tell them. Someone who has paired before knows
    /// exactly what they are missing and is looking at that screen because
    /// something is broken or they unpaired on purpose — pitching the product
    /// to them is noise sitting between them and the fix.
    public static var hasEverPaired: Bool {
        defaults.bool(forKey: everKey)
    }

    // MARK: The peer list

    public static func peers() -> [PairedPeer] {
        migrateIfNeeded()
        guard let data = defaults.data(forKey: peersKey) else { return [] }
        return (try? JSONDecoder().decode([PairedPeer].self, from: data)) ?? []
    }

    /// Adds or replaces (same id, or same public key — a re-pair of the
    /// same install under a new id must not leave the old entry behind).
    public static func add(_ peer: PairedPeer) {
        var list = peers().filter {
            $0.id != peer.id && $0.pubKeyAgreement != peer.pubKeyAgreement
        }
        list.append(peer)
        persist(list)
        defaults.set(true, forKey: everKey)
    }

    public static func remove(_ id: String) {
        persist(peers().filter { $0.id != id })
    }

    public static func clear() {
        defaults.removeObject(forKey: peersKey)
        defaults.removeObject(forKey: legacyKey)
        NotificationCenter.default.post(name: changed, object: nil)
    }

    /// The peer the single-peer call sites mean: the counterpart role's
    /// first entry (the phone's Mac; the Mac's phone), falling back to
    /// anything at all.
    public static var primary: PairedPeer? {
        let list = peers()
        return list.first { $0.role == DeviceRole.current.peer } ?? list.first
    }

    /// Transitional shim over `primary` for pre-multi-peer call sites.
    public static func load() -> PairedDevice? {
        guard let peer = primary else { return nil }
        return PairedDevice(
            name: peer.name, role: peer.role,
            pubKeyAgreement: peer.pubKeyAgreement, pairedAt: peer.pairedAt
        )
    }

    // MARK: Channel keys

    /// The symmetric key shared with the primary peer.
    public static func channelKey() throws -> SymmetricKey {
        guard let peer = primary else { throw PairingError.notPaired }
        return try channelKey(for: peer)
    }

    /// The symmetric key shared with one specific peer, derived fresh from
    /// the local private key and that peer's stored public key.
    public static func channelKey(for peer: PairedPeer) throws -> SymmetricKey {
        let mine = try PairingKeyStore.agreementKey()
        return try PairingCrypto(myKey: mine, peerPub: peer.pubKeyAgreement).channelKey
    }

    // MARK: Migration

    /// The single-device blob becomes a one-entry list, `legacy: true`,
    /// with the public key bytes preserved exactly — that byte identity is
    /// what keeps the shipped pairing authenticating with no user action.
    /// The old blob stays behind (harmless) so a downgrade still works.
    private static func migrateIfNeeded() {
        guard defaults.data(forKey: peersKey) == nil,
              let data = defaults.data(forKey: legacyKey),
              let old = try? JSONDecoder().decode(PairedDevice.self, from: data)
        else { return }
        let migrated = PairedPeer(
            id: "legacy-\(old.role.rawValue)",
            name: old.name, role: old.role,
            pubKeyAgreement: old.pubKeyAgreement,
            pairedAt: old.pairedAt, legacy: true
        )
        if let encoded = try? JSONEncoder().encode([migrated]) {
            defaults.set(encoded, forKey: peersKey)
        }
    }

    private static func persist(_ list: [PairedPeer]) {
        if let data = try? JSONEncoder().encode(list) {
            defaults.set(data, forKey: peersKey)
        }
        NotificationCenter.default.post(name: changed, object: nil)
    }
}

// MARK: - CloudKit rendezvous

/// Rendezvous transport stub — CloudKit removed.
///
/// This build carries no iCloud dependency: pairing is a QR handshake over
/// LAN, and the cross-network hole-punch transport has nothing to publish
/// candidates into. The surface below stays so `Punch` and the rest of the
/// transport keep compiling; every method reports "no rendezvous" instead of
/// silently pretending a write succeeded.
final class PairingCloud: Sendable {
    struct Fields: OptionSet {
        let rawValue: Int
        static let identity = Fields(rawValue: 1 << 0)
        static let approval = Fields(rawValue: 1 << 1)
        static let endpoints = Fields(rawValue: 1 << 2)
        static let connectRequest = Fields(rawValue: 1 << 3)
    }

    enum RendezvousUnavailable: Error {
        case noRendezvous
    }

    func accountStatus() async throws -> String { "available" }

    func upsertSelf(
        _ peer: PeerRecord, fields: Fields, includeLegacy: Bool = false
    ) async throws {
        throw RendezvousUnavailable.noRendezvous
    }

    func fetchPeers() async throws -> [PeerRecord] { [] }
    func fetchPeer(of role: DeviceRole) async throws -> PeerRecord? { nil }
    func fetchPeer(named name: String) async throws -> PeerRecord? { nil }

    func remove(peer: PairedPeer) async throws {}
    func reset() async throws {}
}
// MARK: - Session state machine

/// Runs one pairing attempt while its screen is visible: publish own record,
/// poll for the peer, show the SAS, and — once both sides have approved —
/// persist the peer and stop. Both apps drive the same machine.
@MainActor
public final class PairingSession: ObservableObject {
    public enum Phase: Equatable {
        case idle
        case initializing
        /// iCloud unavailable; message explains what to do.
        case noICloud(String)
        case waitingForPeer
        case peerFound(name: String, sas: String)
        case waitingForPeerApproval(name: String, sas: String)
        case paired(name: String)
        case failed(String)
    }

    @Published public private(set) var phase: Phase = .idle

    private let role = DeviceRole.current
    private var agreementKey: Curve25519.KeyAgreement.PrivateKey?
    private var crypto: PairingCrypto?
    private var peer: PeerRecord?
    private var approvedLocally = false
    private var loop: Task<Void, Never>?
    private static let logger = Logger(
        subsystem: "com.timwilliams.opencodego", category: "pairing"
    )

    public init() {}

    public var deviceName: String { DeviceIdentity.name }

    public func start() {
        guard loop == nil else { return }
        approvedLocally = false
        crypto = nil
        peer = nil
        phase = .initializing
        loop = Task { await run() }
    }

    public func stop() {
        loop?.cancel()
        loop = nil
        if case .paired = phase {} else { phase = .idle }
    }

    public func approve() {
        approvedLocally = true
        if case let .peerFound(name, sas) = phase {
            phase = .waitingForPeerApproval(name: name, sas: sas)
        }
        Task { try? await publishSelf() }
    }

    /// Forget one paired peer and remove its rendezvous state. Removing the
    /// last peer resets the key material too — a device with no pairings
    /// should start its next one from fresh keys, and leaving old keys
    /// behind is what turns "unpair and try again" into a re-pair that
    /// still can't read its own key. With other peers remaining the keys
    /// must obviously stay: they are those pairings.
    public func unpair(_ peer: PairedPeer) {
        PairingStore.remove(peer.id)
        stop()
        if PairingStore.peers().isEmpty {
            PairingKeyStore.reset()
            PairingStore.clear()
        }
    }

    /// Forget every pairing and wipe the rendezvous clean.
    public func unpairAll() {
        PairingStore.clear()
        PairingKeyStore.reset()
        stop()
    }

    /// No rendezvous to poll any more: pairing is now driven entirely by the
    /// QR handshake, so the session simply waits for `adopt(qr:)` to deliver
    /// a peer. Keeping the phase machine means every screen that renders it
    /// still works unchanged.
    private func run() async {
        agreementKey = try? PairingKeyStore.agreementKey()
        phase = .waitingForPeer
        while !Task.isCancelled {
            try? await Task.sleep(for: .seconds(1))
        }
    }

    /// Adopt a peer described by a scanned QR code.
    ///
    /// The payload carries the peer's name, role and Curve25519 public half;
    /// the private key never leaves the device that minted it, so scanning
    /// a code is exactly as strong as the CloudKit exchange it replaces.
    /// A re-scan of a peer we already hold replaces the stored entry, which
    /// is how a reinstalled companion re-keys an existing pairing.
    public func adopt(qr payload: QRPairPayload) {
        agreementKey = (try? PairingKeyStore.agreementKey())
            ?? (try? PairingKeyStore.agreementKey())
        let peer = PairedPeer(
            id: payload.deviceID,
            name: payload.name,
            role: payload.role,
            pubKeyAgreement: payload.pubKeyAgreement,
            pairedAt: Date(),
            legacy: false
        )
        PairingStore.add(peer)
        phase = .paired(name: payload.name)
        loop?.cancel()
        loop = nil
        Self.logger.notice("paired with '\(payload.name, privacy: .public)' via QR")
    }

    private func complete(with found: PeerRecord) {
        PairingStore.add(PairedPeer(
            id: found.deviceID ?? "legacy-\(found.role.rawValue)",
            name: found.deviceName,
            role: found.role,
            pubKeyAgreement: found.pubKeyAgreement,
            pairedAt: Date(),
            legacy: found.deviceID == nil
        ))
        phase = .paired(name: found.deviceName)
        Self.logger.notice("paired with '\(found.deviceName, privacy: .public)'")
        loop?.cancel()
        loop = nil
    }

    /// The payload a QR code carries: who is asking to pair, and the public
    /// half of their Curve25519 agreement key. Base64url + dots keeps it
    /// readable in a terminal and compact enough for a code that a human
    /// has to photograph off a screen.
    public struct QRPairPayload: Codable, Sendable {
        public var version: Int
        public var deviceID: String
        public var name: String
        public var role: DeviceRole
        public var pubKeyAgreement: Data
        public var pubKeySigning: Data

        public init(
            version: Int = 1,
            deviceID: String, name: String, role: DeviceRole,
            pubKeyAgreement: Data, pubKeySigning: Data
        ) {
            self.version = version
            self.deviceID = deviceID
            self.name = name
            self.role = role
            self.pubKeyAgreement = pubKeyAgreement
            self.pubKeySigning = pubKeySigning
        }

        private enum CodingKeys: String, CodingKey {
            case version, deviceID, name, role, pubKeyAgreement, pubKeySigning
        }

        public init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            version = try c.decode(Int.self, forKey: .version)
            deviceID = try c.decode(String.self, forKey: .deviceID)
            name = try c.decode(String.self, forKey: .name)
            role = try c.decode(DeviceRole.self, forKey: .role)
            pubKeyAgreement = try c.decode(Data.self, forKey: .pubKeyAgreement)
            pubKeySigning = try c.decode(Data.self, forKey: .pubKeySigning)
        }

        /// Rendered form: `RFOC1.<base64url json>`. The prefix makes the
        /// code self-identifying, so a future format change can be rejected
        /// by eye instead of by a decode error.
        public func encoded() throws -> String {
            let json = try JSONEncoder().encode(self)
            return "RFOC1." + json.base64URLEncodedString()
        }

        /// Parse a scanned string. Tolerates whitespace and a missing
        /// scheme so a code pasted by hand still works.
        public static func decode(_ text: String) throws -> QRPairPayload {
            var body = text.trimmingCharacters(in: .whitespacesAndNewlines)
            if let dot = body.firstIndex(of: ".") {
                let prefix = String(body[body.startIndex..<dot])
                guard prefix == "RFOC1" else {
                    throw PairingError.unknownPairingCode
                }
                body = String(body[body.index(after: dot)...])
            }
            guard let data = Data(base64URLEncoded: body) else {
                throw PairingError.unknownPairingCode
            }
            return try JSONDecoder().decode(QRPairPayload.self, from: data)
        }
    }

    /// This device's own pairing payload, for a companion to render as a QR
    /// code. Only public halves appear: the private key stays in the keychain.
    public func selfPayload() throws -> QRPairPayload {
        let agreement = try PairingKeyStore.agreementKey()
        let signing = try PairingKeyStore.signingKey()
        return QRPairPayload(
            deviceID: DeviceID.current,
            name: deviceName,
            role: role,
            pubKeyAgreement: agreement.publicKey.rawRepresentation,
            pubKeySigning: signing.publicKey.rawRepresentation
        )
    }
}
