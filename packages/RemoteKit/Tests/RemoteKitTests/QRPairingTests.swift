import XCTest
@testable import RemoteKit

/// The QR payload is the whole pairing handshake now that CloudKit is gone:
/// everything the phone needs about its peer travels in this one string. A
/// regression here is a device that cannot pair at all, so the round trip and
/// the malformed-input paths are both pinned.
final class QRPairingTests: XCTestCase {
    private func payload() -> PairingSession.QRPairPayload {
        PairingSession.QRPairPayload(
            deviceID: "0B1F2A3C-4D5E-6F70-8192-A3B4C5D6E7F8",
            name: "studio",
            role: .mac,
            pubKeyAgreement: Data(repeating: 0xAB, count: 32),
            pubKeySigning: Data(repeating: 0xCD, count: 32)
        )
    }

    func testRoundTripPreservesEveryField() throws {
        let original = payload()
        let text = try original.encoded()
        let decoded = try PairingSession.QRPairPayload.decode(text)

        XCTAssertEqual(decoded.deviceID, original.deviceID)
        XCTAssertEqual(decoded.name, original.name)
        XCTAssertEqual(decoded.role, original.role)
        XCTAssertEqual(decoded.pubKeyAgreement, original.pubKeyAgreement)
        XCTAssertEqual(decoded.pubKeySigning, original.pubKeySigning)
        XCTAssertEqual(decoded.version, original.version)
    }

    /// The prefix is what lets a future format be rejected by eye rather than
    /// by a decode error, so it must survive verbatim.
    func testEncodedCarriesTheSchemePrefix() throws {
        XCTAssertTrue(try payload().encoded().hasPrefix("RFOC1."))
    }

    /// A code photographed off a screen, or pasted through a terminal, picks
    /// up whitespace at the edges. That must not fail the pairing.
    func testDecodeToleratesSurroundingWhitespace() throws {
        let text = try payload().encoded()
        let decoded = try PairingSession.QRPairPayload.decode("\n   \(text)  \n")
        XCTAssertEqual(decoded.name, "studio")
    }

    func testDecodeRejectsAForeignScheme() {
        let bogus = "SOMETHINGELSE." + Data([1, 2, 3]).base64URLEncodedString()
        XCTAssertThrowsError(try PairingSession.QRPairPayload.decode(bogus))
    }

    func testDecodeRejectsNonBase64() {
        XCTAssertThrowsError(
            try PairingSession.QRPairPayload.decode("RFOC1.not base64 !!!")
        )
    }

    func testDecodeRejectsAValidPayloadMissingFields() {
        let partial = PairingSession.QRPairPayload(version: 1, deviceID: "x", name: "y", role: .mac,
                                                  pubKeyAgreement: Data(), pubKeySigning: Data())
        let json = #"{"version":1,"name":"y","role":"mac"}"#
        let text = "RFOC1." + Data(json.utf8).base64URLEncodedString()
        _ = partial
        XCTAssertThrowsError(try PairingSession.QRPairPayload.decode(text))
    }

    /// base64url must survive the two substitutions that would otherwise
    /// corrupt a payload, and must not carry `=` padding.
    func testBase64URLIsURLSafeAndUnpadded() throws {
        let data = Data([0xFB, 0xEF, 0xBE, 0x3F, 0x00, 0x01, 0x02])
        let encoded = data.base64URLEncodedString()

        XCTAssertFalse(encoded.contains("+"))
        XCTAssertFalse(encoded.contains("/"))
        XCTAssertFalse(encoded.contains("="))
        XCTAssertEqual(Data(base64URLEncoded: encoded), data)
    }
}