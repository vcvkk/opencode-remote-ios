import Foundation

/// base64url, the URL- and QR-safe alphabet used by the pairing payload.
///
/// Standard base64 uses `+`, `/` and `=` — all of which either break URL
/// handling or get mangled by anything that trims or re-wraps a scanned
/// string. Swapping the last two symbols and dropping the padding keeps a
/// code scannable and copy-pasteable unchanged.
extension Data {
    func base64URLEncodedString() -> String {
        var s = base64EncodedString()
        s = s.replacingOccurrences(of: "+", with: "-")
        s = s.replacingOccurrences(of: "/", with: "_")
        while s.hasSuffix("=") { s.removeLast() }
        return s
    }

    /// Lenient on purpose: padding is re-added and the alphabet is normalised
    /// before decoding, so a code that lost or gained a `-`/`_` at the edges
    /// still parses.
    init?(base64URLEncoded string: String) {
        var s = string
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder > 0 {
            s += String(repeating: "=", count: 4 - remainder)
        }
        self.init(base64Encoded: s)
    }
}