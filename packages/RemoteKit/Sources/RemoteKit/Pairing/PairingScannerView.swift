import SwiftUI

/// The pairing scanner, resolved once at compile time.
///
/// The name `PairingScannerView` is defined here unconditionally so that
/// `PairingPhaseView` can call it with no conditional of its own. An `#if`
/// sitting inside a `View` body leaves the enclosing `switch` without a
/// resolvable type, and every reference below the conditional fails to
/// compile even when the branch itself is correct.
///
/// Only one of the two implementations below is ever compiled, so exactly one
/// `PairingScannerView` exists in every build.
#if os(iOS)
public typealias PairingScannerView = IOSPairingScannerView
#else
/// The Mac half of a pairing renders a code rather than scanning one; this
/// is the shape that says so. It still names the peer and shows the paste
/// field, so a Mac can pair by hand if the code was copied elsewhere.
public struct PairingScannerView: View {
    @ObservedObject var session: PairingSession
    @State private var pastedCode = ""
    @State private var errorText: String?

    public init(session: PairingSession) {
        self.session = session
    }

    public var body: some View {
        VStack(spacing: 14) {
            Image(systemName: "qrcode")
                .font(.largeTitle)
            Text("Pair with your \(session.peerNoun)")
                .font(.headline)
            Text("Show your \(session.peerNoun) the code below, or paste the code it shows.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .font(.callout)
            TextField("RFOC1.…", text: $pastedCode, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .font(.system(.footnote, design: .monospaced))
                .autocorrectionDisabled()
            Button("Pair") { handle(pastedCode) }
                .buttonStyle(.borderedProminent)
                .disabled(pastedCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            if let errorText {
                Text(errorText)
                    .font(.callout)
                    .foregroundStyle(.orange)
            }
        }
        .frame(maxWidth: 420)
        .padding()
    }

    private func handle(_ text: String) {
        do {
            let payload = try PairingSession.QRPairPayload.decode(text)
            guard payload.role == session.peerRole else {
                errorText = "That code is for a \(payload.role.noun.lowercased()), not a \(session.peerNoun.lowercased())."
                return
            }
            errorText = nil
            pastedCode = ""
            session.adopt(qr: payload)
        } catch {
            errorText = "That code did not read. Paste it in full."
        }
    }
}
#endif