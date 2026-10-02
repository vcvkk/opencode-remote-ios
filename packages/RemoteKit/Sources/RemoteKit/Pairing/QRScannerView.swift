import SwiftUI
import Vision
import VisionKit

#if canImport(UIKit)
import UIKit
#endif

/// Camera scanner for the pairing code.
///
/// VisionKit's `DataScannerViewController` does the QR detection on-device
/// and hands back the raw string; we hand that to `PairingSession.adopt`,
/// which is the only thing that mutates the peer list. Keeping detection
/// here and adoption there means the session stays testable without a camera.
///
/// Two fallbacks matter. `DataScannerViewController` is unsupported on the
/// simulator and on some devices, so scanning is also offered through
/// Vision's `VNDetectBarcodesRequest` over a still photo. And if the camera
/// is denied or absent altogether, a plain text field accepts a pasted
/// code, because someone pairing over SSH should not be locked out by a
/// camera permission.
///
/// macOS has no use for any of this — the Mac half of a pairing renders a QR
/// code instead of scanning one — so the whole view is compiled only where
/// UIKit exists.
#if canImport(UIKit)
public struct PairingScannerView: View {
    @ObservedObject var session: PairingSession
    @StateObject private var photoPicker = PhotoPicker()

    @State private var showsCamera = false
    @State private var pastedCode = ""
    @State private var showsPasteField = false
    @State private var errorText: String?

    public init(session: PairingSession) {
        self.session = session
    }

    public var body: some View {
        VStack(spacing: 16) {
            header

            if showsCamera {
                cameraArea
            } else {
                idleArea
            }

            if let errorText {
                Text(errorText)
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .multilineTextAlignment(.center)
            }

            if showsPasteField {
                pasteField
            }

            secondaryActions
        }
        .frame(maxWidth: 420)
        .padding()
    }

    private var header: some View {
        VStack(spacing: 6) {
            Image(systemName: "qrcode.viewfinder")
                .font(.largeTitle)
            Text("Scan the code on your \(session.peerNoun)")
                .font(.headline)
            Text("Your \(session.peerNoun) shows a pairing code. Point the camera at it — the devices link directly over your network, no account needed.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .font(.callout)
        }
    }

    private var idleArea: some View {
        VStack(spacing: 12) {
            Image(systemName: "camera.viewfinder")
                .font(.system(size: 46))
                .foregroundStyle(.secondary)
            Button("Open Camera") { showsCamera = true }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
    }

    @ViewBuilder
    private var cameraArea: some View {
        if QRScannerController.isSupported {
            QRScannerRepresentable(onScan: handle, onFailure: { errorText = $0 })
                .frame(maxWidth: 320, maxHeight: 380)
                .clipShape(.rect(cornerRadius: 16))
        } else {
            VStack(spacing: 12) {
                Image(systemName: "photo.viewfinder")
                    .font(.system(size: 46))
                    .foregroundStyle(.secondary)
                Text("This device has no live QR scanner. Photograph the code instead.")
                    .multilineTextAlignment(.center)
                    .foregroundStyle(.secondary)
                    .font(.callout)
                Button("Choose Photo") { choosePhoto() }
                    .buttonStyle(.borderedProminent)
            }
        }
    }

    private var pasteField: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Or paste the code")
                .font(.callout)
                .foregroundStyle(.secondary)
            TextField("RFOC1.…", text: $pastedCode, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .font(.system(.footnote, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
            Button("Pair") { handle(pastedCode) }
                .buttonStyle(.bordered)
                .disabled(pastedCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    private var secondaryActions: some View {
        HStack(spacing: 12) {
            if showsCamera {
                Button("Close Camera") { showsCamera = false }
            }
            Button(showsPasteField ? "Hide Paste" : "Paste Code Instead") {
                showsPasteField.toggle()
            }
        }
        .font(.callout)
        .buttonStyle(.borderless)
    }

    /// Parse and adopt. A malformed code is reported on the screen rather
    /// than thrown away — a mis-transcribed character is common enough with
    /// a long base64 payload that retrying beats re-scanning.
    private func handle(_ text: String) {
        do {
            let payload = try PairingSession.QRPairPayload.decode(text)
            guard payload.role == session.peerRole else {
                errorText = "That code is for a \(payload.role.noun.lowercased()), not a \(session.peerNoun.lowercased())."
                return
            }
            errorText = nil
            pastedCode = ""
            showsCamera = false
            session.adopt(qr: payload)
        } catch {
            errorText = "That code did not read. Scan it again, or paste it in full."
        }
    }

    private func choosePhoto() {
        guard let root = Self.topViewController() else {
            errorText = "Cannot open the photo picker right now."
            return
        }
        photoPicker.onPick = { image in
            guard let image else { return }
            QRScannerController.detect(in: image) { text in
                if let text { handle(text) } else {
                    errorText = "No pairing code found in that photo."
                }
            }
        }
        photoPicker.present(from: root)
    }

    /// UIApplication has no "top controller" accessor, so start at the key
    /// window and follow whatever modal is already up.
    private static func topViewController() -> UIViewController? {
        let scenes = UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
        let window = scenes.flatMap(\.windows).first { $0.isKeyWindow }
            ?? scenes.flatMap(\.windows).first
        var top = window?.rootViewController
        while let presented = top?.presentedViewController { top = presented }
        return top
    }
}

/// The live scanner. VisionKit wants a delegate object; a `UIViewController`
/// subclass is the least ceremony that keeps one alive.
enum QRScannerController {
    /// Main-actor because VisionKit's own `isSupported`/`isAvailable` are.
    @MainActor
    static var isSupported: Bool {
        DataScannerViewController.isSupported && DataScannerViewController.isAvailable
    }

    /// Scan a still image — the fallback where live scanning is unavailable.
    /// Only `.qr` is requested, so every observation that comes back is one.
    @MainActor
    static func detect(in image: UIImage, completion: @escaping (String?) -> Void) {
        guard let cgImage = image.cgImage else { return completion(nil) }
        let request = VNDetectBarcodesRequest { request, _ in
            let text = (request.results as? [VNBarcodeObservation])?
                .compactMap(\.payloadStringValue)
                .first
            completion(text)
        }
        request.symbologies = [.qr]
        let handler = VNImageRequestHandler(cgImage: cgImage, orientation: .up)
        try? handler.perform([request])
    }
}

struct QRScannerRepresentable: UIViewControllerRepresentable {
    let onScan: (String) -> Void
    let onFailure: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let controller = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .balanced,
            recognizesMultipleItems: false,
            isHighFrameRateTrackingEnabled: false,
            isHighlightingEnabled: true
        )
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan, onFailure: onFailure) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onScan: (String) -> Void
        private let onFailure: (String) -> Void
        private var delivered = false

        init(onScan: @escaping (String) -> Void, onFailure: @escaping (String) -> Void) {
            self.onScan = onScan
            self.onFailure = onFailure
        }

        func dataScanner(
            _ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem],
            allItems: [RecognizedItem]
        ) {
            // Only the first code counts: a frame can hold several, and
            // re-delivering would run the pairing twice.
            guard !delivered else { return }
            for item in addedItems {
                guard case let .barcode(barcode) = item,
                      let payload = barcode.payloadStringValue
                else { continue }
                delivered = true
                scanner.stopScanning()
                onScan(payload)
                return
            }
        }

        func dataScanner(
            _ scanner: DataScannerViewController,
            becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable
        ) {
            onFailure("The camera is unavailable: \(error.localizedDescription)")
        }
    }
}

/// Retained by `@StateObject` for the life of the view: an image picker
/// deallocated on the next runloop turn never appears on screen.
final class PhotoPicker: NSObject, ObservableObject {
    /// Set by the caller just before presenting.
    @MainActor var onPick: ((UIImage?) -> Void)?

    @MainActor
    func present(from root: UIViewController) {
        let picker = UIImagePickerController()
        picker.sourceType = .photoLibrary
        picker.delegate = self
        root.present(picker, animated: true)
    }
}

extension PhotoPicker: UIImagePickerControllerDelegate, UINavigationControllerDelegate {
    func imagePickerController(
        _ picker: UIImagePickerController,
        didFinishPickingMediaWithInfo info: [UIImagePickerController.InfoKey: Any]
    ) {
        let image = info[.originalImage] as? UIImage
        picker.dismiss(animated: true)
        onPick?(image)
    }

    func imagePickerControllerDidCancel(_ picker: UIImagePickerController) {
        picker.dismiss(animated: true)
    }
}
#endif