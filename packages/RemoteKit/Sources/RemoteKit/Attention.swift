import Foundation

/// Attention — disabled in this build.
///
/// Upstream this delivered push notifications by writing an `Attention`
/// record into the user's private CloudKit database and letting a
/// CKQuerySubscription turn that into an APNs alert. With iCloud gone there
/// is nothing to write and nothing to subscribe to, so publishing is a no-op
/// and resolving always returns nil.
///
/// The type, its category/action identifiers and `Info` shape are all kept so
/// the notification plumbing in the app still compiles and simply never
/// fires. Pending work is discovered by polling the authenticated channel
/// over LAN instead.
public enum Attention {
    public static let recordType = "Attention"
    public static let subscriptionID = "opencodego-attention"

    /// What the phone would have learned after fetching the record.
    public struct Info: Sendable {
        /// "permission" | "question" | "failed" | "done"
        public var kind: String
        public var sessionID: String?
        public var directory: String?
        /// Set for permission asks, so a notification action can answer
        /// the exact request without the app having to guess which one.
        public var permissionID: String?
    }

    /// Notification category carrying Allow/Reject actions, used only for
    /// permission asks — the other kinds have nothing to decide.
    public static let permissionCategory = "OPENCODEGO_PERMISSION"
    public static let plainCategory = "OPENCODEGO_ATTENTION"
    public static let allowAction = "OPENCODEGO_ALLOW_ONCE"
    public static let rejectAction = "OPENCODEGO_REJECT"

    /// No rendezvous store, so there is no record to write.
    public static func publish(
        kind: String, sessionID: String?, directory: String?, permissionID: String? = nil
    ) async {}

    /// No CloudKit subscription to register.
    public static func ensureSubscription() async {}

    /// Nothing can arrive, so there is never a record to resolve.
    public static func resolve(userInfo: [AnyHashable: Any]) async -> Info? { nil }
}