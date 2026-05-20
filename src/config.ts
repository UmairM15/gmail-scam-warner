// ─── Configuration ────────────────────────────────────────────────────────────
//
//  EDIT THIS FILE to customize the extension for your organisation.
//
//  After editing, rebuild the extension:
//    npm run build
//  Then reload the unpacked extension in chrome://extensions.
// ─────────────────────────────────────────────────────────────────────────────

export const config = {

  // ── Your organisation's email domains ──────────────────────────────────────
  // Emails FROM these domains are considered internal and trusted.
  // Any email that spoofs an internal name but uses an outside domain gets
  // a heavy score penalty.
  companyDomains: [
    "upluseducation.ca",
    "yorkeducation.ca",
  ],

  // ── Internal staff / executive display names ───────────────────────────────
  // If an email's sender display name matches one of these (case-insensitive,
  // partial match) but the sender's email domain is NOT in companyDomains,
  // that is a strong spoofing signal.
  internalNames: [
    "Kevin Lin",
    "Moxi Zhang",
    "Carey",
    "Tanya",
    "Umair",
  ],

  // ── Trusted external vendor domains ────────────────────────────────────────
  // Links pointing to these domains are considered safe and will NOT trigger
  // the suspicious-link check. Keep this list tight.
  trustedDomains: [
    "wix.com",
    "interac.ca",
    "google.com",
    "adobe.com",
    "microsoft.com",
    "dropbox.com",
    "zoom.us",
    "atlassian.net",
    "meet.google.com"
  ],

  // ── Google Calendar / Meet trusted domains ─────────────────────────────────
  // Links to these domains inside a likely Calendar invite are never flagged
  // as suspicious or mismatched. Subdomains are also matched automatically
  // (e.g. meet.google.com, calendar.google.com).
  trustedMeetingDomains: [
    "meet.google.com",
    "calendar.google.com",
    "google.com",
  ],

  // ── Trusted Google Calendar sender addresses ────────────────────────────────
  // Emails FROM these exact addresses are treated as Google Calendar
  // notifications. Combined with body content checks, they suppress false
  // positives on legitimate meeting invites.
  trustedCalendarSenders: [
    "calendar-notification@google.com",
    "calendar-noreply@google.com",
  ],

  // ── Keywords that suggest requesting personal contact info ─────────────────
  // Matching ANY of these in the body adds to the score.
  contactKeywords: [
    "phone number",
    "cell number",
    "mobile number",
    "whatsapp",
    "personal number",
    "alternate contact",
    "text me",
    "call me",
    "personal email",
  ],

  // ── Keywords that suggest financial fraud or unusual requests ───────────────
  financialKeywords: [
    "gift card",
    "voucher",
    "surprise gift",
    "reimbursement",
    "purchase",
    "payroll update",
    "bank account",
    "direct deposit",
    "wire transfer",
    "e-transfer",
    "etransfer",
    "buy now",
  ],

  // ── Urgency / pressure language ────────────────────────────────────────────
  urgencyKeywords: [
    "urgent",
    "do not ignore",
    "respond quickly",
    "asap",
    "immediately",
    "confidential",
    "act now",
    "time sensitive",
    "right away",
    "as soon as possible",
  ],

  // ── Known external brand impersonation names ───────────────────────────────
  // If any of these appear in the sender name or email body alongside a
  // non-matching domain, it suggests impersonation.
  externalBrands: [
    "interac",
    "wix",
    "adobe",
    "canada revenue",
    "cra",
    "service canada",
    "government of canada",
    "law firm",
    "legal notice",
    "microsoft support",
    "apple support",
    "paypal",
    "amazon",
  ],

  // ── Vague document / link request phrases ──────────────────────────────────
  vagueDocKeywords: [
    "click the link",
    "open the file",
    "view the document",
    "see attached",
    "download and open",
    "review the attachment",
    "access the document",
  ],

  // ── Scoring weights ────────────────────────────────────────────────────────
  // Adjust these numbers to tune sensitivity.
  weights: {
    executiveSpoofing: 40,      // Sender name matches internal name + external domain
    contactInfoRequest: 30,     // Asking for phone/WhatsApp/cell
    financialRequest: 35,       // Gift cards / payments / payroll
    suspiciousLink: 25,         // A link href looks suspicious
    linkMismatch: 30,           // Link text ≠ actual destination domain
    externalImpersonation: 25,  // Brand impersonation
    payrollBankChange: 35,      // Payroll / bank change (subset of financial)
    urgencyLanguage: 15,        // Urgency keywords
    vagueDocRequest: 20,        // Vague "click this" with no context
    spellingIssue: 10,          // Typos / fake-brand characters
    telLink: 5,                 // tel: link outside a calendar invite (low signal)
  },

  // ── Risk thresholds ────────────────────────────────────────────────────────
  thresholds: {
    caution: 30,      // Score ≥ 30  → yellow banner
    suspicious: 60,   // Score ≥ 60  → orange banner
    highRisk: 80,     // Score ≥ 80  → red banner
  },
};
