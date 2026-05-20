// ─── Types ────────────────────────────────────────────────────────────────────

/** Extracted data from a visible Gmail email. */
export interface EmailData {
  senderName: string;       // Display name shown in the "From" field
  senderEmail: string;      // Raw email address (may be empty if not visible)
  subject: string;          // Subject line text
  bodyText: string;         // Plain text of the email body
  links: LinkData[];        // All <a> tags found in the email body
}

/** A single link found in the email. */
export interface LinkData {
  text: string;             // Visible anchor text
  href: string;             // Actual href URL
}

/** Result produced by the scam scorer. */
export interface ScoreResult {
  score: number;            // 0–100
  riskLevel: RiskLevel;     // Enum label
  reasons: string[];        // Human-readable reasons that contributed to score
}

/** Risk level categories. */
export type RiskLevel = "Low" | "Caution" | "Suspicious" | "High Risk";
