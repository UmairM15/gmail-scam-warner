// ─── Scam Scorer ──────────────────────────────────────────────────────────────
//
//  Evaluates an EmailData object and returns a ScoreResult with a 0–100 score,
//  a risk level label, and a list of human-readable reasons.
//
//  HOW SCORING WORKS
//  ─────────────────
//  Each detection check is independent. When a pattern is found, a fixed point
//  value (defined in config.weights) is added to a running total. The final
//  score is clamped to 100. Checks never subtract points — the score can only
//  go up. Multiple checks can fire on the same email, so a particularly
//  dangerous email can accumulate a high score quickly.
//
//  To tune sensitivity, edit the weights and thresholds in src/config.ts.
// ─────────────────────────────────────────────────────────────────────────────

import { config } from "./config";
import type { EmailData, ScoreResult, RiskLevel } from "./types";

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Case-insensitive substring search. */
function contains(haystack: string, needle: string): boolean {
  return haystack.toLowerCase().includes(needle.toLowerCase());
}

/** Returns true if any keyword in the list is found in the text. */
function matchesAny(text: string, keywords: string[]): string[] {
  return keywords.filter((kw) => contains(text, kw));
}

/**
 * Extracts the hostname from a URL string.
 * Returns an empty string if the URL is unparseable.
 */
function hostname(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

/** Returns true if the URL's hostname is in the trusted domains list. */
function isTrustedDomain(url: string): boolean {
  const host = hostname(url);
  return config.trustedDomains.some(
    (d) => host === d.toLowerCase() || host.endsWith("." + d.toLowerCase())
  );
}

/** Returns true if a URL looks suspicious (non-https, IP address, etc.). */
function isSuspiciousUrl(url: string): boolean {
  if (!url || url.startsWith("mailto:") || url.startsWith("#")) return false;
  if (isTrustedDomain(url)) return false;

  try {
    const parsed = new URL(url);
    // Flag non-https links
    if (parsed.protocol !== "https:") return true;
    // Flag raw IP addresses as hostname
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) return true;
    // Flag URLs with excessive subdomains (likely phishing)
    const parts = parsed.hostname.split(".");
    if (parts.length > 4) return true;
    return false;
  } catch {
    return true; // Unparseable URL is suspicious
  }
}

/**
 * Detects a link mismatch: the visible anchor text looks like a real domain
 * but the actual href goes somewhere different.
 * e.g. text = "www.interac.ca" but href = "http://evil.ru/interac"
 */
function isLinkMismatch(linkText: string, href: string): boolean {
  if (!linkText || !href) return false;
  // Does the link text itself look like a URL / domain?
  const textLooksLikeDomain = /[a-z0-9-]+\.[a-z]{2,}/i.test(linkText.trim());
  if (!textLooksLikeDomain) return false;

  // Extract domain-like token from text
  const textDomainMatch = linkText.trim().match(/([a-z0-9-]+\.[a-z]{2,})/i);
  if (!textDomainMatch) return false;
  const textDomain = textDomainMatch[1].toLowerCase().replace(/^www\./, "");

  const hrefHost = hostname(href);
  // Mismatch if the hostname in the href doesn't end with the text domain
  return hrefHost !== "" && !hrefHost.endsWith(textDomain);
}

// ── Known typo / fake-brand patterns ─────────────────────────────────────────
// Regex list for common scammer misspellings and look-alike characters.
const SPELLING_PATTERNS: RegExp[] = [
  /reb[t4]e/i,          // "rebte", "reb4e" instead of "rebate"
  /g[i1]ft.?c[a4]rd/i,  // "g1ft card", "gift c4rd"
  /[i1]nter[a4]c/i,     // "1nterac", "interac" with substituted chars
  /c[o0]nfirm/i,         // "c0nfirm"
  /verif[i1]c[a4]tion/i, // "verif1cation"
  /acc[o0]unt/i,         // "acc0unt"
  /s[e3]cur[i1]ty/i,     // "s3curity"
];

// ── Main scorer ───────────────────────────────────────────────────────────────

export function scoreEmail(email: EmailData): ScoreResult {
  let score = 0;
  const reasons: string[] = [];
  const w = config.weights;

  const fullText = [email.subject, email.bodyText, email.senderName].join(" ");

  // ── 1. Executive / staff spoofing ────────────────────────────────────────
  // The sender display name matches an internal name, but the email domain
  // is not one of the company's domains.
  if (email.senderName) {
    const nameLower = email.senderName.toLowerCase();
    const matchedName = config.internalNames.find((n) =>
      nameLower.includes(n.toLowerCase())
    );
    if (matchedName) {
      const emailDomain = email.senderEmail.split("@")[1]?.toLowerCase() ?? "";
      const isInternal = config.companyDomains.some(
        (d) => emailDomain === d.toLowerCase()
      );
      if (!isInternal && emailDomain !== "") {
        score += w.executiveSpoofing;
        reasons.push(
          `Sender name "${matchedName}" matches an internal staff member but the email comes from an external domain (${emailDomain}).`
        );
      }
    }
  }

  // ── 2. Requesting personal contact info ──────────────────────────────────
  const contactMatches = matchesAny(fullText, config.contactKeywords);
  if (contactMatches.length > 0) {
    score += w.contactInfoRequest;
    reasons.push(
      `Asks for personal contact information (e.g. "${contactMatches[0]}").`
    );
  }

  // ── 3. Financial fraud patterns (gift cards, payments, etc.) ─────────────
  const financialMatches = matchesAny(fullText, config.financialKeywords);
  // Separate payroll/bank keywords for their higher weight
  const payrollKeywords = ["payroll", "bank account", "direct deposit", "wire transfer", "e-transfer", "etransfer"];
  const payrollMatches = matchesAny(fullText, payrollKeywords);

  if (payrollMatches.length > 0) {
    score += w.payrollBankChange;
    reasons.push(
      `References payroll or bank account changes (e.g. "${payrollMatches[0]}").`
    );
  } else if (financialMatches.length > 0) {
    score += w.financialRequest;
    reasons.push(
      `Mentions financial requests such as "${financialMatches[0]}".`
    );
  }

  // ── 4. Suspicious links ───────────────────────────────────────────────────
  let suspiciousLinkFound = false;
  let linkMismatchFound = false;

  for (const link of email.links) {
    if (!suspiciousLinkFound && isSuspiciousUrl(link.href)) {
      score += w.suspiciousLink;
      reasons.push(
        `Contains a suspicious link: ${link.href.slice(0, 60)}${link.href.length > 60 ? "…" : ""}`
      );
      suspiciousLinkFound = true;
    }
    if (!linkMismatchFound && isLinkMismatch(link.text, link.href)) {
      score += w.linkMismatch;
      reasons.push(
        `Link text "${link.text.slice(0, 40)}" does not match its actual destination.`
      );
      linkMismatchFound = true;
    }
  }

  // ── 5. External brand / organisation impersonation ───────────────────────
  const brandMatches = matchesAny(fullText, config.externalBrands);
  if (brandMatches.length > 0) {
    // Only flag if the sender's domain doesn't match the brand
    const senderDomain = email.senderEmail.split("@")[1]?.toLowerCase() ?? "";
    const brandTrusted = isTrustedDomain("https://" + senderDomain);
    if (!brandTrusted) {
      score += w.externalImpersonation;
      reasons.push(
        `May be impersonating a known organisation ("${brandMatches[0]}").`
      );
    }
  }

  // ── 6. Urgency / pressure language ───────────────────────────────────────
  const urgencyMatches = matchesAny(fullText, config.urgencyKeywords);
  if (urgencyMatches.length > 0) {
    score += w.urgencyLanguage;
    reasons.push(
      `Uses urgency or pressure language (e.g. "${urgencyMatches[0]}").`
    );
  }

  // ── 7. Vague document / link request ─────────────────────────────────────
  const vagueMatches = matchesAny(fullText, config.vagueDocKeywords);
  if (vagueMatches.length > 0) {
    score += w.vagueDocRequest;
    reasons.push(
      `Asks you to open a file or click a link without a clear explanation ("${vagueMatches[0]}").`
    );
  }

  // ── 8. Spelling / fake-character issues ──────────────────────────────────
  const spellingHit = SPELLING_PATTERNS.find((re) => re.test(fullText));
  if (spellingHit) {
    score += w.spellingIssue;
    reasons.push(
      "Contains unusual spelling or look-alike characters (possible fake brand name)."
    );
  }

  // ── Clamp score to 0–100 ─────────────────────────────────────────────────
  score = Math.min(100, Math.max(0, score));

  // ── Determine risk level ─────────────────────────────────────────────────
  const riskLevel = getRiskLevel(score);

  return { score, riskLevel, reasons };
}

function getRiskLevel(score: number): RiskLevel {
  if (score >= config.thresholds.highRisk) return "High Risk";
  if (score >= config.thresholds.suspicious) return "Suspicious";
  if (score >= config.thresholds.caution) return "Caution";
  return "Low";
}
