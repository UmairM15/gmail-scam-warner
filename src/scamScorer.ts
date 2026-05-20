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
//  GOOGLE CALENDAR / MEET EXEMPTIONS
//  ──────────────────────────────────
//  Legitimate Google Calendar invites contain tel: dial-in links and
//  meet.google.com URLs that would otherwise look suspicious. The scorer
//  detects likely calendar invites and skips or reduces those checks so
//  real meeting invites don't get flagged.
//
//  To tune sensitivity, edit the weights and thresholds in src/config.ts.
// ─────────────────────────────────────────────────────────────────────────────

import { config } from "./config";
import type { EmailData, LinkData, ScoreResult, RiskLevel } from "./types";

// ── Generic helpers ───────────────────────────────────────────────────────────

/** Case-insensitive substring search. */
function contains(haystack: string, needle: string): boolean {
  return haystack.toLowerCase().includes(needle.toLowerCase());
}

/** Returns all keywords from the list that appear in the text. */
function matchesAny(text: string, keywords: string[]): string[] {
  return keywords.filter((kw) => contains(text, kw));
}

// ── URL helpers ───────────────────────────────────────────────────────────────

/**
 * Extracts the normalised hostname from a URL string.
 * Strips leading "www." and lowercases the result.
 * Returns "" if the URL is unparseable or uses a non-http(s) scheme.
 */
function urlHostname(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

/**
 * Extracts the pathname from a URL, normalised to lower-case with
 * a trailing slash stripped.
 * Returns "" if the URL is unparseable.
 */
function urlPathname(url: string): string {
  try {
    return new URL(url).pathname.toLowerCase().replace(/\/$/, "");
  } catch {
    return "";
  }
}

/** Returns true if the URL's hostname matches (or is a subdomain of) any
 *  entry in the provided domain list. */
function matchesDomainList(url: string, domainList: string[]): boolean {
  const host = urlHostname(url);
  if (!host) return false;
  return domainList.some(
    (d) => host === d.toLowerCase() || host.endsWith("." + d.toLowerCase())
  );
}

/** Returns true if the link's hostname is in config.trustedDomains. */
function isTrustedDomain(url: string): boolean {
  return matchesDomainList(url, config.trustedDomains);
}

/** Returns true if the link's hostname is in config.trustedMeetingDomains. */
function isTrustedMeetingDomain(url: string): boolean {
  return matchesDomainList(url, config.trustedMeetingDomains);
}

/**
 * Returns true if a URL looks inherently suspicious.
 * Skips mailto:, #anchors, and tel: links — those are handled separately.
 * Skips links to trusted domains.
 */
function isSuspiciousUrl(url: string): boolean {
  if (!url) return false;
  // Skip non-http schemes that aren't themselves suspicious
  if (
    url.startsWith("mailto:") ||
    url.startsWith("#") ||
    url.startsWith("tel:")
  ) return false;

  if (isTrustedDomain(url) || isTrustedMeetingDomain(url)) return false;

  try {
    const parsed = new URL(url);
    // Flag non-https links (http:// is a phishing red flag)
    if (parsed.protocol !== "https:") return true;
    // Flag raw IP addresses as hostname
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) return true;
    // Flag URLs with excessive subdomains (>4 parts, e.g. a.b.c.evil.com)
    if (parsed.hostname.split(".").length > 4) return true;
    return false;
  } catch {
    return true; // Unparseable URL is treated as suspicious
  }
}

/**
 * Detects a link mismatch: the visible anchor text looks like a domain/URL,
 * but the actual href resolves to a different hostname+path.
 *
 * Key improvements over the original:
 * - Compares BOTH hostname AND pathname (not just hostname).
 * - Ignores protocol, www prefix, query parameters, hash, and trailing slash.
 * - Example that should NOT mismatch:
 *     text = "meet.google.com/abc-defg-hij"
 *     href = "https://meet.google.com/abc-defg-hij?hs=224"
 *   → hostname matches, pathname matches → no mismatch ✓
 */
function isLinkMismatch(linkText: string, href: string): boolean {
  if (!linkText || !href) return false;
  // tel: and mailto: links never produce a visual domain mismatch
  if (href.startsWith("tel:") || href.startsWith("mailto:")) return false;

  const trimmedText = linkText.trim();

  // Does the link text itself look like a URL or a bare domain/path?
  // Must contain at least one dot in a domain-like position.
  if (!/[a-z0-9-]+\.[a-z]{2,}/i.test(trimmedText)) return false;

  // Normalise the text: if it has no scheme, prepend https:// so URL() can parse it.
  const textUrl = trimmedText.startsWith("http")
    ? trimmedText
    : "https://" + trimmedText.replace(/^\/\//, "");

  let textHost: string;
  let textPath: string;
  try {
    const parsed = new URL(textUrl);
    textHost = parsed.hostname.toLowerCase().replace(/^www\./, "");
    textPath = parsed.pathname.toLowerCase().replace(/\/$/, "");
  } catch {
    // Text doesn't parse as a URL — extract the domain portion manually
    const domainMatch = trimmedText.match(/([a-z0-9-]+\.[a-z]{2,})/i);
    if (!domainMatch) return false;
    textHost = domainMatch[1].toLowerCase().replace(/^www\./, "");
    textPath = "";
  }

  const hrefHost = urlHostname(href);
  const hrefPath = urlPathname(href);

  if (!hrefHost) return false;

  // The href host must end with the text host (allows subdomain→parent matching)
  if (!hrefHost.endsWith(textHost) && hrefHost !== textHost) return true;

  // If the text also specifies a path, the href path must start with that path.
  // This catches text = "interac.ca/pay" href = "https://evil.com/interac.ca/pay"
  // (caught by hostname check above), but also allows query params to differ.
  if (textPath && !hrefPath.startsWith(textPath)) return true;

  return false;
}

// ── Google Calendar invite detection ─────────────────────────────────────────

/**
 * Returns true when the email is almost certainly a legitimate Google Calendar
 * or Google Meet invitation. When this is true, tel: links are ignored and
 * meet.google.com link-mismatch checks are suppressed.
 *
 * Detection criteria (all three must be met):
 *   1. Sender email is in config.trustedCalendarSenders OR from google.com.
 *   2. Body or subject contains calendar/meet invitation language.
 *   3. At least one link points to meet.google.com or calendar.google.com.
 */
function isLikelyGoogleCalendarInvite(email: EmailData): boolean {
  // ── Criterion 1: trusted sender ──────────────────────────────────────────
  const senderEmailLower = email.senderEmail.toLowerCase();
  const isTrustedSender =
    config.trustedCalendarSenders.some((s) => senderEmailLower === s.toLowerCase()) ||
    senderEmailLower.endsWith("@google.com");

  if (!isTrustedSender) return false;

  // ── Criterion 2: calendar / meet language in body or subject ─────────────
  const calendarPhrases = [
    "google calendar",
    "google meet",
    "join with google meet",
    "calendar invite",
    "you have been invited",
    "invitation:",        // Google Calendar subject prefix
    "join video call",
    "video call link",
    "dial in",
    "dial-in",
  ];
  const fullText = [email.subject, email.bodyText].join(" ");
  const hasCalendarLanguage = calendarPhrases.some((p) => contains(fullText, p));

  if (!hasCalendarLanguage) return false;

  // ── Criterion 3: at least one meet.google.com or calendar.google.com link ─
  const hasMeetLink = email.links.some((link) =>
    isTrustedMeetingDomain(link.href)
  );

  return hasMeetLink;
}

// ── Known typo / fake-brand patterns ─────────────────────────────────────────
// Regex list for common scammer misspellings and look-alike characters.
const SPELLING_PATTERNS: RegExp[] = [
  /reb[t4]e/i,           // "rebte", "reb4e" instead of "rebate"
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

  // Detect Google Calendar invite early — used to gate several checks below.
  const calendarInvite = isLikelyGoogleCalendarInvite(email);

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
  // NOTE: This checks body TEXT for phrases like "send me your phone number".
  // It is distinct from tel: links (handled in check 4 below), which are dial-in
  // numbers embedded in calendar invites — not requests for the user's number.
  const contactMatches = matchesAny(fullText, config.contactKeywords);
  if (contactMatches.length > 0) {
    score += w.contactInfoRequest;
    reasons.push(
      `Asks for personal contact information (e.g. "${contactMatches[0]}").`
    );
  }

  // ── 3. Financial fraud patterns (gift cards, payments, etc.) ─────────────
  const payrollKeywords = [
    "payroll", "bank account", "direct deposit",
    "wire transfer", "e-transfer", "etransfer",
  ];
  const payrollMatches = matchesAny(fullText, payrollKeywords);
  const financialMatches = matchesAny(fullText, config.financialKeywords);

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

  // ── 4. Link analysis ──────────────────────────────────────────────────────
  let suspiciousLinkFound = false;
  let linkMismatchFound = false;
  let telLinkFound = false;

  for (const link of email.links) {
    const { href, text } = link;

    // ── tel: links ──────────────────────────────────────────────────────────
    // tel: links in a Google Calendar invite are normal dial-in numbers.
    // Outside of calendar invites they are a weak signal worth noting, but
    // they are NOT equivalent to someone asking for your personal phone number
    // in the email body (that is check 2 above, which remains high-scored).
    if (href.startsWith("tel:")) {
      if (!calendarInvite && !telLinkFound) {
        score += w.telLink; // +5 — low signal only
        telLinkFound = true;
        // No user-visible reason added: too low-signal to alarm the user.
      }
      continue; // Never treat a tel: link as suspicious or mismatched
    }

    // ── Suspicious URL check ────────────────────────────────────────────────
    if (!suspiciousLinkFound && isSuspiciousUrl(href)) {
      score += w.suspiciousLink;
      reasons.push(
        `Contains a suspicious link: ${href.slice(0, 60)}${href.length > 60 ? "…" : ""}`
      );
      suspiciousLinkFound = true;
    }

    // ── Link mismatch check ─────────────────────────────────────────────────
    // Skip mismatch check for links that are trusted meeting domains — query
    // params like ?hs=224 on meet.google.com URLs would otherwise trip this.
    if (!linkMismatchFound && !isTrustedMeetingDomain(href) && isLinkMismatch(text, href)) {
      score += w.linkMismatch;
      reasons.push(
        `Link text "${text.slice(0, 40)}" does not match its actual destination.`
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
