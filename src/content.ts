// ─── Content Script ───────────────────────────────────────────────────────────
//
//  Runs on https://mail.google.com/* and:
//    1. Uses a MutationObserver to detect when the user opens an email.
//    2. Extracts visible email data (sender, subject, body, links).
//    3. Passes the data to scamScorer.ts for scoring.
//    4. Injects a warning banner if the risk level is Caution or higher.
//
//  Gmail is a SPA — the URL and DOM change without full page reloads, so we
//  rely on MutationObserver rather than a simple DOMContentLoaded listener.
// ─────────────────────────────────────────────────────────────────────────────

import { scoreEmail } from "./scamScorer";
import type { EmailData, LinkData } from "./types";

// ── Constants ─────────────────────────────────────────────────────────────────

const BANNER_ID = "gsw-warning-banner";

// Gmail CSS selectors (subject to change if Google updates Gmail's markup).
// These are best-effort selectors that work with the current Gmail DOM.
const SELECTORS = {
  // The outermost container of an open email thread
  emailView: 'div[role="main"]',
  // The single message "card" inside a thread
  messageContainer: 'div.adn.ads',
  // Sender info block
  senderBlock: 'span.gD',
  // Subject line
  subject: 'h2.hP',
  // Email body
  body: 'div.a3s.aiL',
};

// ── State ─────────────────────────────────────────────────────────────────────

// Track the last scanned message element to avoid re-scanning the same email.
let lastScannedNode: Element | null = null;

// ── Entry point ───────────────────────────────────────────────────────────────

/**
 * Start observing the Gmail DOM for email opens.
 * We watch the entire document body because Gmail dynamically replaces large
 * chunks of the DOM when navigating between emails.
 */
function init(): void {
  const observer = new MutationObserver(onMutation);
  observer.observe(document.body, { childList: true, subtree: true });

  // Also try scanning immediately in case an email is already open on load.
  tryScanEmail();
}

// ── MutationObserver callback ─────────────────────────────────────────────────

function onMutation(mutations: MutationRecord[]): void {
  // We don't need to inspect every mutation — just attempt a scan.
  // tryScanEmail() is cheap when no email is open or when it's already scanned.
  tryScanEmail();
}

// ── Email detection ───────────────────────────────────────────────────────────

/**
 * Tries to find an open email in the current DOM.
 * Does nothing if no email is open or if the same email was already scanned.
 */
function tryScanEmail(): void {
  // Find the most recent visible message container
  const messages = document.querySelectorAll<HTMLElement>(SELECTORS.messageContainer);
  if (messages.length === 0) {
    // No email open — remove any lingering banner
    removeBanner();
    lastScannedNode = null;
    return;
  }

  // Take the last (most recently expanded) message
  const latestMessage = messages[messages.length - 1];

  // Skip if we've already scanned this exact DOM node
  if (latestMessage === lastScannedNode) return;
  lastScannedNode = latestMessage;

  // Remove any banner from the previous email
  removeBanner();

  // Extract data and score
  const emailData = extractEmailData(latestMessage);
  const result = scoreEmail(emailData);

  // Only show a banner for Caution level and above
  if (result.riskLevel !== "Low") {
    injectBanner(latestMessage, result.score, result.riskLevel, result.reasons);
  }
}

// ── Data extraction ───────────────────────────────────────────────────────────

/**
 * Extracts visible email metadata from a Gmail message DOM node.
 * We only read text that is already rendered on screen — we never make
 * any network requests or access raw MIME data.
 */
function extractEmailData(messageNode: HTMLElement): EmailData {
  // ── Sender name and email ────────────────────────────────────────────────
  const senderEl = messageNode.querySelector<HTMLElement>(SELECTORS.senderBlock)
    ?? document.querySelector<HTMLElement>(SELECTORS.senderBlock);

  const senderName = senderEl?.getAttribute("name") ?? senderEl?.textContent?.trim() ?? "";
  const senderEmail = senderEl?.getAttribute("email") ?? "";

  // ── Subject ──────────────────────────────────────────────────────────────
  const subjectEl = document.querySelector<HTMLElement>(SELECTORS.subject);
  const subject = subjectEl?.textContent?.trim() ?? "";

  // ── Body text ────────────────────────────────────────────────────────────
  const bodyEl = messageNode.querySelector<HTMLElement>(SELECTORS.body);
  const bodyText = bodyEl?.innerText ?? "";

  // ── Links ────────────────────────────────────────────────────────────────
  const anchors = bodyEl?.querySelectorAll<HTMLAnchorElement>("a") ?? [];
  const links: LinkData[] = Array.from(anchors).map((a) => ({
    text: a.textContent?.trim() ?? "",
    href: a.href ?? "",
  }));

  return { senderName, senderEmail, subject, bodyText, links };
}

// ── Banner injection ──────────────────────────────────────────────────────────

/**
 * Inserts a warning banner directly above the email body.
 * The banner is a simple div injected into the DOM — no iframes or shadow DOM.
 */
function injectBanner(
  messageNode: HTMLElement,
  score: number,
  riskLevel: string,
  reasons: string[]
): void {
  // Safety check — avoid duplicate banners
  if (document.getElementById(BANNER_ID)) return;

  const banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.setAttribute("data-gsw-banner", "true");
  banner.className = `gsw-banner gsw-banner--${riskLevel.toLowerCase().replace(" ", "-")}`;

  // ── Icon + level label ───────────────────────────────────────────────────
  const icon = getRiskIcon(riskLevel);
  const scoreBar = buildScoreBar(score, riskLevel);

  // ── Reasons list ─────────────────────────────────────────────────────────
  const reasonsHtml = reasons.length > 0
    ? `<ul class="gsw-reasons">${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`
    : "";

  // ── Safety reminder ──────────────────────────────────────────────────────
  const reminder =
    "Do not reply, click links, share your phone number, or buy gift cards " +
    "unless you verify through Slack, in person, or another trusted internal channel.";

  banner.innerHTML = `
    <div class="gsw-header">
      <span class="gsw-icon">${icon}</span>
      <span class="gsw-level">${escapeHtml(riskLevel)}</span>
      <span class="gsw-score">Risk score: ${score}/100</span>
      <button class="gsw-dismiss" aria-label="Dismiss warning">✕ Dismiss</button>
    </div>
    ${scoreBar}
    ${reasonsHtml}
    <div class="gsw-reminder">
      <strong>⚠ Safety reminder:</strong> ${escapeHtml(reminder)}
    </div>
  `;

  // Wire up dismiss button
  banner.querySelector<HTMLButtonElement>(".gsw-dismiss")?.addEventListener("click", () => {
    banner.remove();
  });

  // Insert the banner at the very top of the message node so it appears
  // above the email content but stays within the email card.
  messageNode.prepend(banner);
}

/** Removes any existing banner from the DOM. */
function removeBanner(): void {
  document.getElementById(BANNER_ID)?.remove();
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function getRiskIcon(riskLevel: string): string {
  switch (riskLevel) {
    case "High Risk":   return "🚨";
    case "Suspicious":  return "⚠️";
    case "Caution":     return "🟡";
    default:            return "ℹ️";
  }
}

/** Renders a visual score bar using a simple filled div. */
function buildScoreBar(score: number, riskLevel: string): string {
  const pct = Math.min(100, Math.max(0, score));
  return `
    <div class="gsw-scorebar-wrap" aria-label="Risk score ${pct} out of 100">
      <div class="gsw-scorebar-fill gsw-scorebar--${riskLevel.toLowerCase().replace(" ", "-")}"
           style="width:${pct}%"></div>
    </div>
  `;
}

/** Minimal HTML escaping to prevent XSS from email content in the banner. */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

// Wait for the DOM to be ready, then start observing.
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
