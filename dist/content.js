"use strict";
(() => {
  // src/config.ts
  var config = {
    // ── Your organisation's email domains ──────────────────────────────────────
    // Emails FROM these domains are considered internal and trusted.
    // Any email that spoofs an internal name but uses an outside domain gets
    // a heavy score penalty.
    companyDomains: [
      "upluseducation.ca",
      "yorkeducation.ca"
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
      "Umair"
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
      "personal email"
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
      "buy now"
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
      "as soon as possible"
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
      "amazon"
    ],
    // ── Vague document / link request phrases ──────────────────────────────────
    vagueDocKeywords: [
      "click the link",
      "open the file",
      "view the document",
      "see attached",
      "download and open",
      "review the attachment",
      "access the document"
    ],
    // ── Scoring weights ────────────────────────────────────────────────────────
    // Adjust these numbers to tune sensitivity.
    weights: {
      executiveSpoofing: 40,
      // Sender name matches internal name + external domain
      contactInfoRequest: 30,
      // Asking for phone/WhatsApp/cell
      financialRequest: 35,
      // Gift cards / payments / payroll
      suspiciousLink: 25,
      // A link href looks suspicious
      linkMismatch: 30,
      // Link text ≠ actual destination domain
      externalImpersonation: 25,
      // Brand impersonation
      payrollBankChange: 35,
      // Payroll / bank change (subset of financial)
      urgencyLanguage: 15,
      // Urgency keywords
      vagueDocRequest: 20,
      // Vague "click this" with no context
      spellingIssue: 10
      // Typos / fake-brand characters
    },
    // ── Risk thresholds ────────────────────────────────────────────────────────
    thresholds: {
      caution: 30,
      // Score ≥ 30  → yellow banner
      suspicious: 60,
      // Score ≥ 60  → orange banner
      highRisk: 80
      // Score ≥ 80  → red banner
    }
  };

  // src/scamScorer.ts
  function contains(haystack, needle) {
    return haystack.toLowerCase().includes(needle.toLowerCase());
  }
  function matchesAny(text, keywords) {
    return keywords.filter((kw) => contains(text, kw));
  }
  function hostname(url) {
    try {
      return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    } catch {
      return "";
    }
  }
  function isTrustedDomain(url) {
    const host = hostname(url);
    return config.trustedDomains.some(
      (d) => host === d.toLowerCase() || host.endsWith("." + d.toLowerCase())
    );
  }
  function isSuspiciousUrl(url) {
    if (!url || url.startsWith("mailto:") || url.startsWith("#")) return false;
    if (isTrustedDomain(url)) return false;
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== "https:") return true;
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) return true;
      const parts = parsed.hostname.split(".");
      if (parts.length > 4) return true;
      return false;
    } catch {
      return true;
    }
  }
  function isLinkMismatch(linkText, href) {
    if (!linkText || !href) return false;
    const textLooksLikeDomain = /[a-z0-9-]+\.[a-z]{2,}/i.test(linkText.trim());
    if (!textLooksLikeDomain) return false;
    const textDomainMatch = linkText.trim().match(/([a-z0-9-]+\.[a-z]{2,})/i);
    if (!textDomainMatch) return false;
    const textDomain = textDomainMatch[1].toLowerCase().replace(/^www\./, "");
    const hrefHost = hostname(href);
    return hrefHost !== "" && !hrefHost.endsWith(textDomain);
  }
  var SPELLING_PATTERNS = [
    /reb[t4]e/i,
    // "rebte", "reb4e" instead of "rebate"
    /g[i1]ft.?c[a4]rd/i,
    // "g1ft card", "gift c4rd"
    /[i1]nter[a4]c/i,
    // "1nterac", "interac" with substituted chars
    /c[o0]nfirm/i,
    // "c0nfirm"
    /verif[i1]c[a4]tion/i,
    // "verif1cation"
    /acc[o0]unt/i,
    // "acc0unt"
    /s[e3]cur[i1]ty/i
    // "s3curity"
  ];
  function scoreEmail(email) {
    let score = 0;
    const reasons = [];
    const w = config.weights;
    const fullText = [email.subject, email.bodyText, email.senderName].join(" ");
    if (email.senderName) {
      const nameLower = email.senderName.toLowerCase();
      const matchedName = config.internalNames.find(
        (n) => nameLower.includes(n.toLowerCase())
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
    const contactMatches = matchesAny(fullText, config.contactKeywords);
    if (contactMatches.length > 0) {
      score += w.contactInfoRequest;
      reasons.push(
        `Asks for personal contact information (e.g. "${contactMatches[0]}").`
      );
    }
    const financialMatches = matchesAny(fullText, config.financialKeywords);
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
    let suspiciousLinkFound = false;
    let linkMismatchFound = false;
    for (const link of email.links) {
      if (!suspiciousLinkFound && isSuspiciousUrl(link.href)) {
        score += w.suspiciousLink;
        reasons.push(
          `Contains a suspicious link: ${link.href.slice(0, 60)}${link.href.length > 60 ? "\u2026" : ""}`
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
    const brandMatches = matchesAny(fullText, config.externalBrands);
    if (brandMatches.length > 0) {
      const senderDomain = email.senderEmail.split("@")[1]?.toLowerCase() ?? "";
      const brandTrusted = isTrustedDomain("https://" + senderDomain);
      if (!brandTrusted) {
        score += w.externalImpersonation;
        reasons.push(
          `May be impersonating a known organisation ("${brandMatches[0]}").`
        );
      }
    }
    const urgencyMatches = matchesAny(fullText, config.urgencyKeywords);
    if (urgencyMatches.length > 0) {
      score += w.urgencyLanguage;
      reasons.push(
        `Uses urgency or pressure language (e.g. "${urgencyMatches[0]}").`
      );
    }
    const vagueMatches = matchesAny(fullText, config.vagueDocKeywords);
    if (vagueMatches.length > 0) {
      score += w.vagueDocRequest;
      reasons.push(
        `Asks you to open a file or click a link without a clear explanation ("${vagueMatches[0]}").`
      );
    }
    const spellingHit = SPELLING_PATTERNS.find((re) => re.test(fullText));
    if (spellingHit) {
      score += w.spellingIssue;
      reasons.push(
        "Contains unusual spelling or look-alike characters (possible fake brand name)."
      );
    }
    score = Math.min(100, Math.max(0, score));
    const riskLevel = getRiskLevel(score);
    return { score, riskLevel, reasons };
  }
  function getRiskLevel(score) {
    if (score >= config.thresholds.highRisk) return "High Risk";
    if (score >= config.thresholds.suspicious) return "Suspicious";
    if (score >= config.thresholds.caution) return "Caution";
    return "Low";
  }

  // src/content.ts
  var BANNER_ID = "gsw-warning-banner";
  var SELECTORS = {
    // The outermost container of an open email thread
    emailView: 'div[role="main"]',
    // The single message "card" inside a thread
    messageContainer: "div.adn.ads",
    // Sender info block
    senderBlock: "span.gD",
    // Subject line
    subject: "h2.hP",
    // Email body
    body: "div.a3s.aiL"
  };
  var lastScannedNode = null;
  function init() {
    const observer = new MutationObserver(onMutation);
    observer.observe(document.body, { childList: true, subtree: true });
    tryScanEmail();
  }
  function onMutation(mutations) {
    tryScanEmail();
  }
  function tryScanEmail() {
    const messages = document.querySelectorAll(SELECTORS.messageContainer);
    if (messages.length === 0) {
      removeBanner();
      lastScannedNode = null;
      return;
    }
    const latestMessage = messages[messages.length - 1];
    if (latestMessage === lastScannedNode) return;
    lastScannedNode = latestMessage;
    removeBanner();
    const emailData = extractEmailData(latestMessage);
    const result = scoreEmail(emailData);
    if (result.riskLevel !== "Low") {
      injectBanner(latestMessage, result.score, result.riskLevel, result.reasons);
    }
  }
  function extractEmailData(messageNode) {
    const senderEl = messageNode.querySelector(SELECTORS.senderBlock) ?? document.querySelector(SELECTORS.senderBlock);
    const senderName = senderEl?.getAttribute("name") ?? senderEl?.textContent?.trim() ?? "";
    const senderEmail = senderEl?.getAttribute("email") ?? "";
    const subjectEl = document.querySelector(SELECTORS.subject);
    const subject = subjectEl?.textContent?.trim() ?? "";
    const bodyEl = messageNode.querySelector(SELECTORS.body);
    const bodyText = bodyEl?.innerText ?? "";
    const anchors = bodyEl?.querySelectorAll("a") ?? [];
    const links = Array.from(anchors).map((a) => ({
      text: a.textContent?.trim() ?? "",
      href: a.href ?? ""
    }));
    return { senderName, senderEmail, subject, bodyText, links };
  }
  function injectBanner(messageNode, score, riskLevel, reasons) {
    if (document.getElementById(BANNER_ID)) return;
    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("data-gsw-banner", "true");
    banner.className = `gsw-banner gsw-banner--${riskLevel.toLowerCase().replace(" ", "-")}`;
    const icon = getRiskIcon(riskLevel);
    const scoreBar = buildScoreBar(score, riskLevel);
    const reasonsHtml = reasons.length > 0 ? `<ul class="gsw-reasons">${reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>` : "";
    const reminder = "Do not reply, click links, share your phone number, or buy gift cards unless you verify through Slack, in person, or another trusted internal channel.";
    banner.innerHTML = `
    <div class="gsw-header">
      <span class="gsw-icon">${icon}</span>
      <span class="gsw-level">${escapeHtml(riskLevel)}</span>
      <span class="gsw-score">Risk score: ${score}/100</span>
      <button class="gsw-dismiss" aria-label="Dismiss warning">\u2715 Dismiss</button>
    </div>
    ${scoreBar}
    ${reasonsHtml}
    <div class="gsw-reminder">
      <strong>\u26A0 Safety reminder:</strong> ${escapeHtml(reminder)}
    </div>
  `;
    banner.querySelector(".gsw-dismiss")?.addEventListener("click", () => {
      banner.remove();
    });
    messageNode.prepend(banner);
  }
  function removeBanner() {
    document.getElementById(BANNER_ID)?.remove();
  }
  function getRiskIcon(riskLevel) {
    switch (riskLevel) {
      case "High Risk":
        return "\u{1F6A8}";
      case "Suspicious":
        return "\u26A0\uFE0F";
      case "Caution":
        return "\u{1F7E1}";
      default:
        return "\u2139\uFE0F";
    }
  }
  function buildScoreBar(score, riskLevel) {
    const pct = Math.min(100, Math.max(0, score));
    return `
    <div class="gsw-scorebar-wrap" aria-label="Risk score ${pct} out of 100">
      <div class="gsw-scorebar-fill gsw-scorebar--${riskLevel.toLowerCase().replace(" ", "-")}"
           style="width:${pct}%"></div>
    </div>
  `;
  }
  function escapeHtml(str) {
    return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
//# sourceMappingURL=content.js.map
