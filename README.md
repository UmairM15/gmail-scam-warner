# Gmail Scam Warner — Chrome Extension

A lightweight Chrome Extension (Manifest V3) that adds a **second layer of warning** when you open a suspicious or scam-looking email in Gmail.

It runs entirely in your browser. No backend, no database, no AI API, no network requests. Email content is never stored or transmitted anywhere.

---

## Folder Structure

```
gmail-scam-warner/
├── manifest.json          Chrome Extension manifest (MV3)
├── package.json           npm build scripts
├── tsconfig.json          TypeScript config
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── src/
    ├── config.ts          ← EDIT THIS to customise names, domains, keywords
    ├── types.ts           Shared TypeScript interfaces
    ├── scamScorer.ts      Scoring logic — reads config and scores an email
    ├── content.ts         Content script — watches Gmail and injects banners
    └── styles.css         Banner styles (injected alongside content.ts)
```

After a successful build, a `dist/` folder is created:

```
dist/
└── content.js             Bundled + compiled output (loaded by Chrome)
```

---

## Prerequisites

- **Node.js 18+** — [nodejs.org](https://nodejs.org)
- **npm** — included with Node.js
- **Google Chrome**

---

## Setup & Build

```bash
# 1. Navigate to the project folder
cd gmail-scam-warner

# 2. Install dependencies (only esbuild + typescript)
npm install

# 3. Build the extension
npm run build
```

This produces `dist/content.js`.

To rebuild automatically whenever you change a source file:

```bash
npm run watch
```

---

## Load the Extension in Chrome

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `gmail-scam-warner/` folder (the root, containing `manifest.json`)
5. The extension will appear in your extensions list

> Every time you rebuild (`npm run build`), click the **↻ refresh** icon on the extension card in `chrome://extensions`.

---

## Test the Extension

1. Open [Gmail](https://mail.google.com) in Chrome
2. Open any email that contains suspicious content
3. A coloured warning banner should appear at the top of the email message

### Quick test checklist

| What to try | Expected banner |
|---|---|
| Email from `kevin@gmail.com` with display name "Kevin Lin" | 🚨 High Risk (executive spoofing) |
| Email body contains "gift card" or "urgent" | 🟡 Caution or ⚠️ Suspicious |
| Email body contains a link where the text says `interac.ca` but href goes elsewhere | ⚠️ Suspicious (link mismatch) |
| Normal internal email from `yourcompany.org` | No banner |

---

## How Scoring Works

Each scam detection check runs independently on the email's visible text, sender name, sender email, and links. When a pattern is detected, a fixed number of points is added to the score. The final score is clamped to 100.

| Check | Points |
|---|---|
| Sender display name matches internal staff but email is external | +40 |
| Asks for phone/WhatsApp/cell number | +30 |
| Mentions gift cards, vouchers, reimbursements | +35 |
| Mentions payroll or bank account changes | +35 |
| Contains a suspicious link (non-HTTPS, IP, excess subdomains) | +25 |
| Link text domain ≠ actual link destination | +30 |
| Impersonates an external brand or organisation | +25 |
| Uses urgency / pressure language | +15 |
| Vague "click this" / "open this file" with no explanation | +20 |
| Spelling / look-alike character patterns | +10 |

**Risk levels:**

| Score | Level | Banner |
|---|---|---|
| 0–29 | Low | No banner |
| 30–59 | Caution | 🟡 Yellow |
| 60–79 | Suspicious | 🟠 Orange |
| 80–100 | High Risk | 🔴 Red |

---

## Customising the Extension

All configuration lives in **`src/config.ts`**. Open it in any text editor.

### Add your company's email domains

```ts
companyDomains: [
  "yourcompany.org",
  "yourcompany.ca",
],
```

These are the domains considered "internal". Any email that appears to come from a staff member but uses a different domain will be flagged.

### Add internal staff / executive names

```ts
internalNames: [
  "Kevin Lin",
  "Moxi Zhang",
  "Carey",
  "Tanya",
],
```

Add the display names of people in your organisation who might be impersonated. Matching is case-insensitive and partial (so "Tanya" matches "Tanya Smith").

### Add trusted external vendor domains

```ts
trustedDomains: [
  "wix.com",
  "interac.ca",
  "google.com",
],
```

Links pointing to these domains won't trigger the suspicious-link check.

### Adjust keywords

Edit any of these arrays to add or remove phrases:
- `contactKeywords` — phrases that suggest asking for personal contact info
- `financialKeywords` — gift cards, vouchers, payments, etc.
- `urgencyKeywords` — pressure/urgency language
- `externalBrands` — brands that scammers commonly impersonate
- `vagueDocKeywords` — vague "click here" phrases

### Adjust score weights and thresholds

```ts
weights: {
  executiveSpoofing: 40,
  contactInfoRequest: 30,
  // ...
},
thresholds: {
  caution: 30,
  suspicious: 60,
  highRisk: 80,
},
```

**After any change to `src/config.ts` or any other source file:**

```bash
npm run build
```

Then refresh the extension in `chrome://extensions`.

---

## Privacy & Permissions

- The extension only runs on `https://mail.google.com/*`
- It only reads text that is already rendered on your screen
- It does **not** make any network requests
- It does **not** store or transmit email content
- It does **not** modify, delete, archive, or report emails
- The only Chrome permission used is `storage` (reserved for future settings UI)

---

## Limitations & Known Issues

- Gmail's DOM structure can change without notice. If the extension stops working after a Gmail update, the CSS selectors in `src/content.ts` under `SELECTORS` may need updating.
- The extension reads visible body text only. It does not parse raw email headers or MIME parts.
- Scoring is heuristic — it will occasionally produce false positives on legitimate emails. Use the **Dismiss** button if a banner is not needed.
