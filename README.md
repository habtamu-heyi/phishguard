# PhishGuard v1.1 — Phishing & Fraud Detection Engine

**Author:** Habtamu Heyi
**License:** MIT

---

## What This Is

PhishGuard analyzes URLs and emails using an original, rule-based, fully deterministic multi-factor detection engine. Version 1.1 adds an optional AI explanation layer that translates detection results into plain English — it does **not** perform detection.

## Architecture — Detection vs. Explanation (read this first)

This distinction matters and is deliberate:

| Layer | What it does | Technology | Required? |
|---|---|---|---|
| **Detection Engine** (`src/engines/`) | Computes the PhishScore, verdict, and all signals | Rule-based: Shannon entropy, Levenshtein distance, homoglyph normalization, weighted keyword classification, header forensics | Yes — this is the core original contribution |
| **AI Explanation Layer** (`src/ai-explain.js`) | Translates an *already-computed* result into a 2-3 sentence plain-English summary for non-technical users | Provider-agnostic: Groq (free), Google Gemini (free), or Anthropic (paid) — configurable via `.env` | No — fully optional, detection works completely without it |

The AI layer is called **after** detection is complete, is given only the already-computed score/verdict/signals (never the raw URL or email content to independently judge), and cannot change a verdict. If the AI layer is unavailable or unconfigured, every detection endpoint still returns the full, correct rule-based result — the AI summary field is simply `null`.

This separation exists so that PhishGuard's core detection claim rests entirely on original, reproducible, inspectable logic — not on a third-party model's behavior.

## Detection Dimensions

**URL Engine** — 6 dimensions: lexical analysis, domain entropy (Shannon), brand impersonation (Levenshtein + homoglyph normalization), TLD risk scoring, structural anomalies, redirect risk.

**Email Engine** — 7 dimensions: header forensics (SPF/DKIM/DMARC), sender spoofing, urgency-language classification (weighted keyword matching), link analysis, brand impersonation in content, attachment risk, content anomalies.

See `docs/METHODOLOGY.md` for full technical detail on each dimension.

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/api/analyze/url` | POST | Detection only, no AI |
| `/api/analyze/url/explain` | POST | Detection + AI plain-English summary |
| `/api/analyze/email` | POST | Detection only, no AI |
| `/api/analyze/email/explain` | POST | Detection + AI plain-English summary |
| `/api/analyze/bulk` | POST | Bulk URL scan (up to 50), detection only |
| `/api/history` | GET | Recent analyses (requires Supabase) |
| `/api/stats` | GET | Aggregate stats (requires Supabase) |
| `/api/cyberwatch/enrich` | POST | Integration endpoint for CyberWatch |
| `/api/health` | GET | Server + engine + AI layer status |

## Getting Started

```bash
npm install
cp .env.example .env
```

Edit `.env` — Supabase is optional. For the AI explanation layer, pick **one** free provider:

**Groq (recommended — free, no credit card):**
1. Get a key at https://console.groq.com/keys
2. Set `GROQ_API_KEY=your_key` in `.env`

**Google Gemini (free tier alternative):**
1. Get a key at https://aistudio.google.com/apikey
2. Set `GEMINI_API_KEY=your_key` in `.env`

```bash
npm start
```

Server runs on `http://localhost:3001`. Detection endpoints work immediately with zero configuration. The AI explanation layer activates automatically once any one provider key is set — PhishGuard auto-detects which provider to use.

## Validation Study

`scripts/phishtank-validation.js` runs PhishGuard's URL engine against a random sample of independently verified phishing URLs from PhishTank (phishtank.org), producing a reproducible detection-rate report.

```bash
npm run validate
```

This requires outbound internet access to `data.phishtank.com`. Output is written to `docs/validation-study-<date>.md` and `.json`, plus the raw sampled dataset for integrity verification. See the script's header comment for full methodology notes.

## Project Structure

```
phishguard/
├── server.js                    Express API server
├── src/
│   ├── threat-data.js           Brand/TLD/keyword reference data
│   ├── ai-explain.js            AI explanation layer (optional, additive)
│   └── engines/
│       ├── url-engine.js        6-dimension URL detection (rule-based)
│       └── email-engine.js      7-dimension email detection (rule-based)
├── scripts/
│   └── phishtank-validation.js  Independent validation study script
├── public/
│   └── index.html               Dashboard UI
└── docs/                        Methodology + validation study output
```
