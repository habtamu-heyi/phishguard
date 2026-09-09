# phishguard

Open-source phishing and fraud detection engine using original structural URL analysis and email forensics.

## PhishGuard — Phishing & Fraud Detection Engine

![Version](https://img.shields.io/badge/version-1.1.0-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Engine](https://img.shields.io/badge/engine-rule--based-orange) ![Node](https://img.shields.io/badge/node-%E2%89%A518-brightgreen)

PhishGuard is an open-source phishing and fraud detection engine that analyzes URLs and emails using original, rule-based structural and linguistic analysis. Rather than relying on blacklists — which can only catch threats that have already been reported — PhishGuard evaluates the structural and behavioral characteristics of a URL or email directly, enabling detection of phishing attempts that have not yet been catalogued anywhere else.

Designed for deployment by organizations without dedicated security analysts, PhishGuard translates multi-dimensional threat analysis into a single explainable PhishScore, with an optional AI layer that turns the result into a plain-English summary.

### Live Demo

🔗 Deployed alongside [CyberWatch CTI Dashboard](https://github.com/habtamu-heyi/cyberwatch-cti) — see Documented Deployments below.

### What Makes PhishGuard Different

Most free phishing checkers rely on blacklists (e.g. Google Safe Browsing) — reactive systems that can only flag a URL after it has already been reported and verified by someone else. PhishGuard is proactive:

- **Structural detection, not blacklist lookup** — evaluates the URL and email itself, catching phishing infrastructure before it's been reported anywhere
- **Thirteen independent dimensions** — six for URL analysis, seven for email forensics, each contributing an explainable, weighted signal
- **Homoglyph-aware brand matching** — normalizes lookalike character substitutions (e.g. `paypa1.com` → `paypal.com`) before comparing against a brand database, rather than simple string matching
- **Explainable scoring** — every result includes the specific contributing factors, not just a verdict
- **Independently validated** — tested against a live, independently-verified phishing dataset (see Validation Study below), with results reported honestly, including limitations
- **Optional AI explanation layer** — translates technical scores into plain English for non-technical users, without ever performing detection itself

### Detection Architecture

PhishGuard is built from two clearly separated layers, deliberately kept apart so that the detection claim rests entirely on original, inspectable, reproducible logic:

| Layer | Role | Technology |
|---|---|---|
| **Detection Engine** | Computes the PhishScore, verdict, and every contributing signal | Rule-based: Shannon entropy, Levenshtein distance, homoglyph normalization, weighted keyword classification, header forensics |
| **AI Explanation Layer** (optional) | Translates an *already-computed* result into a 2–3 sentence plain-English summary | Google Gemini (or Groq / Anthropic — provider-agnostic) |

The AI layer is called only after detection is complete, receives only the already-computed score and signals (never the raw URL or email content), and cannot alter a verdict. If it is unavailable or unconfigured, every detection endpoint still returns the full, correct rule-based result.

### URL Detection — 6 Dimensions

| Dimension | Weight | Description |
|---|---|---|
| Brand Impersonation | 28% | Homoglyph-normalized brand matching + Levenshtein typosquat detection against 200+ tracked brands |
| TLD Risk | 20% | Reputation scoring across 45+ TLDs based on documented phishing abuse rates |
| Redirect Risk | 19% | URL shorteners and redirect chains that hide the true destination |
| Lexical Analysis | 18% | Structural red flags — raw IPs, excessive hyphens, @ symbols, percent-encoding |
| Structural Anomalies | 10% | Pattern matching against known malicious URL constructions |
| Domain Entropy | 5% | Shannon entropy and consonant/vowel ratio to flag algorithmically generated domains |

Verdict thresholds: **PHISHING** (≥65) · **SUSPICIOUS** (≥40) · **UNCERTAIN** (≥20) · **LIKELY SAFE** (<20)

### Email Detection — 7 Dimensions

| Dimension | Weight | Description |
|---|---|---|
| Sender Spoofing | 25% | Display name vs. actual sender domain mismatch; free-provider abuse detection |
| Header Forensics | 20% | SPF / DKIM / DMARC authentication failures, Reply-To mismatches, routing anomalies |
| Urgency Manipulation | 20% | Weighted classification across 40+ documented social-engineering phrase patterns |
| Link Analysis | 15% | Every embedded URL is independently scored through the URL engine above |
| Brand Impersonation | 10% | Claimed sender identity vs. actual domain |
| Attachment Risk | 5% | Dangerous file types, double extensions, macro-enabled documents |
| Content Anomalies | 5% | Generic greetings, hidden HTML text, thread-hijacking patterns |

Full methodology: [`Methodology.md`](./Methodology.md)

### Validation Study

PhishGuard's URL engine has been tested against live, independently-verified phishing data from [PhishTank](https://phishtank.org) — a community-driven database where every URL has already been confirmed as phishing by reviewers unaffiliated with this project.

**Latest result:** 7.0% detection rate (score ≥ 40) against a random 100-URL sample drawn from PhishTank's live feed on 2026-09-09.

This number is reported honestly, including what it reveals: analysis of the tested sample found that a substantial share of confirmed phishing URLs used ordinary, low-suspicion domains (36% on `.com` alone) with minimal structural red flags — reflecting a well-documented industry trend in which phishing operators increasingly favor clean-looking domains specifically to evade structural detection. This is a genuine, known limitation of lexical/structural URL analysis performed in isolation, consistent with findings across the anti-phishing research literature.

Two real detection gaps were identified and fixed during this validation process:
1. A flawed homoglyph-substitution check that fired independently of any actual brand match, producing false positives unrelated to real phishing indicators
2. A stale high-risk-TLD list missing several currently-abused TLDs (`.cyou`, `.sbs`, `.buzz`, etc.)

Full study, methodology, and raw dataset: [`docs/validation-study-2026-09-09.md`](./docs/validation-study-2026-09-09.md)

This study can be reproduced by any reviewer via `npm run validate`.

### Features

- **URL Scanner** — score any URL with full dimension breakdown
- **Email Analyzer** — full header, sender, content, and attachment analysis
- **Bulk Scanner** — score up to 50 URLs in a single request
- **AI Explanation** — optional plain-English summary of any result (`/explain` endpoints)
- **Scan History** — persistent record via Supabase
- **CyberWatch Integration** — dedicated enrichment endpoint for cross-tool IOC analysis

### Quick Start

**Prerequisites**
- Node.js ≥ 18
- npm or yarn

**Installation**
```bash
git clone https://github.com/habtamu-heyi/phishguard.git
cd phishguard
npm install
cp .env.example .env
# Add your API keys to .env (all optional — see below)
npm run dev
```

Server runs on `http://localhost:3001`. Detection works immediately with zero configuration.

### Environment Variables

```bash
# Optional — enables persistent scan history and stats
SUPABASE_URL=your_supabase_url
SUPABASE_ANON_KEY=your_supabase_anon_key

# Optional — enables the AI plain-English explanation layer
# Pick ONE provider (Gemini recommended — free tier, no credit card)
AI_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key
# GROQ_API_KEY=your_groq_api_key
# ANTHROPIC_API_KEY=your_anthropic_api_key
```

All API keys are optional. Detection runs fully without any configuration — the AI explanation layer and Supabase persistence are additive.

### Documented Deployments

PhishGuard has been deployed alongside CyberWatch to the following organizations, each of which received a written findings report and confirmed the engagement by organizational letter of record:

| Organization | Type | Notable Finding |
|---|---|---|
| KD Allen Ministries (kingdomrich.life) | Faith-based | Domain flagged malicious by Webroot, confirmed via multi-engine scan — organization had no prior awareness |
| Greater Nation International Church (gnic.life) | Faith-based | Phishing impersonation risk identified on online giving page; SPF/DKIM authentication gaps confirmed |
| Anchor Bay University (anchorbayuniversity.com) | Educational | Admissions and financial aid pages flagged as high-sensitivity phishing targets |
| Kingdom Legacy Missionary Service (kingdomlegacy.live) | Nonprofit/missionary | Cross-border donation system identified as a high-value phishing target |

### Architecture

phishguard/
├── server.js Express API server
├── src/
│ ├── threat-data.js Brand list, TLD risk scores, urgency keyword weights
│ ├── ai-explain.js Optional AI explanation layer (provider-agnostic)
│ └── engines/
│ ├── url-engine.js 6-dimension URL detection (rule-based)
│ └── email-engine.js 7-dimension email detection (rule-based)
├── scripts/
│ └── phishtank-validation.js Independent validation study script
├── public/
│ └── index.html Dashboard UI
└── docs/ Methodology and validation study output




### API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/analyze/url` | Score a URL — detection only |
| POST | `/api/analyze/url/explain` | Score a URL + AI plain-English summary |
| POST | `/api/analyze/email` | Score an email — detection only |
| POST | `/api/analyze/email/explain` | Score an email + AI plain-English summary |
| POST | `/api/analyze/bulk` | Score up to 50 URLs in one request |
| GET | `/api/history` | Recent scan history (requires Supabase) |
| GET | `/api/stats` | Aggregate scan statistics |
| POST | `/api/cyberwatch/enrich` | Integration endpoint for CyberWatch |
| GET | `/api/health` | Service health check |

### Addressing a National Cybersecurity Gap

CISA has identified faith-based institutions, educational organizations, nonprofits, and small businesses as high-value, under-resourced targets for phishing and fraud — organizations that hold sensitive data and process financial transactions but operate without the security infrastructure larger enterprises take for granted. Commercial phishing detection and threat intelligence platforms are priced entirely out of reach for this segment. PhishGuard is free, open-source, and designed to be deployable by any organization in this category.

### Author

**Habtamu W. Heyi**
Cyber Crime Intelligence Analyst, Walmart Inc. (Fortune 1)
Master's degree in Cybersecurity Engineering

GitHub: [@habtamu-heyi](https://github.com/habtamu-heyi)

### Related Project

[**CyberWatch CTI Dashboard**](https://github.com/habtamu-heyi/cyberwatch-cti) — Open-source cyber threat intelligence platform with the CTSE multi-factor scoring algorithm.

### License

MIT License — free to use, modify, and deploy. See [LICENSE](./LICENSE).
