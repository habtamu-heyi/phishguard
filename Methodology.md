# PhishGuard — Detection Methodology

**Author:** Habtamu W. Heyi
**Version:** 1.1.0

This document describes the technical methodology behind PhishGuard's URL and email phishing detection engines, including the rationale for dimension weighting, the design decisions that distinguish this approach from existing tools, and the honest findings of PhishGuard's independent validation study.

---

## 1. Design Philosophy

PhishGuard is built on a single core principle: **detection must be structural and reproducible, not dependent on a third-party blacklist or a black-box model.**

Most free phishing-checking tools fall into one of two categories:

1. **Blacklist lookups** (e.g. Google Safe Browsing, VirusTotal's URL scanner) — these can only flag a URL after someone has already reported it and a reviewer has confirmed it. They are inherently reactive and blind to newly registered phishing infrastructure.
2. **Single-verdict aggregators** — these report whether *any* engine flagged a URL, without explaining *why*, and without any independent judgment of their own.

PhishGuard takes a third approach: it evaluates the **structural and linguistic characteristics** of a URL or email directly — the same signals a trained human analyst would look for — and produces an explainable, multi-dimensional composite score. This makes detection proactive (it does not require the threat to have been seen before) and explainable (every score comes with the specific reasons behind it).

---

## 2. URL Detection Engine — 6 Dimensions

### 2.1 Brand Impersonation (weight: 28%)

The single highest-weighted dimension, because brand impersonation is the most direct and interpretable phishing signal available from a URL alone.

Three detection strategies run in combination:

- **Direct match** — the brand name appears literally in the domain (e.g. `paypal-security.xyz`)
- **Homoglyph-normalized match** — before comparison, the domain is normalized by mapping visually similar characters to their canonical letter (`0→o`, `1→l`, `3→e`, `4→a`, `5→s`, `6→b`, `7→t`, `9→g`, `@→a`, `$→s`, `|→l`). This catches attacks like `paypa1.com` or `micr0soft.com`, which would otherwise evade simple string matching entirely.
- **Typosquat match** — Levenshtein edit distance of exactly 1 against a tracked brand name (for brands longer than 4 characters, to avoid false positives on short strings)

**Design note (v1.1):** An earlier version of this dimension also included a standalone homoglyph-substitution check that fired independently of any actual brand match — for example, flagging any domain containing the letter "l" without the letter "i," regardless of whether a real brand was being impersonated. This was identified as a false-positive source during validation testing (see Section 5) and removed. Genuine homoglyph attacks are now detected exclusively through the brand-normalization comparison described above, which only fires on an actual match against the tracked brand list.

### 2.2 TLD Risk (weight: 20%)

Top-level domains are scored based on documented phishing abuse rates (ICANN abuse statistics, Spamhaus TLD reputation data). Established, regulated TLDs (`.gov`, `.edu`, `.com`, `.org`) score 0. Historically high-abuse TLDs (`.tk`, `.xyz`, `.loan`, `.cyou`, `.sbs`, etc.) score between 60–95 depending on documented abuse frequency. Unknown/unlisted TLDs default to a moderate risk score of 20.

### 2.3 Redirect Risk (weight: 19%)

URL shorteners (`bit.ly`, `tinyurl.com`, `qrco.de`, and 20+ others) score 80, since they inherently hide the true destination from the user regardless of what that destination turns out to be. Additional points are added for explicit redirect parameters (`?redirect=`, `?goto=`) and for multiple embedded URLs suggesting a redirect chain.

### 2.4 Lexical Analysis (weight: 18%)

Structural red flags in the URL string itself: use of a raw IP address instead of a domain name, excessive hyphenation, `@` symbols (a classic redirect-obfuscation trick), unusually long URLs, double slashes in the path, purely numeric domains, and percent-encoded characters used for evasion.

### 2.5 Structural Anomalies (weight: 10%)

Pattern matching against a library of known malicious URL constructions, including dangerous URI schemes (`data:`, `javascript:`), excessive query parameters, and links to executable file types.

### 2.6 Domain Entropy (weight: 5%)

Shannon entropy of the second-level domain, combined with a consonant-to-vowel ratio check, to flag algorithmically generated domain names (a signature of domain-generation-algorithm-based phishing infrastructure). This dimension is intentionally weighted low, since high entropy alone is a weak standalone signal — many legitimate short-lived campaign or marketing domains also exhibit moderate entropy.

### Composite Scoring

PhishScore = (Headers × 0.20) + (Sender × 0.25) + (Urgency × 0.20)
+ (Links × 0.15) + (Impersonation × 0.10)
+ (Attachments × 0.05) + (Anomalies × 0.05)

+ 
Same verdict thresholds as the URL engine.

---

## 4. The AI Explanation Layer

PhishGuard v1.1 adds an optional layer (`src/ai-explain.js`) that translates an *already-computed* detection result into a 2–3 sentence plain-English summary for non-technical users — for example, a church administrator or small business owner with no security background.

This layer is architecturally downstream of and strictly separate from detection:

- It receives only the final score, verdict, confidence level, and top contributing signals — never the raw URL or email content
- It cannot alter, override, or re-run the detection verdict
- If unavailable or unconfigured, every detection endpoint still returns the complete, correct rule-based result with no degradation

This separation is deliberate: PhishGuard's detection claim rests entirely on original, inspectable, reproducible rule-based logic. The AI layer's only function is accessibility — making a technical result understandable to someone without a security background — not detection itself. The layer is provider-agnostic and currently supports Google Gemini, Groq, or Anthropic, configurable via a single environment variable.

---

## 5. Independent Validation Study

To measure real-world detection performance rather than relying on hand-picked examples, PhishGuard's URL engine was tested against live, independently-verified phishing data from [PhishTank](https://phishtank.org) — a community-driven database in which every URL has already been confirmed as phishing by reviewers with no affiliation to this project.

**Methodology:** A random sample of 100 URLs was drawn without replacement from PhishTank's live feed. The raw sample was saved to disk *before* scoring, so results could not be selected or altered after the fact. PhishGuard's unmodified detection engine was run against the sample via `scripts/phishtank-validation.js`, a script publicly available in this repository and reproducible by any reviewer.

**Result (2026-09-09):** 7.0% detection rate (score ≥ 40, SUSPICIOUS or higher).

**What this revealed, reported honestly:** Analysis of the sample showed that 36% of confirmed phishing URLs used ordinary `.com` domains, with the remainder spread across mainstream, low-suspicion TLDs (`.shop`, `.app`, `.dev`, `.pro`, `.io`) rather than the exotic, disposable TLDs typically associated with phishing infrastructure. Fifty-one percent of sampled URLs produced a PhishScore below 10, indicating little to no structural signal was present for the engine to act on.

This is consistent with a well-documented trend in the anti-phishing research literature: as automated structural filters have become more common, phishing operators have increasingly shifted toward clean, low-suspicion domains — including compromised legitimate sites and newly registered mainstream-TLD domains — specifically to evade structural detection. This is a genuine and known limitation of lexical/structural URL analysis performed in isolation, without complementary signal sources such as domain registration age, hosting reputation, or destination page content inspection.

During this validation process, two real detection bugs were also identified and fixed:

1. **A flawed homoglyph check** (described in Section 2.1) that produced false positives unrelated to any actual brand impersonation, inflating scores on the basis of coincidental character patterns rather than genuine phishing indicators.
2. **A stale TLD risk list** missing several TLDs that have become common in current phishing campaigns (`.cyou`, `.sbs`, `.buzz`, `.cfd`, `.icu`, and others), which were added following this finding.

Full results, including the complete raw dataset and detailed per-URL scoring output, are available in `docs/validation-study-2026-09-09.md` and the accompanying JSON files.

**Why this result is reported as-is rather than tuned further:** Continuing to adjust detection weights specifically to improve performance against this one known sample would risk overfitting to the test data — producing a number that looks better without reflecting genuine improvement in general detection capability. The honest, reproducible number, together with a clear explanation of its cause, is a more credible and useful piece of evidence than an inflated one.

---

## 6. Future Development

Addressing the limitation identified in Section 5 — clean-domain phishing that evades structural analysis — is a planned area of future development, potentially incorporating domain registration age, hosting reputation signals, or destination content verification as complementary detection layers alongside the existing structural engine.

---

## 7. Reproducibility

Every claim in this document is independently verifiable:

- Source code: `src/engines/url-engine.js`, `src/engines/email-engine.js`, `src/threat-data.js`
- Validation script: `scripts/phishtank-validation.js` (run via `npm run validate`)
- Validation results: `docs/validation-study-2026-09-09.md` and accompanying raw dataset JSON

No proprietary or closed-source component is used in any part of the detection pipeline.
