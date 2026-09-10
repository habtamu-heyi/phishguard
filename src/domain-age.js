/**
 * PhishGuard — Domain Age Enrichment Layer v1.0
 * Author: Habtamu Heyi
 *
 * WHY THIS EXISTS:
 * PhishGuard's validation study against a live PhishTank sample (see
 * docs/validation-study-*.md) identified a genuine limitation: 36% of
 * confirmed phishing URLs in the tested sample used ordinary .com
 * domains with no structural red flags for the core 6-dimension engine
 * to detect. This is a well-documented pattern in anti-phishing
 * research — domain registration age is one of the most predictive
 * single signals for phishing, because the overwhelming majority of
 * phishing domains are used within days or weeks of registration,
 * regardless of which TLD or structural pattern they use.
 *
 * DESIGN NOTE — WHY THIS IS SEPARATE FROM THE CORE ENGINE:
 * This module is intentionally NOT merged into url-engine.js's existing
 * 6-dimension scoreLexical/scoreDomainEntropy/etc. functions or their
 * weights. Those weights were fixed before this validation study and
 * are left untouched, so there is no appearance of having re-tuned the
 * core engine specifically to pass a known test sample. Domain age is
 * a genuinely new, independent data source (registration data, not URL
 * structure) blended in afterward via a separate, clearly-labeled step
 * — see blendDomainAgeScore() below.
 *
 * DATA SOURCE: RDAP (Registration Data Access Protocol), the modern,
 * standardized, free replacement for WHOIS (RFC 7482/7483). No API key
 * required. Not every registry/TLD supports RDAP equally well; lookups
 * that fail or time out degrade gracefully — the base 6-dimension score
 * is used unmodified rather than penalizing or rewarding an unknown age.
 */

const https = require('https');

const RDAP_TIMEOUT_MS = 5000;
const RDAP_BOOTSTRAP_URL = 'https://rdap.org/domain/';

/**
 * Fetch RDAP registration data for a domain.
 * Returns { registrationDate: Date, ageInDays: number } or null on any failure.
 */
/**
 * Fetch RDAP registration data for a domain.
 * Returns { registrationDate: Date, ageInDays: number } or null on any failure.
 *
 * IMPORTANT: rdap.org operates as a bootstrap/router service — it responds
 * to a query with an HTTP redirect (301/302) pointing to the actual
 * registry-specific RDAP server that holds the real data. This is the
 * standard, expected behavior of RDAP bootstrapping (RFC 7484), not an
 * error condition. This function follows redirects (up to MAX_REDIRECTS)
 * before giving up.
 */
const MAX_REDIRECTS = 5;

function fetchRDAP(domain, redirectCount = 0) {
  return new Promise((resolve) => {
    if (redirectCount > MAX_REDIRECTS) return resolve(null);

    const url = redirectCount === 0 ? RDAP_BOOTSTRAP_URL + domain : domain; // on redirect, `domain` param holds the full next URL

    const req = https.get(url, { timeout: RDAP_TIMEOUT_MS }, (res) => {
      // Follow redirects — this is the normal, expected RDAP bootstrap flow
      if ([301, 302, 303, 307, 308].includes(res.statusCode)) {
        res.resume();
        const location = res.headers.location;
        if (!location) return resolve(null);
        return fetchRDAP(location, redirectCount + 1).then(resolve);
      }

      if (res.statusCode !== 200) { res.resume(); return resolve(null); }

      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          const events = json.events || [];
          // Different registries use slightly different eventAction labels
          const regEvent = events.find(e =>
            /registration/i.test(e.eventAction) || /^registered$/i.test(e.eventAction)
          );
          if (!regEvent || !regEvent.eventDate) return resolve(null);

          const registrationDate = new Date(regEvent.eventDate);
          if (isNaN(registrationDate.getTime())) return resolve(null);

          const ageInDays = Math.floor((Date.now() - registrationDate.getTime()) / (1000 * 60 * 60 * 24));
          resolve({ registrationDate, ageInDays });
        } catch {
          resolve(null);
        }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
  });
}
/**
 * Score domain age risk based on registration recency.
 * Weighting reflects the well-documented pattern that the large majority
 * of phishing domains are used within days to weeks of registration.
 */
function scoreDomainAge(ageInDays) {
  if (ageInDays < 7)   return { score: 90, signal: `Domain registered ${ageInDays} day(s) ago — extremely recent registration` };
  if (ageInDays < 30)  return { score: 70, signal: `Domain registered ${ageInDays} days ago — very recent registration` };
  if (ageInDays < 90)  return { score: 45, signal: `Domain registered ${ageInDays} days ago — relatively new` };
  if (ageInDays < 365) return { score: 20, signal: `Domain registered ${ageInDays} days ago — under one year old` };
  return { score: 0, signal: null };
}

/**
 * Look up domain age and return a scoring result, or null if unavailable.
 *
 * @param {string} domain - bare hostname (e.g. "example.com")
 * @returns {Promise<Object|null>} { score, signal, ageInDays, registrationDate } or null
 */
async function checkDomainAge(domain) {
  const rdap = await fetchRDAP(domain);
  if (!rdap) return null; // Lookup failed/unsupported — caller should treat as unavailable, not risky
  const { score, signal } = scoreDomainAge(rdap.ageInDays);
  return { score, signal, ageInDays: rdap.ageInDays, registrationDate: rdap.registrationDate.toISOString() };
}

/**
 * Blend a domain-age result into an already-computed PhishGuard result.
 *
 * This does NOT touch the original 6-dimension composite score or its
 * weights. It computes a new blended score as:
 *   finalScore = originalScore * (1 - AGE_WEIGHT) + ageScore * AGE_WEIGHT
 * only when domain age data is available. If the RDAP lookup fails,
 * the original result is returned completely unmodified.
 *
 * @param {Object} result - output of analyzeURL() from url-engine.js
 * @returns {Promise<Object>} result, possibly enriched with domain age data
 */
const AGE_WEIGHT = 0.25; // Moderate weight — see docs/METHODOLOGY.md for rationale

async function enrichWithDomainAge(result) {
  if (result.error || !result.domain) return result;

  const ageResult = await checkDomainAge(result.domain);
  if (!ageResult) {
    return { ...result, domain_age: { available: false } };
  }

  const originalScore = result.phish_score;
  const blendedScore = Math.round(originalScore * (1 - AGE_WEIGHT) + ageResult.score * AGE_WEIGHT);

  const signals = [...result.signals];
  if (ageResult.signal) signals.push(ageResult.signal);

  // Recompute verdict from blended score using the same thresholds as url-engine.js
  let verdict, riskLevel, recommendation;
  if (blendedScore >= 65) {
    verdict = 'PHISHING'; riskLevel = 'critical';
    recommendation = 'Block immediately. Do not visit this URL. Report to your security team.';
  } else if (blendedScore >= 40) {
    verdict = 'SUSPICIOUS'; riskLevel = 'high';
    recommendation = 'Treat with extreme caution. Verify through official channels before proceeding.';
  } else if (blendedScore >= 20) {
    verdict = 'UNCERTAIN'; riskLevel = 'medium';
    recommendation = 'Proceed with caution. Verify the sender and destination before clicking.';
  } else {
    verdict = 'LIKELY SAFE'; riskLevel = 'low';
    recommendation = 'No significant phishing indicators detected. Standard caution applies.';
  }

  return {
    ...result,
    phish_score: blendedScore,
    verdict,
    risk_level: riskLevel,
    recommendation,
    signals,
    structural_score: originalScore, // preserved for transparency — the original 6-dimension score
    domain_age: {
      available: true,
      age_in_days: ageResult.ageInDays,
      registration_date: ageResult.registrationDate,
      age_risk_score: ageResult.score
    }
  };
}

module.exports = { checkDomainAge, enrichWithDomainAge, AGE_WEIGHT };