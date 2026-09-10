/**
 * PhishGuard — URL Analysis Engine v1.0
 * Author: Habtamu Wario
 *
 * Original multi-factor URL phishing detection algorithm.
 * Analyzes URLs across 8 independent dimensions to produce
 * a composite PhishScore (0-100).
 *
 * Detection dimensions:
 *   1. Lexical Analysis      — structural deception patterns
 *   2. Domain Entropy        — randomness indicating generated domains
 *   3. Brand Impersonation   — lookalike brand detection
 *   4. TLD Risk              — top-level domain reputation
 *   5. Structural Anomalies  — URL construction red flags
 *   6. Redirect Risk         — URL shorteners and redirect chains
 *   7. Pattern Matching      — known malicious patterns
 *   8. Homoglyph Detection   — character substitution attacks
 */

const {
  IMPERSONATED_BRANDS,
  HIGH_RISK_TLDS,
  LOW_RISK_TLDS,
  SUSPICIOUS_URL_PATTERNS,
  LEGITIMATE_DOMAINS
} = require('../threat-data');

// ── Utility Functions ─────────────────────────────────────────────────────────

/**
 * Shannon entropy — measures randomness of a string
 * High entropy (>4.0) indicates algorithmically generated domains
 */
function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / str.length;
    return sum + p * Math.log2(p);
  }, 0);
}

/**
 * Extract domain parts from a URL
 */
function parseDomain(url) {
  try {
    // Add protocol if missing
    const withProto = url.startsWith('http') ? url : 'http://' + url;
    const parsed = new URL(withProto);
    const hostname = parsed.hostname.toLowerCase();
    const parts = hostname.split('.');
    const tld = parts.length >= 2 ? '.' + parts.slice(-1)[0] : '';
    const secondLevelDomain = parts.length >= 2 ? parts[parts.length - 2] : hostname;
    const subdomains = parts.length > 2 ? parts.slice(0, -2) : [];
    return { hostname, tld, secondLevelDomain, subdomains, pathname: parsed.pathname, fullUrl: withProto, parsed };
  } catch {
    return null;
  }
}

/**
 * REMOVED (post-validation-study fix, see docs/validation-study-*.md):
 * detectHomoglyphs() previously flagged any domain containing character
 * X but not character Y for arbitrary homoglyph pairs, regardless of
 * whether any known brand was being impersonated — this produced
 * widespread false positives (e.g. any domain with "l" but no "i").
 * Genuine homoglyph brand attacks are correctly detected inside
 * detectBrandImpersonation() below via normalizeHomoglyphs(), which
 * only fires on an actual match against IMPERSONATED_BRANDS.
 */

/**
 * Check for brand impersonation including typosquatting
 * Uses Levenshtein distance for fuzzy matching
 */
function levenshtein(a, b) {
  const matrix = Array.from({ length: b.length + 1 }, (_, i) => [i]);
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      matrix[i][j] = b[i-1] === a[j-1]
        ? matrix[i-1][j-1]
        : Math.min(matrix[i-1][j-1] + 1, matrix[i][j-1] + 1, matrix[i-1][j] + 1);
    }
  }
  return matrix[b.length][a.length];
}

// Normalize homoglyphs for brand matching
// e.g. "paypa1" → "paypal", "micr0soft" → "microsoft"
function normalizeHomoglyphs(str) {
  const map = { '0':'o','1':'l','3':'e','4':'a','5':'s','6':'b','7':'t','9':'g','@':'a','$':'s','|':'l' };
  return str.toLowerCase().split('').map(c => map[c] || c).join('');
}

function detectBrandImpersonation(domain, fullUrl) {
  const lower = domain.toLowerCase();
  const normalized = normalizeHomoglyphs(domain); // homoglyph-normalized version
  const urlLower = fullUrl.toLowerCase();
  const findings = [];

  for (const brand of IMPERSONATED_BRANDS) {
    // Exact brand in raw domain
    if (lower.includes(brand) && !lower.endsWith(brand + '.com') && !lower.endsWith(brand + '.org')) {
      findings.push({ brand, type: 'contains', confidence: 85 });
      continue;
    }
    // Homoglyph substitution — normalized domain contains brand (e.g. paypa1 → paypal)
    if (normalized.includes(brand) && !lower.includes(brand)) {
      findings.push({ brand, type: 'homoglyph', confidence: 95 });
      continue;
    }
    // Typosquatting — Levenshtein distance 1
    const distance = levenshtein(lower.replace(/[\.\-]/g, ''), brand);
    if (distance === 1 && brand.length > 4) {
      findings.push({ brand, type: 'typosquat', confidence: 90 });
      continue;
    }
    // Brand in path but not domain (credential harvesting)
    if (!lower.includes(brand) && !normalized.includes(brand) && urlLower.includes('/' + brand)) {
      findings.push({ brand, type: 'path_only', confidence: 75 });
    }
  }
  return findings;
}

// ── Dimension Scorers ─────────────────────────────────────────────────────────

/**
 * D1: Lexical Analysis
 * Analyzes structural properties of the URL for deceptive patterns
 */
function scoreLexical(domainInfo, fullUrl) {
  let score = 0;
  const signals = [];

  // Raw IP address instead of domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domainInfo.hostname)) {
    score += 40; signals.push('Raw IP address used instead of domain name');
  }

  // Excessive subdomains (legitimate sites rarely have 3+)
  if (domainInfo.subdomains.length >= 4) {
    score += 30; signals.push(`Excessive subdomain depth (${domainInfo.subdomains.length} levels)`);
  } else if (domainInfo.subdomains.length >= 3) {
    score += 15; signals.push('Deep subdomain structure');
  }

  // Hyphen abuse in domain
  const hyphenCount = (domainInfo.secondLevelDomain.match(/-/g) || []).length;
  if (hyphenCount >= 4) { score += 25; signals.push('Excessive hyphens in domain'); }
  else if (hyphenCount >= 2) { score += 10; signals.push('Multiple hyphens in domain'); }

  // URL length (phishing URLs tend to be long to obscure domain)
  if (fullUrl.length > 150) { score += 20; signals.push('Extremely long URL (obfuscation)'); }
  else if (fullUrl.length > 75) { score += 8; signals.push('Unusually long URL'); }

  // @ symbol in URL (redirects to different domain)
  if (fullUrl.includes('@')) { score += 35; signals.push('@ symbol in URL — potential redirect attack'); }

  // Double slash in path (confusion attack)
  if (domainInfo.pathname && domainInfo.pathname.includes('//')) {
    score += 15; signals.push('Double slash in URL path');
  }

  // Numeric domain (all numbers)
  if (/^\d+$/.test(domainInfo.secondLevelDomain)) {
    score += 30; signals.push('Purely numeric domain name');
  }

  // Percent encoding in domain (evasion)
  if (/%[0-9a-f]{2}/i.test(domainInfo.hostname)) {
    score += 25; signals.push('Percent-encoded characters in domain');
  }

  return { score: Math.min(100, score), signals };
}

/**
 * D2: Domain Entropy
 * High Shannon entropy indicates algorithmically generated domains (DGA)
 */
function scoreDomainEntropy(domainInfo) {
  const entropy = shannonEntropy(domainInfo.secondLevelDomain);
  const signals = [];
  let score = 0;

  if (entropy > 4.5) {
    score = 85; signals.push(`Very high domain entropy (${entropy.toFixed(2)}) — likely DGA`);
  } else if (entropy > 3.8) {
    score = 60; signals.push(`High domain entropy (${entropy.toFixed(2)}) — possible DGA`);
  } else if (entropy > 3.2) {
    score = 35; signals.push(`Elevated domain entropy (${entropy.toFixed(2)})`);
  } else {
    score = 5;
  }

  // Also check consonant/vowel ratio (DGA domains often have unusual ratios)
  const domain = domainInfo.secondLevelDomain;
  const vowels = (domain.match(/[aeiou]/gi) || []).length;
  const consonants = (domain.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
  const ratio = consonants / (vowels + 1);
  if (ratio > 5) {
    score += 20; signals.push('Unusual consonant/vowel ratio — possible generated domain');
  }

  return { score: Math.min(100, score), signals, entropy: entropy.toFixed(2) };
}

/**
 * D3: Brand Impersonation
 * Detects attempts to impersonate legitimate brands
 *
 * NOTE (fixed after validation study, see docs/validation-study-*.md):
 * An earlier version of this function also scored a standalone
 * detectHomoglyphs() character-substitution check independent of any
 * actual brand match. That check fired on ordinary domains containing
 * common letter/number combinations with no relationship to brand
 * impersonation (e.g. any domain containing "l" without "i"), producing
 * false-positive brand_impersonation scores. Genuine homoglyph attacks
 * (e.g. "paypa1.com" for "paypal.com") are already correctly detected
 * inside detectBrandImpersonation() via normalizeHomoglyphs(), which
 * only fires when the normalized domain matches a known brand. The
 * standalone, brand-independent check has been removed.
 */
function scoreBrandImpersonation(domainInfo, fullUrl) {
  const findings = detectBrandImpersonation(domainInfo.hostname, fullUrl);
  const signals = [];
  let score = 0;

  for (const f of findings) {
    score = Math.max(score, f.confidence);
    if (f.type === 'typosquat') signals.push(`Typosquatting detected — impersonating "${f.brand}"`);
    else if (f.type === 'contains') signals.push(`Brand name "${f.brand}" embedded in suspicious domain`);
    else if (f.type === 'homoglyph') signals.push(`Homoglyph substitution detected — impersonating "${f.brand}"`);
    else if (f.type === 'path_only') signals.push(`Brand "${f.brand}" in URL path — credential harvesting likely`);
  }

  // Check if it's a legitimate domain we know about
  const isKnownLegit = LEGITIMATE_DOMAINS.some(d => domainInfo.hostname === d || domainInfo.hostname.endsWith('.' + d));
  if (isKnownLegit) score = 0;

  return { score: Math.min(100, score), signals, findings, homoglyphCount: findings.filter(f => f.type === 'homoglyph').length };
}

/**
 * D4: TLD Risk Scoring
 * Top-level domain reputation based on abuse statistics
 */
function scoreTLD(domainInfo) {
  const tld = domainInfo.tld.toLowerCase();
  const signals = [];
  let score = 0;

  if (HIGH_RISK_TLDS[tld]) {
    score = HIGH_RISK_TLDS[tld];
    signals.push(`High-risk TLD "${tld}" — frequently abused in phishing campaigns`);
  } else if (LOW_RISK_TLDS.includes(tld)) {
    score = 0;
  } else {
    score = 20; // Unknown TLD — moderate risk
  }

  // Numeric TLD
  if (/\.\d+$/.test(domainInfo.hostname)) {
    score += 40; signals.push('Numeric TLD — likely malicious');
  }

  return { score: Math.min(100, score), signals };
}

/**
 * D5: Structural Anomalies
 * Pattern matching against known malicious URL structures
 */
function scoreStructuralAnomalies(fullUrl) {
  const signals = [];
  let score = 0;

  for (const pattern of SUSPICIOUS_URL_PATTERNS) {
    if (pattern.test(fullUrl)) {
      // Determine severity of each pattern
      if (pattern.toString().includes('data:') || pattern.toString().includes('javascript:')) {
        score += 50; signals.push('Dangerous URI scheme detected');
      } else if (pattern.toString().includes('@')) {
        score += 35; signals.push('Redirect trick via @ symbol');
      } else if (pattern.toString().includes('bit.ly') || pattern.toString().includes('tinyurl')) {
        score += 30; signals.push('URL shortener detected — hides true destination');
      } else if (pattern.toString().includes('exe|zip')) {
        score += 40; signals.push('Direct link to potentially dangerous file type');
      } else if (pattern.toString().includes('%[0-9a-f]')) {
        score += 20; signals.push('URL encoding used — possible evasion attempt');
      } else {
        score += 15; signals.push('Suspicious URL pattern detected');
      }
    }
  }

  // Multiple query parameters (common in phishing redirects)
  const queryParams = (fullUrl.match(/[?&]/g) || []).length;
  if (queryParams > 8) { score += 20; signals.push('Excessive URL parameters'); }

  return { score: Math.min(100, score), signals };
}

/**
 * D6: Redirect Risk
 * URL shorteners and redirect chains hide true destinations
 */
function scoreRedirectRisk(fullUrl) {
  const shorteners = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'cli.gs', 'pic.gd', 'turl.ch', 'tiny.cc', 'rb.gy', 'cutt.ly',
    'shorturl.at', 'tiny.one', 'bl.ink', 'rebrand.ly',
    'qrco.de', 'qr.codes', 'lnk.bio', 'linktr.ee', 'v.gd', 'shorte.st',
    's.id', 'clck.ru', 'shrtco.de'
  ];
  const signals = [];
  let score = 0;

  for (const shortener of shorteners) {
    if (fullUrl.includes(shortener)) {
      score = 80;
      signals.push(`URL shortener "${shortener}" detected — true destination hidden`);
      break;
    }
  }

  // Redirect keywords in URL
  if (/redirect|goto|return|redir|forward/i.test(fullUrl)) {
    score += 25; signals.push('Redirect parameter in URL');
  }

  // Multiple URLs embedded (redirect chain)
  const urlCount = (fullUrl.match(/https?:\/\//gi) || []).length;
  if (urlCount > 1) {
    score += 35; signals.push(`Multiple URLs embedded — redirect chain (${urlCount} URLs)`);
  }

  return { score: Math.min(100, score), signals };
}

// ── Main URL Scoring Function ─────────────────────────────────────────────────

/**
 * Compute composite PhishScore for a URL
 *
 * @param {string} url - URL to analyze
 * @returns {Object} Detailed PhishScore with dimension breakdown
 */
function analyzeURL(url) {
  const startTime = Date.now();

  if (!url || typeof url !== 'string') {
    return { error: 'Invalid URL provided' };
  }

  const domainInfo = parseDomain(url.trim());
  if (!domainInfo) {
    return { error: 'Could not parse URL — check format' };
  }

  // Run all detection dimensions
  const d1 = scoreLexical(domainInfo, url);
  const d2 = scoreDomainEntropy(domainInfo);
  const d3 = scoreBrandImpersonation(domainInfo, url);
  const d4 = scoreTLD(domainInfo);
  const d5 = scoreStructuralAnomalies(url);
  const d6 = scoreRedirectRisk(url);

  // Weighted composite score
  const weights = {
    lexical:    0.18,
    entropy:    0.05,
    brand:      0.28,
    tld:        0.20,
    structural: 0.10,
    redirect:   0.19
  };

  const rawScore =
    d1.score * weights.lexical +
    d2.score * weights.entropy +
    d3.score * weights.brand +
    d4.score * weights.tld +
    d5.score * weights.structural +
    d6.score * weights.redirect;

  const phishScore = Math.round(Math.min(100, rawScore));

  // Verdict thresholds — calibrated against known phishing samples
  let verdict, riskLevel, recommendation;
  if (phishScore >= 65) {
    verdict = 'PHISHING';
    riskLevel = 'critical';
    recommendation = 'Block immediately. Do not visit this URL. Report to your security team.';
  } else if (phishScore >= 40) {
    verdict = 'SUSPICIOUS';
    riskLevel = 'high';
    recommendation = 'Treat with extreme caution. Verify through official channels before proceeding.';
  } else if (phishScore >= 20) {
    verdict = 'UNCERTAIN';
    riskLevel = 'medium';
    recommendation = 'Proceed with caution. Verify the sender and destination before clicking.';
  } else {
    verdict = 'LIKELY SAFE';
    riskLevel = 'low';
    recommendation = 'No significant phishing indicators detected. Standard caution applies.';
  }

  // Collect all signals
  const allSignals = [
    ...d1.signals, ...d2.signals, ...d3.signals,
    ...d4.signals, ...d5.signals, ...d6.signals
  ];

  return {
    url: url.trim(),
    domain: domainInfo.hostname,
    phish_score: phishScore,
    verdict,
    risk_level: riskLevel,
    recommendation,
    confidence: allSignals.length > 3 ? 'high' : allSignals.length > 1 ? 'medium' : 'low',
    signals: allSignals,
    dimensions: {
      lexical_analysis:      Math.round(d1.score),
      domain_entropy:        Math.round(d2.score),
      brand_impersonation:   Math.round(d3.score),
      tld_risk:              Math.round(d4.score),
      structural_anomalies:  Math.round(d5.score),
      redirect_risk:         Math.round(d6.score)
    },
    metadata: {
      entropy:          d2.entropy,
      tld:              domainInfo.tld,
      subdomain_depth:  domainInfo.subdomains.length,
      brand_findings:   d3.findings,
      homoglyphs:       d3.homoglyphCount,
      url_length:       url.length,
      analyzed_at:      new Date().toISOString(),
      analysis_ms:      Date.now() - startTime
    }
  };
}

module.exports = { analyzeURL, parseDomain, shannonEntropy };