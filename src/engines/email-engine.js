/**
 * PhishGuard — Email Analysis Engine v1.0
 * Author: Habtamu Wario
 *
 * Original multi-factor email phishing detection algorithm.
 * Analyzes email headers, body content, and metadata to produce
 * a composite PhishScore (0-100).
 *
 * Detection dimensions:
 *   1. Header Forensics       — routing anomalies and authentication failures
 *   2. Sender Spoofing        — display name vs actual address mismatch
 *   3. Urgency Classification — NLP-based pressure tactic detection
 *   4. Link Analysis          — suspicious URLs extracted from body
 *   5. Brand Impersonation    — claimed identity vs actual sender
 *   6. Attachment Risk        — dangerous file type detection
 *   7. Content Anomalies      — structural red flags in email body
 */

const { URGENCY_KEYWORDS, IMPERSONATED_BRANDS, DANGEROUS_EXTENSIONS } = require('../threat-data');
const { analyzeURL } = require('./url-engine');

// ── Header Analysis ───────────────────────────────────────────────────────────

/**
 * D1: Header Forensics
 * Analyzes email routing headers for authentication failures and anomalies
 * Expects raw email headers as a string
 */
function analyzeHeaders(headers) {
  const signals = [];
  let score = 0;

  if (!headers || typeof headers !== 'string') {
    return { score: 0, signals: ['No headers provided — header analysis skipped'] };
  }

  const h = headers.toLowerCase();

  // SPF check
  if (h.includes('spf=fail') || h.includes('spf=hardfail')) {
    score += 35; signals.push('SPF authentication FAILED — sender domain mismatch');
  } else if (h.includes('spf=softfail')) {
    score += 20; signals.push('SPF softfail — sender not fully authorized');
  } else if (h.includes('spf=none')) {
    score += 10; signals.push('No SPF record — sender domain unverified');
  }

  // DKIM check
  if (h.includes('dkim=fail')) {
    score += 30; signals.push('DKIM signature FAILED — email may be tampered');
  } else if (h.includes('dkim=none') || !h.includes('dkim=')) {
    score += 10; signals.push('No DKIM signature — authenticity unverified');
  }

  // DMARC check
  if (h.includes('dmarc=fail')) {
    score += 35; signals.push('DMARC policy FAILED — likely spoofed sender');
  } else if (h.includes('dmarc=none') || !h.includes('dmarc=')) {
    score += 10; signals.push('No DMARC policy — domain spoofing risk');
  }

  // Reply-To mismatch (common phishing pattern)
  const fromMatch = headers.match(/^From:.*?<([^>]+)>/im);
  const replyToMatch = headers.match(/^Reply-To:.*?<([^>]+)>/im);
  if (fromMatch && replyToMatch) {
    const fromDomain = fromMatch[1].split('@')[1]?.toLowerCase();
    const replyDomain = replyToMatch[1].split('@')[1]?.toLowerCase();
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      score += 40; signals.push(`Reply-To domain (${replyDomain}) differs from From domain (${fromDomain})`);
    }
  }

  // Received header anomalies — many hops suggest relay abuse
  const receivedCount = (headers.match(/^Received:/gim) || []).length;
  if (receivedCount > 8) {
    score += 20; signals.push(`Excessive routing hops (${receivedCount}) — possible relay abuse`);
  }

  // X-Mailer or User-Agent anomalies
  if (h.includes('x-mailer: microsoft outlook') && h.includes('spf=fail')) {
    score += 15; signals.push('Outlook claimed as mailer but SPF failed — spoofed client');
  }

  // Suspicious originating IP in headers
  if (/x-originating-ip:.*\b(185|91|45|194)\.\d+\.\d+\.\d+/.test(h)) {
    score += 15; signals.push('Originating IP in high-abuse range');
  }

  return { score: Math.min(100, score), signals };
}

/**
 * D2: Sender Spoofing Detection
 * Analyzes From address, display name, and envelope sender for deception
 */
function analyzeSender(fromAddress, displayName, replyTo) {
  const signals = [];
  let score = 0;

  if (!fromAddress) return { score: 0, signals: ['No sender address provided'] };

  const from = fromAddress.toLowerCase().trim();
  const display = (displayName || '').toLowerCase().trim();

  // Extract domain from email
  const emailDomain = from.split('@')[1] || '';

  // Display name contains brand but email domain doesn't match
  for (const brand of IMPERSONATED_BRANDS) {
    if (display.includes(brand) && !emailDomain.includes(brand)) {
      score += 50;
      signals.push(`Display name claims to be "${brand}" but sender domain is "${emailDomain}"`);
      break;
    }
  }

  // Free email service used for "official" communication
  const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'protonmail.com'];
  if (freeProviders.some(p => emailDomain.endsWith(p))) {
    if (display.includes('support') || display.includes('security') || display.includes('noreply') || display.includes('admin')) {
      score += 45;
      signals.push(`"${display}" using free email provider — likely spoofed`);
    } else {
      score += 10;
      signals.push('Free email provider used — consider context');
    }
  }

  // Suspicious email patterns
  if (/no.?reply.*@/i.test(from) && freeProviders.some(p => emailDomain.endsWith(p))) {
    score += 30; signals.push('Fake no-reply address using free email provider');
  }

  // Email address with excessive numbers (generated addresses)
  const numbers = (from.match(/\d/g) || []).length;
  if (numbers > 6) {
    score += 20; signals.push('Excessive numbers in email address — possibly generated');
  }

  // Reply-to differs from from
  if (replyTo && replyTo.toLowerCase() !== from) {
    const replyDomain = replyTo.split('@')[1]?.toLowerCase();
    if (replyDomain && replyDomain !== emailDomain) {
      score += 35; signals.push(`Reply-To (${replyDomain}) differs from sender (${emailDomain})`);
    }
  }

  // Very long local part (obfuscation)
  const localPart = from.split('@')[0] || '';
  if (localPart.length > 30) {
    score += 15; signals.push('Unusually long email local part');
  }

  return { score: Math.min(100, score), signals, emailDomain };
}

/**
 * D3: Urgency Classification (NLP-based)
 * Scores email body for manipulation and pressure tactics
 */
function analyzeUrgency(body) {
  if (!body) return { score: 0, signals: [], urgencyTerms: [] };

  const lower = body.toLowerCase();
  const signals = [];
  const urgencyTerms = [];
  let totalWeight = 0;

  for (const [keyword, weight] of Object.entries(URGENCY_KEYWORDS)) {
    if (lower.includes(keyword.toLowerCase())) {
      totalWeight += weight;
      urgencyTerms.push({ term: keyword, weight });
    }
  }

  // Calculate score — diminishing returns after many keywords
  // (to prevent over-scoring legitimate security notifications)
  const score = Math.min(100, totalWeight * 4);

  if (urgencyTerms.length > 0) {
    const topTerms = urgencyTerms.sort((a, b) => b.weight - a.weight).slice(0, 3);
    signals.push(`Urgency/manipulation language detected: "${topTerms.map(t => t.term).join('", "')}"`);
  }

  if (urgencyTerms.length >= 5) {
    signals.push(`High manipulation density — ${urgencyTerms.length} pressure tactics identified`);
  }

  // Excessive capitalization (shouting)
  const capsRatio = (body.match(/[A-Z]/g) || []).length / body.length;
  if (capsRatio > 0.3 && body.length > 50) {
    signals.push('Excessive capitalization — psychological pressure tactic');
    return { score: Math.min(100, score + 15), signals, urgencyTerms };
  }

  return { score, signals, urgencyTerms };
}

/**
 * D4: Link Analysis
 * Extracts and analyzes all URLs from email body
 */
function analyzeLinks(body) {
  if (!body) return { score: 0, signals: [], links: [] };

  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  const urls = body.match(urlRegex) || [];
  const signals = [];
  const linkResults = [];
  let maxScore = 0;

  for (const url of urls.slice(0, 20)) { // Analyze up to 20 links
    const result = analyzeURL(url);
    if (!result.error) {
      linkResults.push({ url, score: result.phish_score, verdict: result.verdict });
      maxScore = Math.max(maxScore, result.phish_score);
      if (result.phish_score >= 50) {
        signals.push(`Suspicious link detected: ${url.slice(0, 60)}… (PhishScore: ${result.phish_score})`);
      }
    }
  }

  // Many links in email (link bombing)
  if (urls.length > 15) {
    signals.push(`Link bombing detected — ${urls.length} URLs in email body`);
    maxScore = Math.max(maxScore, 40);
  }

  // No unsubscribe link (legitimate bulk email always has one)
  if (body.toLowerCase().includes('dear') && !body.toLowerCase().includes('unsubscribe')) {
    signals.push('No unsubscribe link — violates CAN-SPAM, suspicious bulk email');
    maxScore = Math.max(maxScore, 25);
  }

  return { score: Math.min(100, maxScore), signals, links: linkResults, totalLinks: urls.length };
}

/**
 * D5: Brand Impersonation in Content
 * Detects when email claims to be from a brand the sender isn't
 */
function analyzeContentImpersonation(body, subject, senderDomain) {
  if (!body && !subject) return { score: 0, signals: [] };

  const content = ((body || '') + ' ' + (subject || '')).toLowerCase();
  const signals = [];
  let score = 0;

  for (const brand of IMPERSONATED_BRANDS) {
    if (content.includes(brand)) {
      // Brand mentioned in content but sender doesn't match
      if (!senderDomain?.includes(brand)) {
        score = Math.max(score, 60);
        signals.push(`Email claims to be from "${brand}" but sender domain doesn't match`);
      }
    }
  }

  // Generic credential harvesting phrases
  const harvestPhrases = [
    'enter your password', 'confirm your password', 'verify your identity',
    'update your billing', 'your account has been', 'click the link below'
  ];
  for (const phrase of harvestPhrases) {
    if (content.includes(phrase)) {
      score += 20;
      signals.push(`Credential harvesting phrase: "${phrase}"`);
      break;
    }
  }

  return { score: Math.min(100, score), signals };
}

/**
 * D6: Attachment Risk
 * Analyzes attachment filenames for dangerous file types
 */
function analyzeAttachments(attachments) {
  if (!attachments || !attachments.length) {
    return { score: 0, signals: [], attachments: [] };
  }

  const signals = [];
  let maxScore = 0;
  const results = [];

  for (const attachment of attachments) {
    const name = attachment.toLowerCase();
    let attachScore = 0;
    let reason = '';

    // Double extension (e.g., invoice.pdf.exe)
    if (/\.\w+\.\w+$/.test(name)) {
      attachScore = 85; reason = 'Double extension — classic malware delivery';
    }
    // Dangerous extension
    else if (DANGEROUS_EXTENSIONS.some(ext => name.endsWith(ext))) {
      if (name.endsWith('.exe') || name.endsWith('.bat') || name.endsWith('.vbs')) {
        attachScore = 95; reason = 'Executable file — extremely high risk';
      } else if (name.endsWith('.docm') || name.endsWith('.xlsm')) {
        attachScore = 75; reason = 'Macro-enabled Office document — malware risk';
      } else if (name.endsWith('.zip') || name.endsWith('.rar') || name.endsWith('.iso')) {
        attachScore = 55; reason = 'Compressed archive — may contain malware';
      } else {
        attachScore = 60; reason = 'Potentially dangerous file type';
      }
    }
    // Suspicious filename patterns
    else if (/invoice|payment|receipt|order|shipping|document/i.test(name)) {
      attachScore = 30; reason = 'Social engineering filename — verify before opening';
    }

    if (attachScore > 0) {
      maxScore = Math.max(maxScore, attachScore);
      results.push({ name: attachment, score: attachScore, reason });
      signals.push(`Attachment "${attachment}": ${reason}`);
    }
  }

  return { score: maxScore, signals, attachments: results };
}

/**
 * D7: Content Anomalies
 * Structural red flags in email body
 */
function analyzeContentAnomalies(body, subject) {
  if (!body) return { score: 0, signals: [] };

  const signals = [];
  let score = 0;
  const lower = body.toLowerCase();

  // Very short body with link (classic phishing)
  if (body.length < 200 && (body.match(/https?:\/\//gi) || []).length > 0) {
    score += 25; signals.push('Very short email body with link — classic phishing pattern');
  }

  // Generic greeting (not personalized)
  if (/dear (customer|user|account holder|valued member|sir|madam)/i.test(body)) {
    score += 20; signals.push('Generic impersonal greeting — mass phishing indicator');
  }

  // Grammatical anomalies (simplified check)
  const sentences = body.split(/[.!?]+/).filter(s => s.trim().length > 10);
  const shortSentences = sentences.filter(s => s.trim().split(' ').length < 4).length;
  if (shortSentences / (sentences.length + 1) > 0.5 && sentences.length > 3) {
    score += 15; signals.push('Unusual sentence structure — possible machine-translated content');
  }

  // HTML in plain text context
  if (/<[^>]+>/.test(body) && body.includes('</a>') && body.includes('</div>')) {
    // Check for hidden text
    if (/color:\s*white|font-size:\s*0|display:\s*none/i.test(body)) {
      score += 40; signals.push('Hidden text detected in HTML — evasion technique');
    }
  }

  // Subject line analysis
  if (subject) {
    const subLower = subject.toLowerCase();
    if (/re:|fwd:/i.test(subject) && !subLower.includes('your')) {
      score += 10; signals.push('Fake reply/forward thread — thread hijacking');
    }
    if (subject.length > 100) {
      score += 10; signals.push('Unusually long subject line');
    }
  }

  return { score: Math.min(100, score), signals };
}

// ── Main Email Scoring Function ───────────────────────────────────────────────

/**
 * Compute composite PhishScore for an email
 *
 * @param {Object} email - Email object
 * @param {string} email.from         - Sender email address
 * @param {string} email.displayName  - Sender display name
 * @param {string} email.replyTo      - Reply-To address
 * @param {string} email.subject      - Email subject
 * @param {string} email.body         - Email body (plain text or HTML)
 * @param {string} email.headers      - Raw email headers
 * @param {Array}  email.attachments  - Array of attachment filenames
 *
 * @returns {Object} Detailed PhishScore with dimension breakdown
 */
function analyzeEmail(email) {
  const startTime = Date.now();
  const { from = '', displayName = '', replyTo = '', subject = '', body = '', headers = '', attachments = [] } = email;

  const senderDomain = from.split('@')[1]?.toLowerCase() || '';

  // Run all detection dimensions
  const d1 = analyzeHeaders(headers);
  const d2 = analyzeSender(from, displayName, replyTo);
  const d3 = analyzeUrgency(body);
  const d4 = analyzeLinks(body);
  const d5 = analyzeContentImpersonation(body, subject, senderDomain);
  const d6 = analyzeAttachments(attachments);
  const d7 = analyzeContentAnomalies(body, subject);

  // Weighted composite
  // Sender spoofing and header forensics are primary (25% + 20%)
  // Urgency and link analysis reinforce (20% + 15%)
  // Brand impersonation, attachments, content anomalies support (10% + 5% + 5%)
  const weights = {
    headers:     0.20,
    sender:      0.25,
    urgency:     0.20,
    links:       0.15,
    impersonation: 0.10,
    attachments: 0.05,
    anomalies:   0.05
  };

  const rawScore =
    d1.score * weights.headers +
    d2.score * weights.sender +
    d3.score * weights.urgency +
    d4.score * weights.links +
    d5.score * weights.impersonation +
    d6.score * weights.attachments +
    d7.score * weights.anomalies;

  const phishScore = Math.round(Math.min(100, rawScore));

  // Verdict
  let verdict, riskLevel, recommendation;
  if (phishScore >= 75) {
    verdict = 'PHISHING';
    riskLevel = 'critical';
    recommendation = 'Do not click any links or open attachments. Report to IT security immediately. Delete this email.';
  } else if (phishScore >= 50) {
    verdict = 'SUSPICIOUS';
    riskLevel = 'high';
    recommendation = 'Treat with extreme caution. Verify sender through official channels. Do not provide credentials.';
  } else if (phishScore >= 25) {
    verdict = 'UNCERTAIN';
    riskLevel = 'medium';
    recommendation = 'Proceed carefully. Verify sender identity before clicking links or opening attachments.';
  } else {
    verdict = 'LIKELY SAFE';
    riskLevel = 'low';
    recommendation = 'No significant phishing indicators. Standard email caution applies.';
  }

  const allSignals = [
    ...d1.signals, ...d2.signals, ...d3.signals,
    ...d4.signals, ...d5.signals, ...d6.signals, ...d7.signals
  ];

  return {
    type: 'email',
    from,
    display_name: displayName,
    subject,
    phish_score: phishScore,
    verdict,
    risk_level: riskLevel,
    recommendation,
    confidence: allSignals.length > 4 ? 'high' : allSignals.length > 2 ? 'medium' : 'low',
    signals: allSignals,
    dimensions: {
      header_forensics:      Math.round(d1.score),
      sender_spoofing:       Math.round(d2.score),
      urgency_manipulation:  Math.round(d3.score),
      link_analysis:         Math.round(d4.score),
      brand_impersonation:   Math.round(d5.score),
      attachment_risk:       Math.round(d6.score),
      content_anomalies:     Math.round(d7.score)
    },
    metadata: {
      sender_domain:    senderDomain,
      links_found:      d4.totalLinks || 0,
      urgency_terms:    d3.urgencyTerms?.length || 0,
      attachments_risk: d6.attachments || [],
      suspicious_links: d4.links?.filter(l => l.score >= 50) || [],
      analyzed_at:      new Date().toISOString(),
      analysis_ms:      Date.now() - startTime
    }
  };
}

module.exports = { analyzeEmail, analyzeHeaders, analyzeSender, analyzeUrgency, analyzeLinks };
