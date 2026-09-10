/**
 * PhishGuard — AI Explanation Layer v1.1
 * Author: Habtamu Heyi
 *
 * IMPORTANT — SCOPE OF THIS MODULE:
 * This module does NOT perform phishing detection. All detection,
 * scoring, and verdict decisions happen in the rule-based engines
 * (url-engine.js, email-engine.js) BEFORE this module is ever called.
 *
 * This module's only job is to take an already-computed PhishScore
 * result and translate it into a short, plain-English explanation for
 * non-technical readers — e.g. a church administrator or small business
 * owner who has no security background and needs to know, in one
 * paragraph, what happened and what to do about it.
 *
 * This separation matters and is deliberate: the detection engine's
 * output is fully deterministic, reproducible, and independent of any
 * AI model. The AI layer sits strictly downstream of detection, as a
 * plain-language interpreter — not as the thing making the call.
 *
 * PROVIDER-AGNOSTIC: This module supports three interchangeable providers
 * — Groq (recommended, free), Google Gemini (free tier), and Anthropic
 * (paid). Set AI_PROVIDER in .env to "groq", "gemini", or "anthropic".
 * The prompt and output contract are identical regardless of provider —
 * only the API call underneath changes. Detection accuracy and behavior
 * are completely unaffected by which provider is chosen, since none of
 * them touch the detection logic.
 */

/**
 * Build a compact, factual prompt from an existing PhishGuard result.
 * The prompt deliberately includes ONLY the already-computed output —
 * the AI is never given the raw URL/email to independently judge,
 * so it cannot silently override or replace the rule-based verdict.
 */
function buildPrompt(result) {
  const topSignals = (result.signals || []).slice(0, 5);
  const dims = result.dimensions || {};
  const topDims = Object.entries(dims)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([name, score]) => `${name.replace(/_/g, ' ')} (${score}/100)`)
    .join(', ');

  return `You are explaining an automated phishing-detection result to a non-technical reader — for example, a church administrator or small business owner with no security background.

Detection result (already computed by a rule-based engine — do not re-evaluate or second-guess it):
- Type: ${result.type === 'email' ? 'Email' : 'URL'}
- PhishScore: ${result.phish_score}/100
- Verdict: ${result.verdict}
- Confidence: ${result.confidence}
- Top contributing factors: ${topDims || 'none significant'}
- Specific signals detected: ${topSignals.length ? topSignals.join('; ') : 'none significant'}

Write a plain-English explanation in exactly 2-3 short sentences. Do not use technical jargon (no "entropy," "homoglyph," "SPF/DKIM," etc. — translate these into everyday language). Do not repeat the raw score. Explain simply what was found and why it matters. End with one short, concrete recommended action. Do not add any disclaimers, caveats, or mention that you are an AI.`;
}

// ── Provider: Groq (recommended — free, fast) ──────────────────────────────────
async function callGroq(prompt) {
  const Groq = require('groq-sdk');
  const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });
  const completion = await groq.chat.completions.create({
    model: 'llama-3.3-70b-versatile',
    messages: [{ role: 'user', content: prompt }],
    max_tokens: 200,
    temperature: 0.3
  });
  return completion.choices?.[0]?.message?.content?.trim() || null;
}

// ── Provider: Google Gemini (free tier) ─────────────────────────────────────────
async function callGemini(prompt) {
  const { GoogleGenerativeAI } = require('@google/generative-ai');
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
  const result = await model.generateContent(prompt);
  return result.response.text()?.trim() || null;
}

// ── Provider: Anthropic (paid) ──────────────────────────────────────────────────
async function callAnthropic(prompt) {
  const Anthropic = require('@anthropic-ai/sdk');
  const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  const message = await anthropic.messages.create({
    model: 'claude-haiku-4-5',
    max_tokens: 200,
    messages: [{ role: 'user', content: prompt }]
  });
  return message.content?.[0]?.text?.trim() || null;
}

/**
 * Determine which provider is configured and available.
 * Checks AI_PROVIDER env var first; falls back to whichever API key is set.
 */
function resolveProvider() {
  const explicit = (process.env.AI_PROVIDER || '').toLowerCase();
  if (explicit === 'groq' && process.env.GROQ_API_KEY) return 'groq';
  if (explicit === 'gemini' && process.env.GEMINI_API_KEY) return 'gemini';
  if (explicit === 'anthropic' && process.env.ANTHROPIC_API_KEY) return 'anthropic';

  // Auto-detect if AI_PROVIDER isn't set — checks in order of preference
  if (process.env.GEMINI_API_KEY && !process.env.GEMINI_API_KEY.includes('your_')) return 'gemini';
  if (process.env.GROQ_API_KEY && !process.env.GROQ_API_KEY.includes('your_')) return 'groq';
  if (process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_API_KEY.includes('your_')) return 'anthropic';
  return null;
}

/**
 * Generate a plain-English summary for an already-scored PhishGuard result.
 *
 * @param {Object} result - Output from analyzeURL() or analyzeEmail()
 * @returns {Promise<Object>} { summary: string, ai_available: boolean, provider: string }
 */
async function explainResult(result) {
  const provider = resolveProvider();

  if (!provider) {
    return {
      summary: null,
      ai_available: false,
      provider: null,
      note: 'AI explanation layer not configured — detection result above is unaffected and fully valid on its own. Set GROQ_API_KEY (recommended, free), GEMINI_API_KEY, or ANTHROPIC_API_KEY in .env to enable.'
    };
  }

  const prompt = buildPrompt(result);

  try {
    let summary;
    if (provider === 'groq') summary = await callGroq(prompt);
    else if (provider === 'gemini') summary = await callGemini(prompt);
    else summary = await callAnthropic(prompt);

    return { summary, ai_available: true, provider };
  } catch (e) {
    console.warn(`[AI Layer] Explanation generation failed (provider: ${provider}):`, e.message);
    return {
      summary: null,
      ai_available: false,
      provider,
      note: `AI explanation temporarily unavailable (${provider} error) — detection result above is unaffected and fully valid on its own.`
    };
  }
}

module.exports = { explainResult, resolveProvider };
