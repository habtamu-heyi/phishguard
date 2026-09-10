/**
 * PhishGuard — Express API Server v1.1
 * Author: Habtamu Heyi
 *
 * Phishing & Fraud Detection Engine
 * Detection: original rule-based multi-factor structural and linguistic
 * analysis (url-engine.js, email-engine.js) — fully deterministic,
 * reproducible, and independent of any AI model.
 * AI Explanation Layer (v1.1): translates already-computed detection
 * results into plain-English summaries for non-technical users. The AI
 * layer never performs detection and cannot alter a verdict.
 */

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const path      = require('path');
const { createClient } = require('@supabase/supabase-js');

const { analyzeURL }   = require('./src/engines/url-engine');
const { analyzeEmail } = require('./src/engines/email-engine');
const { explainResult } = require('./src/ai-explain');
const { enrichWithDomainAge } = require('./src/domain-age');
const app   = express();
const cache = new NodeCache({ stdTTL: 300 });

// ── Supabase ──────────────────────────────────────────────────────────────────
let supabase = null;
if (process.env.SUPABASE_URL && !process.env.SUPABASE_URL.includes('your_')) {
  supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
}

async function saveAnalysis(type, input, result, aiSummary = null) {
  if (!supabase) return;
  try {
    await supabase.from('phishguard_analyses').insert({
      analysis_type: type,
      input_value:   input.slice(0, 500),
      phish_score:   result.phish_score,
      verdict:       result.verdict,
      risk_level:    result.risk_level,
      signals:       result.signals,
      dimensions:    result.dimensions,
      metadata:      result.metadata,
      ai_summary:    aiSummary
    });
  } catch (e) {
    console.warn('[DB] Save failed:', e.message);
  }
}

async function getHistory(limit = 20) {
  if (!supabase) return [];
  try {
    const { data } = await supabase
      .from('phishguard_analyses')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit);
    return data || [];
  } catch { return []; }
}

async function getStats() {
  if (!supabase) return null;
  try {
    const { data } = await supabase
      .from('phishguard_analyses')
      .select('verdict, analysis_type, phish_score');
    if (!data) return null;
    return {
      total:     data.length,
      phishing:  data.filter(d => d.verdict === 'PHISHING').length,
      suspicious:data.filter(d => d.verdict === 'SUSPICIOUS').length,
      safe:      data.filter(d => d.verdict === 'LIKELY SAFE').length,
      url_scans: data.filter(d => d.analysis_type === 'url').length,
      email_scans:data.filter(d => d.analysis_type === 'email').length,
      avg_score: Math.round(data.reduce((s, d) => s + d.phish_score, 0) / data.length)
    };
  } catch { return null; }
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: '2mb' })); // Emails can be large
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

function log(level, msg) {
  console.log(`[${new Date().toISOString()}] [${level.toUpperCase()}] ${msg}`);
}

// ── API Routes ────────────────────────────────────────────────────────────────

// Analyze URL
app.post('/api/analyze/url', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  try {
    const result = analyzeURL(url);
    if (result.error) return res.status(400).json({ error: result.error });
    saveAnalysis('url', url, result).catch(() => {});
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Analyze Email
app.post('/api/analyze/email', async (req, res) => {
  const { from, displayName, replyTo, subject, body, headers, attachments } = req.body;
  if (!from && !body) return res.status(400).json({ error: 'from or body is required' });
  try {
    const result = analyzeEmail({ from, displayName, replyTo, subject, body, headers, attachments: attachments || [] });
    saveAnalysis('email', from || subject || 'unknown', result).catch(() => {});
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Bulk URL scan
app.post('/api/analyze/bulk', async (req, res) => {
  const { urls } = req.body;
  if (!urls || !Array.isArray(urls)) return res.status(400).json({ error: 'urls array required' });
  if (urls.length > 50) return res.status(400).json({ error: 'Maximum 50 URLs per bulk request' });
  try {
    const results = urls.map(url => ({ url, ...analyzeURL(url) }));
    results.forEach(r => saveAnalysis('url', r.url, r).catch(() => {}));
    const summary = {
      total: results.length,
      phishing:   results.filter(r => r.verdict === 'PHISHING').length,
      suspicious: results.filter(r => r.verdict === 'SUSPICIOUS').length,
      uncertain:  results.filter(r => r.verdict === 'UNCERTAIN').length,
      safe:       results.filter(r => r.verdict === 'LIKELY SAFE').length,
      highest_score: Math.max(...results.map(r => r.phish_score || 0))
    };
    res.json({ summary, results });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── AI Explanation Layer ─────────────────────────────────────────────────────
// IMPORTANT: These endpoints do NOT re-run or alter detection. They call the
// exact same rule-based engines as /api/analyze/url and /api/analyze/email,
// then pass the already-computed result to the AI layer for a plain-English
// explanation only. If the AI layer is unavailable, the detection result is
// still returned in full — the AI explanation is additive, never load-bearing.

// Analyze URL + plain-English AI explanation
app.post('/api/analyze/url/explain', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  try {
    const result = analyzeURL(url);
    if (result.error) return res.status(400).json({ error: result.error });
    const { summary, ai_available, note } = await explainResult(result);
    saveAnalysis('url', url, result, summary).catch(() => {});
    res.json({ ...result, ai_summary: summary, ai_available, ai_note: note });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});


// Analyze URL + domain age enrichment + AI explanation ("deep" analysis)
// Domain age check is a genuinely separate signal source (RDAP registration
// data, not URL structure) — see src/domain-age.js for full rationale.
// This is additive: if the RDAP lookup fails or times out, the original
// 6-dimension structural result is returned completely unmodified.
app.post('/api/analyze/url/deep', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url is required' });
  try {
    const structuralResult = analyzeURL(url);
    if (structuralResult.error) return res.status(400).json({ error: structuralResult.error });
    const enriched = await enrichWithDomainAge(structuralResult);
    const { summary, ai_available, note } = await explainResult(enriched);
    saveAnalysis('url', url, enriched, summary).catch(() => {});
    res.json({ ...enriched, ai_summary: summary, ai_available, ai_note: note });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Analyze Email + plain-English AI explanation
app.post('/api/analyze/email/explain', async (req, res) => {
  const { from, displayName, replyTo, subject, body, headers, attachments } = req.body;
  if (!from && !body) return res.status(400).json({ error: 'from or body is required' });
  try {
    const result = analyzeEmail({ from, displayName, replyTo, subject, body, headers, attachments: attachments || [] });
    const { summary, ai_available, note } = await explainResult(result);
    saveAnalysis('email', from || subject || 'unknown', result, summary).catch(() => {});
    res.json({ ...result, ai_summary: summary, ai_available, ai_note: note });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Analysis history
app.get('/api/history', async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);
  const history = await getHistory(limit);
  res.json({ results: history });
});

// Stats
app.get('/api/stats', async (req, res) => {
  const stats = await getStats();
  res.json(stats || { total: 0, phishing: 0, suspicious: 0, safe: 0, url_scans: 0, email_scans: 0, avg_score: 0 });
});

// CyberWatch integration endpoint
// CyberWatch calls this when a URL appears in an IOC lookup
app.post('/api/cyberwatch/enrich', async (req, res) => {
  const { urls = [], emails = [] } = req.body;
  const urlResults   = urls.map(url => ({ url, ...analyzeURL(url) }));
  const emailResults = emails.map(email => ({ ...analyzeEmail(email) }));
  res.json({
    url_analysis:   urlResults,
    email_analysis: emailResults,
    powered_by:     'PhishGuard v1.0'
  });
});

// Health
app.get('/api/health', async (req, res) => {
  let dbConnected = false;
  if (supabase) {
    try { const { error } = await supabase.from('phishguard_analyses').select('id').limit(1); dbConnected = !error; }
    catch {}
  }
  const provider = process.env.AI_PROVIDER || (process.env.GEMINI_API_KEY ? 'gemini' : process.env.GROQ_API_KEY ? 'groq' : process.env.ANTHROPIC_API_KEY ? 'anthropic' : null);
  const aiConfigured = !!(
    (process.env.GEMINI_API_KEY && !process.env.GEMINI_API_KEY.includes('your_')) ||
    (process.env.GROQ_API_KEY && !process.env.GROQ_API_KEY.includes('your_')) ||
    (process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_API_KEY.includes('your_'))
  );
  res.json({
    status: 'ok', version: '1.1.0',
    engines: { url: 'PhishGuard URL Engine v1.0', email: 'PhishGuard Email Engine v1.0' },
    ai_explanation_layer: aiConfigured ? `active (${provider})` : 'not configured (detection unaffected)',
    database: dbConnected ? 'connected' : 'not configured',
    cyberwatch_integration: true,
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  const provider = process.env.AI_PROVIDER || (process.env.GEMINI_API_KEY ? 'gemini' : process.env.GROQ_API_KEY ? 'groq' : process.env.ANTHROPIC_API_KEY ? 'anthropic' : null);
  const aiConfigured = !!(
    (process.env.GEMINI_API_KEY && !process.env.GEMINI_API_KEY.includes('your_')) ||
    (process.env.GROQ_API_KEY && !process.env.GROQ_API_KEY.includes('your_')) ||
    (process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_API_KEY.includes('your_'))
  );
  log('info', `PhishGuard v1.1.0 running on http://localhost:${PORT}`);
  log('info', `URL Engine: active`);
  log('info', `Email Engine: active`);
  log('info', `AI Explanation Layer: ${aiConfigured ? `active (${provider})` : 'not configured — /explain endpoints will return detection results without AI summary'}`);
  log('info', `Database: ${supabase ? 'connected' : 'not configured'}`);
  log('info', `CyberWatch integration: enabled on /api/cyberwatch/enrich`);
});

module.exports = app;
