/**
 * PhishGuard — Threat Intelligence Data
 * Author: Habtamu Wario
 *
 * Static threat intelligence datasets used by the detection engines.
 * In production these would be updated from live threat feeds.
 */

// Top 200+ brands most commonly impersonated in phishing campaigns
// Source: APWG, Anti-Phishing Working Group reports, FBI IC3 data
// Updated after validation study to include major international brands
// (original list was US-centric; PhishTank's feed is global)
const IMPERSONATED_BRANDS = [
  // Financial
  'paypal', 'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'usbank',
  'capitalone', 'americanexpress', 'amex', 'discover', 'venmo', 'cashapp',
  'zelle', 'coinbase', 'binance', 'kraken', 'robinhood', 'fidelity',
  'schwab', 'vanguard', 'td', 'pnc', 'regions', 'suntrust', 'truist',
  'revolut', 'ing', 'santander', 'hsbc', 'barclays', 'natwest', 'lloyds',
  // Tech
  'microsoft', 'apple', 'google', 'amazon', 'facebook', 'meta', 'instagram',
  'twitter', 'netflix', 'spotify', 'dropbox', 'adobe', 'linkedin', 'yahoo',
  'outlook', 'office365', 'onedrive', 'icloud', 'gmail', 'youtube',
  'whatsapp', 'telegram', 'zoom', 'slack', 'github', 'aws', 'azure',
  'salesforce', 'docusign', 'intuit', 'turbotax', 'quickbooks',
  // Retail / Delivery / International e-commerce
  'amazon', 'ebay', 'walmart', 'target', 'bestbuy', 'fedex', 'ups',
  'usps', 'dhl', 'shein', 'etsy', 'shopify', 'allegro', 'zalando',
  'mercadolibre', 'aliexpress', 'temu', 'otto', 'flipkart', 'lazada',
  // Government / Healthcare
  'irs', 'ssa', 'medicare', 'medicaid', 'socialsecurity', 'treasury',
  'dmv', 'fbi', 'doj', 'cdc', 'fda', 'va',
  // Telecom
  'att', 'verizon', 'tmobile', 'comcast', 'xfinity', 'spectrum',
  // Insurance
  'geico', 'progressive', 'statefarm', 'allstate', 'aetna', 'humana',
  'unitedhealth', 'anthem', 'cigna'
];

// High-risk TLDs frequently abused in phishing campaigns
// Source: ICANN abuse statistics, Spamhaus TLD reputation data
// Updated [validation study date] after PhishGuard's PhishTank validation
// study identified several current high-abuse TLDs missing from the
// original list (.cyou, .sbs, .buzz, .cfd, .icu were observed in the
// live PhishTank feed but scored as generic "unknown TLD" — see
// docs/validation-study-*.md for the study that identified this gap)
const HIGH_RISK_TLDS = {
  '.xyz':    90, '.top':    88, '.click':  85, '.loan':   95,
  '.work':   80, '.gq':     92, '.ml':     90, '.cf':     88,
  '.ga':     87, '.tk':     95, '.pw':     85, '.cc':     75,
  '.su':     80, '.ws':     72, '.biz':    65, '.info':   60,
  '.online': 70, '.site':   68, '.web':    65, '.tech':   55,
  '.live':   72, '.stream': 75, '.download':80,'.zip':    90,
  '.mov':    88, '.link':   65, '.email':  70, '.support':75,
  '.help':   70, '.claims': 85, '.review': 72, '.win':    80,
  // Added after validation study — current high-abuse TLDs
  '.cyou':   93, '.sbs':    90, '.buzz':   82, '.cfd':    88,
  '.icu':    85, '.rest':   78, '.bond':   80, '.beauty': 75,
  '.cam':    78, '.phd':    70, '.wf':     75, '.autos':  70,
  '.sa.com': 65, '.uno':    72, '.quest':  75, '.digital':60
};

// Low-risk TLDs (established, regulated registries)
const LOW_RISK_TLDS = [
  '.gov', '.edu', '.mil', '.int',
  '.com', '.org', '.net', '.co.uk', '.ac.uk', '.gov.uk'
];

// Urgency and manipulation keywords commonly used in phishing
// Weighted by frequency in confirmed phishing samples
const URGENCY_KEYWORDS = {
  // Critical urgency (high weight)
  'account suspended':     9, 'account terminated':   9,
  'immediate action':      8, 'act now':              8,
  'urgent':                7, 'immediately':          7,
  'verify now':            8, 'confirm immediately':  8,
  'limited time':          7, 'expires today':        8,
  'final notice':          9, 'last warning':         9,
  'account will be closed':9, 'suspended':            7,
  // Financial pressure
  'unusual activity':      8, 'suspicious activity':  8,
  'unauthorized access':   8, 'security alert':       7,
  'payment failed':        7, 'payment declined':     7,
  'invoice attached':      6, 'wire transfer':        7,
  'gift card':             8, 'bitcoin':              7,
  'refund pending':        7, 'tax refund':           8,
  // Authority spoofing
  'irs notice':            9, 'federal bureau':       9,
  'legal action':          8, 'lawsuit':              8,
  'warrant':               9, 'arrest':               9,
  'government':            5, 'official notice':      7,
  // Prize/reward fraud
  'you have won':          9, 'winner':               8,
  'selected':              6, 'lottery':              9,
  'prize':                 7, 'reward':               6,
  'free gift':             7, 'claim your':           7,
  // Credential harvesting
  'verify your account':   8, 'confirm your identity':8,
  'update your information':7,'click here to verify': 8,
  'login to continue':     7, 'sign in to':           6,
  'password expired':      8, 'reset your password':  7
};

// Homoglyph character substitutions used in lookalike domains
const HOMOGLYPHS = {
  'a': ['@', '4', 'à', 'á', 'â', 'ã', 'ä', 'å'],
  'e': ['3', 'è', 'é', 'ê', 'ë'],
  'i': ['1', 'l', '!', 'ì', 'í', 'î', 'ï'],
  'o': ['0', 'ò', 'ó', 'ô', 'õ', 'ö'],
  'u': ['ù', 'ú', 'û', 'ü'],
  's': ['5', '$'],
  'g': ['9'],
  'b': ['6'],
  't': ['7'],
  'l': ['1', 'i', '|']
};

// Suspicious URL patterns
const SUSPICIOUS_URL_PATTERNS = [
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,  // Raw IP address
  /@/,                                      // @ symbol in URL (redirect trick)
  /[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\./,      // Excessive hyphens
  /\.(exe|zip|rar|js|vbs|bat|cmd|scr|pif|msi)$/i, // Dangerous extensions
  /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|cli\.gs|pic\.gd|turl\.ch|tiny\.cc/, // URL shorteners
  /[a-z]{30,}/,                            // Very long strings (obfuscation)
  /%[0-9a-f]{2}/i,                         // Percent encoding (evasion)
  /data:/i,                                // Data URI
  /javascript:/i                           // JavaScript URI
];

// Common legitimate domains for context (not exhaustive)
const LEGITIMATE_DOMAINS = [
  'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'amazon.com',
  'apple.com', 'microsoft.com', 'twitter.com', 'instagram.com', 'linkedin.com',
  'paypal.com', 'netflix.com', 'github.com', 'stackoverflow.com', 'reddit.com',
  'wikipedia.org', 'yahoo.com', 'dropbox.com', 'spotify.com', 'zoom.us'
];

// Dangerous email attachment extensions
const DANGEROUS_EXTENSIONS = [
  '.exe', '.bat', '.cmd', '.vbs', '.js', '.jar', '.msi', '.ps1',
  '.scr', '.pif', '.com', '.hta', '.reg', '.dll', '.sys',
  '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm', // Macro-enabled Office
  '.zip', '.rar', '.7z', '.iso', '.img'               // Archive files
];

module.exports = {
  IMPERSONATED_BRANDS,
  HIGH_RISK_TLDS,
  LOW_RISK_TLDS,
  URGENCY_KEYWORDS,
  HOMOGLYPHS,
  SUSPICIOUS_URL_PATTERNS,
  LEGITIMATE_DOMAINS,
  DANGEROUS_EXTENSIONS
};