/**
 * Solodit API Integration for Web3CRIT Scanner
 *
 * Correlates detected vulnerabilities with real-world exploits and disclosed bugs
 * from the Solodit vulnerability database.
 *
 * Features:
 * - Query by vulnerability type, root cause, affected protocol, and code pattern
 * - Validate findings as "confirmed in the wild" or "theoretical"
 * - Assign confidence scores based on match quality
 * - Read-only, production-safe, with graceful error handling
 * - Intelligent caching to minimize API calls
 *
 * Solodit Categories Mapping:
 * - Access Control: unprotected functions, missing modifiers
 * - Reentrancy: classic, cross-function, cross-contract, read-only
 * - Oracle Manipulation: price feed attacks, TWAP manipulation
 * - Flash Loan: balance manipulation, governance attacks
 * - Arithmetic: overflow, underflow, precision loss
 * - Logic Errors: state machine bugs, incorrect assumptions
 */

const https = require('https');
const http = require('http');

// Vulnerability type mapping to Solodit categories
const VULN_TYPE_TO_SOLODIT_CATEGORY = {
  // Reentrancy variants
  'reentrancy': ['reentrancy', 'cross-function-reentrancy'],
  'cross-function-reentrancy': ['reentrancy', 'cross-function-reentrancy'],
  'cross-contract-reentrancy': ['reentrancy', 'cross-contract-reentrancy'],
  'read-only-reentrancy': ['reentrancy', 'read-only-reentrancy'],
  'callback-reentrancy': ['reentrancy', 'erc777-callback', 'erc1155-callback'],

  // Access control
  'access-control': ['access-control', 'missing-access-control', 'privilege-escalation'],
  'missing-access-control': ['access-control', 'missing-access-control'],
  'broken-access-control': ['access-control', 'broken-access-control'],
  'tx-origin': ['access-control', 'tx-origin-authentication'],

  // Oracle/Price manipulation
  'oracle-manipulation': ['oracle-manipulation', 'price-manipulation', 'twap-manipulation'],
  'flash-loan': ['flash-loan', 'price-manipulation', 'oracle-manipulation'],
  'flash-loan-oracle': ['flash-loan', 'oracle-manipulation'],
  'flash-loan-oracle-manipulation': ['flash-loan', 'oracle-manipulation'],
  'stale-price': ['oracle-manipulation', 'stale-price', 'chainlink'],
  'spot-price-manipulation': ['price-manipulation', 'spot-price'],

  // Proxy/Upgrade
  'proxy': ['proxy', 'upgradeable', 'storage-collision'],
  'unprotected-initializer': ['proxy', 'unprotected-initializer', 'initialization'],
  'unauthorized-upgrade': ['proxy', 'unauthorized-upgrade', 'uups'],
  'storage-collision': ['proxy', 'storage-collision'],

  // Signature/Replay
  'signature-replay': ['signature', 'replay-attack', 'missing-nonce'],
  'permit-replay': ['signature', 'permit', 'erc20-permit'],
  'missing-deadline': ['signature', 'deadline', 'permit'],

  // Fund handling
  'unchecked-call': ['unchecked-return', 'low-level-call'],
  'delegatecall': ['delegatecall', 'proxy', 'code-injection'],
  'delegatecall-injection': ['delegatecall', 'code-injection'],
  'selfdestruct': ['selfdestruct', 'force-ether', 'contract-destruction'],

  // DeFi specific
  'vault-inflation': ['vault', 'first-depositor', 'share-inflation'],
  'share-manipulation': ['vault', 'share-manipulation', 'erc4626'],
  'first-depositor': ['vault', 'first-depositor', 'donation-attack'],
  'donation-attack': ['donation-attack', 'vault', 'share-manipulation'],

  // Governance
  'governance': ['governance', 'voting', 'flash-loan-governance'],
  'governance-reentrancy': ['governance', 'reentrancy'],

  // Arithmetic
  'integer-overflow': ['arithmetic', 'overflow', 'underflow'],
  'precision-loss': ['arithmetic', 'precision-loss', 'rounding'],

  // Other
  'frontrunning': ['frontrunning', 'mev', 'sandwich'],
  'toctou': ['toctou', 'race-condition'],
  'timestamp-dependence': ['timestamp', 'block-timestamp']
};

// Root cause patterns for deeper matching
const ROOT_CAUSE_PATTERNS = {
  'external-call-before-state-update': /external.*call.*before.*state|state.*after.*call|reentrancy/i,
  'missing-access-control': /no.*access.*control|missing.*modifier|public.*sensitive|unprotected/i,
  'unchecked-external-input': /user.*input|untrusted.*input|external.*input|tainted/i,
  'flash-loan-price-manipulation': /flash.*loan|price.*manipulat|oracle.*manipulat/i,
  'arithmetic-precision': /precision|rounding|division.*before.*multiplic|truncat/i,
  'signature-validation': /signature|ecrecover|nonce|replay|permit/i,
  'initialization-race': /initializ|uninitializ|proxy|upgrade/i,
  'state-inconsistency': /inconsistent.*state|state.*corrupt|toctou|race.*condition/i
};

/**
 * Built-in knowledge base of notable exploits for offline mode
 * Data sourced from public post-mortems and security research
 */
const OFFLINE_EXPLOIT_DATABASE = [
  // Reentrancy exploits
  {
    id: 'OKB-001',
    title: 'The DAO Hack - Classic Reentrancy',
    protocol: 'The DAO',
    categories: ['reentrancy'],
    rootCause: 'external-call-before-state-update',
    keywords: ['reentrancy', 'withdraw', 'call', 'balance', 'recursive'],
    codePatterns: ['external-call-with-value', 'low-level-call'],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 60000000,
    exploitDate: '2016-06-17',
    references: ['https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/']
  },
  {
    id: 'OKB-002',
    title: 'Cream Finance Reentrancy via AMP Token',
    protocol: 'Cream Finance',
    categories: ['reentrancy', 'erc777-callback'],
    rootCause: 'external-call-before-state-update',
    keywords: ['reentrancy', 'erc777', 'callback', 'lending', 'borrow'],
    codePatterns: ['external-call-with-value'],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 18800000,
    exploitDate: '2021-08-30',
    references: ['https://medium.com/cream-finance/c-r-e-a-m-finance-post-mortem-amp-exploit-6ceb20a630c5']
  },
  {
    id: 'OKB-003',
    title: 'Curve Finance Read-Only Reentrancy',
    protocol: 'Curve Finance',
    categories: ['reentrancy', 'read-only-reentrancy'],
    rootCause: 'external-call-before-state-update',
    keywords: ['reentrancy', 'read-only', 'view', 'price', 'oracle', 'curve'],
    codePatterns: ['external-call-with-value', 'balance-based-logic'],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 47000000,
    exploitDate: '2023-07-30',
    references: ['https://hackmd.io/@LlamaRisk/BJzSKHNjn']
  },

  // Flash loan / Oracle manipulation
  {
    id: 'OKB-010',
    title: 'bZx Flash Loan Oracle Manipulation',
    protocol: 'bZx',
    categories: ['flash-loan', 'oracle-manipulation', 'price-manipulation'],
    rootCause: 'flash-loan-price-manipulation',
    keywords: ['flash', 'loan', 'oracle', 'price', 'manipulation', 'borrow'],
    codePatterns: ['balance-based-logic'],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 8100000,
    exploitDate: '2020-02-15',
    references: ['https://peckshield.medium.com/bzx-hack-full-disclosure-with-detailed-profit-analysis-e6b1fa9b18fc']
  },
  {
    id: 'OKB-011',
    title: 'Harvest Finance Flash Loan Attack',
    protocol: 'Harvest Finance',
    categories: ['flash-loan', 'price-manipulation'],
    rootCause: 'flash-loan-price-manipulation',
    keywords: ['flash', 'loan', 'vault', 'price', 'manipulation', 'arbitrage'],
    codePatterns: ['balance-based-logic'],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 34000000,
    exploitDate: '2020-10-26',
    references: ['https://medium.com/harvest-finance/harvest-flashloan-economic-attack-post-mortem-3cf900d65217']
  },
  {
    id: 'OKB-012',
    title: 'Euler Finance Flash Loan Attack',
    protocol: 'Euler Finance',
    categories: ['flash-loan', 'oracle-manipulation'],
    rootCause: 'flash-loan-price-manipulation',
    keywords: ['flash', 'loan', 'donate', 'liquidation', 'collateral'],
    codePatterns: ['balance-based-logic'],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 197000000,
    exploitDate: '2023-03-13',
    references: ['https://www.euler.finance/blog/euler-protocol-attack-post-mortem']
  },

  // Access control
  {
    id: 'OKB-020',
    title: 'Poly Network Access Control Bypass',
    protocol: 'Poly Network',
    categories: ['access-control', 'missing-access-control'],
    rootCause: 'missing-access-control',
    keywords: ['access', 'control', 'keeper', 'admin', 'cross-chain'],
    codePatterns: ['unprotected-sender'],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 610000000,
    exploitDate: '2021-08-10',
    references: ['https://slowmist.medium.com/the-root-cause-of-poly-network-being-hacked-ec2ee1b0c68f']
  },
  {
    id: 'OKB-021',
    title: 'Ronin Bridge Validator Key Compromise',
    protocol: 'Ronin Network',
    categories: ['access-control'],
    rootCause: 'missing-access-control',
    keywords: ['bridge', 'validator', 'multisig', 'admin', 'key'],
    codePatterns: [],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 624000000,
    exploitDate: '2022-03-23',
    references: ['https://roninblockchain.substack.com/p/community-alert-ronin-validators']
  },

  // Proxy/Upgrade vulnerabilities
  {
    id: 'OKB-030',
    title: 'Wormhole Uninitialized Proxy',
    protocol: 'Wormhole',
    categories: ['proxy', 'unprotected-initializer'],
    rootCause: 'initialization-race',
    keywords: ['proxy', 'initialize', 'guardian', 'bridge', 'upgrade'],
    codePatterns: [],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 320000000,
    exploitDate: '2022-02-02',
    references: ['https://extropy-io.medium.com/solana-wormhole-bridge-exploit-technical-analysis-3c1c0c99e8b8']
  },
  {
    id: 'OKB-031',
    title: 'Audius Uninitialized Proxy Storage',
    protocol: 'Audius',
    categories: ['proxy', 'unprotected-initializer', 'storage-collision'],
    rootCause: 'initialization-race',
    keywords: ['proxy', 'initialize', 'storage', 'governance', 'voting'],
    codePatterns: [],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 6000000,
    exploitDate: '2022-07-24',
    references: ['https://blog.audius.co/article/audius-governance-takeover-post-mortem-7-23-22']
  },

  // Signature replay
  {
    id: 'OKB-040',
    title: 'Wintermute Profanity Key Vulnerability',
    protocol: 'Wintermute',
    categories: ['signature', 'access-control'],
    rootCause: 'signature-validation',
    keywords: ['signature', 'key', 'vanity', 'private', 'brute-force'],
    codePatterns: ['ecrecover'],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 160000000,
    exploitDate: '2022-09-20',
    references: ['https://rekt.news/wintermute-rekt/']
  },
  {
    id: 'OKB-041',
    title: 'Nomad Bridge Signature Bypass',
    protocol: 'Nomad',
    categories: ['signature', 'access-control'],
    rootCause: 'signature-validation',
    keywords: ['bridge', 'signature', 'merkle', 'root', 'verification'],
    codePatterns: [],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 190000000,
    exploitDate: '2022-08-01',
    references: ['https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis-875ad2e5aacd']
  },

  // First depositor / Share manipulation
  {
    id: 'OKB-050',
    title: 'ERC4626 First Depositor Inflation Attack',
    protocol: 'Various ERC4626 Vaults',
    categories: ['vault', 'first-depositor', 'share-inflation'],
    rootCause: 'arithmetic-precision',
    keywords: ['vault', 'share', 'deposit', 'first', 'inflation', 'rounding', 'erc4626'],
    codePatterns: ['balance-based-logic'],
    severity: 'HIGH',
    exploited: true,
    lossAmount: 0,
    exploitDate: '2022-01-01',
    references: ['https://blog.openzeppelin.com/a-]vulnerability-in-erc4626-vaults']
  },

  // Governance attacks
  {
    id: 'OKB-060',
    title: 'Beanstalk Flash Loan Governance Attack',
    protocol: 'Beanstalk',
    categories: ['governance', 'flash-loan', 'flash-loan-governance'],
    rootCause: 'flash-loan-price-manipulation',
    keywords: ['governance', 'flash', 'loan', 'vote', 'proposal', 'snapshot'],
    codePatterns: [],
    severity: 'CRITICAL',
    exploited: true,
    lossAmount: 182000000,
    exploitDate: '2022-04-17',
    references: ['https://bean.money/blog/beanstalk-governance-exploit']
  },

  // Unchecked calls
  {
    id: 'OKB-070',
    title: 'King of the Ether Unchecked Send',
    protocol: 'King of the Ether',
    categories: ['unchecked-return', 'low-level-call'],
    rootCause: 'unchecked-external-input',
    keywords: ['send', 'transfer', 'unchecked', 'return', 'value'],
    codePatterns: ['low-level-call'],
    severity: 'HIGH',
    exploited: true,
    lossAmount: 0,
    exploitDate: '2016-02-06',
    references: ['https://www.kingoftheether.com/postmortem.html']
  }
];

/**
 * Offline vulnerability matcher using built-in knowledge base
 */
class OfflineVulnerabilityMatcher {
  constructor() {
    this.database = OFFLINE_EXPLOIT_DATABASE;
  }

  /**
   * Search for matching vulnerabilities in offline database
   */
  search(finding, categories, keywords, rootCause, codePatterns) {
    const results = [];

    for (const entry of this.database) {
      let score = 0;
      const matchReasons = [];

      // Category match (0-30 points)
      const categoryOverlap = categories.filter(c =>
        entry.categories.some(ec => ec.toLowerCase().includes(c.toLowerCase()) ||
                                    c.toLowerCase().includes(ec.toLowerCase()))
      );
      if (categoryOverlap.length > 0) {
        score += Math.min(30, categoryOverlap.length * 15);
        matchReasons.push(`category: ${categoryOverlap.join(', ')}`);
      }

      // Root cause match (0-25 points)
      if (rootCause !== 'unknown' && entry.rootCause === rootCause) {
        score += 25;
        matchReasons.push(`root cause: ${rootCause}`);
      }

      // Keyword match (0-25 points)
      const keywordOverlap = keywords.filter(k =>
        entry.keywords.some(ek => ek.includes(k) || k.includes(ek))
      );
      if (keywordOverlap.length > 0) {
        score += Math.min(25, keywordOverlap.length * 5);
        matchReasons.push(`keywords: ${keywordOverlap.length} matches`);
      }

      // Code pattern match (0-20 points)
      const patternOverlap = codePatterns.filter(p =>
        entry.codePatterns.some(ep => ep.includes(p) || p.includes(ep))
      );
      if (patternOverlap.length > 0) {
        score += Math.min(20, patternOverlap.length * 10);
        matchReasons.push(`patterns: ${patternOverlap.join(', ')}`);
      }

      // Only include if score is above threshold
      if (score >= 20) {
        results.push({
          ...entry,
          matchConfidence: {
            score: Math.min(100, score),
            normalized: Math.min(1, score / 100),
            reasons: matchReasons
          }
        });
      }
    }

    // Sort by score descending
    results.sort((a, b) => b.matchConfidence.score - a.matchConfidence.score);

    return { results };
  }
}

class SoloditEnricher {
  /**
   * @param {Object} options
   * @param {string} options.apiKey - Solodit API key (or use SOLODIT_API_KEY env var)
   * @param {string} options.baseUrl - Solodit API base URL
   * @param {boolean} options.enabled - Enable/disable enrichment
   * @param {boolean} options.verbose - Verbose logging
   * @param {number} options.timeout - API request timeout in ms
   * @param {number} options.cacheTTL - Cache TTL in ms
   * @param {number} options.maxRetries - Max API retry attempts
   * @param {number} options.minConfidenceThreshold - Minimum match confidence to include (0-1)
   */
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.SOLODIT_API_KEY || null;
    this.baseUrl = options.baseUrl || process.env.SOLODIT_API_URL || 'https://api.solodit.xyz/v1';
    this.verbose = options.verbose || false;
    this.timeout = options.timeout || 10000; // 10 seconds
    this.cacheTTL = options.cacheTTL || 3600000; // 1 hour
    this.maxRetries = options.maxRetries || 2;
    this.minConfidenceThreshold = options.minConfidenceThreshold || 0.3;

    // Offline mode: use built-in knowledge base when no API key
    this.offlineMode = options.offlineMode || !this.apiKey;
    this.offlineMatcher = new OfflineVulnerabilityMatcher();

    // Enable if explicitly requested OR if API key is available
    // Also enable in offline mode for local matching
    this.enabled = options.enabled === true || (options.enabled !== false && this.apiKey !== null);

    // If enabled but no API key, force offline mode
    if (this.enabled && !this.apiKey) {
      this.offlineMode = true;
      this.log('info', 'Solodit enrichment enabled in offline mode (using built-in knowledge base)');
    }

    // In-memory cache with TTL
    this.cache = new Map();
    this.cacheTimestamps = new Map();

    // Statistics
    this.stats = {
      queriesTotal: 0,
      queriesSuccessful: 0,
      queriesFailed: 0,
      cacheHits: 0,
      findingsEnriched: 0,
      confirmedInWild: 0,
      theoretical: 0,
      offlineMode: this.offlineMode
    };

    // Validate API key format if provided
    if (this.apiKey && !this.isValidApiKey(this.apiKey)) {
      this.log('warn', 'Invalid Solodit API key format - falling back to offline mode');
      this.offlineMode = true;
    }
  }

  /**
   * Validate API key format (basic check)
   */
  isValidApiKey(key) {
    return typeof key === 'string' && key.length >= 16 && /^[a-zA-Z0-9_-]+$/.test(key);
  }

  /**
   * Log with verbosity control
   */
  log(level, message, data = null) {
    if (!this.verbose && level !== 'error') return;

    const prefix = `[Solodit ${level.toUpperCase()}]`;
    if (data) {
      console.log(prefix, message, data);
    } else {
      console.log(prefix, message);
    }
  }

  /**
   * Check if cache entry is valid
   */
  isCacheValid(key) {
    if (!this.cache.has(key)) return false;
    const timestamp = this.cacheTimestamps.get(key) || 0;
    return Date.now() - timestamp < this.cacheTTL;
  }

  /**
   * Get from cache
   */
  getFromCache(key) {
    if (this.isCacheValid(key)) {
      this.stats.cacheHits++;
      return this.cache.get(key);
    }
    return null;
  }

  /**
   * Set cache entry
   */
  setCache(key, value) {
    this.cache.set(key, value);
    this.cacheTimestamps.set(key, Date.now());
  }

  /**
   * Generate cache key for a finding
   */
  generateCacheKey(finding) {
    const attackVector = this.normalizeAttackVector(finding.attackVector || finding.detector);
    const titleHash = this.simpleHash(finding.title || '');
    const descHash = this.simpleHash((finding.description || '').substring(0, 200));
    return `${attackVector}:${titleHash}:${descHash}`;
  }

  /**
   * Simple string hash for cache keys
   */
  simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  }

  /**
   * Normalize attack vector for API queries
   */
  normalizeAttackVector(vector) {
    if (!vector) return 'unknown';
    return vector.toLowerCase()
      .replace(/[^a-z0-9-]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  }

  /**
   * Extract keywords from a finding for search
   */
  extractKeywords(finding) {
    const keywords = new Set();

    // Extract from attack vector
    const vector = finding.attackVector || '';
    if (vector) {
      vector.split(/[-_\s]/).forEach(w => {
        if (w.length > 2) keywords.add(w.toLowerCase());
      });
    }

    // Extract from title
    const title = finding.title || '';
    title.split(/[\s\-_()]+/).forEach(w => {
      const cleaned = w.toLowerCase().replace(/[^a-z0-9]/g, '');
      if (cleaned.length > 3) keywords.add(cleaned);
    });

    // Extract from description (first 500 chars)
    const desc = (finding.description || '').substring(0, 500);
    const descWords = desc.match(/\b[a-zA-Z]{4,}\b/g) || [];
    descWords.slice(0, 20).forEach(w => keywords.add(w.toLowerCase()));

    // Add known DeFi terms if present
    const defiTerms = ['vault', 'pool', 'swap', 'stake', 'lending', 'borrow',
                       'collateral', 'liquidat', 'oracle', 'price', 'flash',
                       'permit', 'approve', 'transfer', 'mint', 'burn'];
    defiTerms.forEach(term => {
      if (desc.toLowerCase().includes(term)) {
        keywords.add(term);
      }
    });

    return Array.from(keywords).slice(0, 15);
  }

  /**
   * Identify root cause from finding
   */
  identifyRootCause(finding) {
    const combined = `${finding.title || ''} ${finding.description || ''}`.toLowerCase();

    for (const [cause, pattern] of Object.entries(ROOT_CAUSE_PATTERNS)) {
      if (pattern.test(combined)) {
        return cause;
      }
    }

    return 'unknown';
  }

  /**
   * Extract code pattern signature for matching
   */
  extractCodePattern(finding) {
    const code = finding.code || '';
    const patterns = [];

    // Detect common vulnerable patterns
    if (/\.call\{.*value/.test(code)) patterns.push('external-call-with-value');
    if (/\.call\(/.test(code)) patterns.push('low-level-call');
    if (/delegatecall/.test(code)) patterns.push('delegatecall');
    if (/selfdestruct/.test(code)) patterns.push('selfdestruct');
    if (/tx\.origin/.test(code)) patterns.push('tx-origin');
    if (/ecrecover/.test(code)) patterns.push('ecrecover');
    if (/balanceOf/.test(code) && /\.call/.test(code)) patterns.push('balance-based-logic');
    if (/block\.timestamp/.test(code)) patterns.push('timestamp-dependent');
    if (/msg\.sender/.test(code) && !/require|modifier/.test(code)) patterns.push('unprotected-sender');

    return patterns;
  }

  /**
   * Make HTTP request to Solodit API
   */
  async makeRequest(endpoint, method = 'GET', body = null) {
    return new Promise((resolve, reject) => {
      const url = new URL(endpoint, this.baseUrl);
      const isHttps = url.protocol === 'https:';
      const httpModule = isHttps ? https : http;

      const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: method,
        headers: {
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'User-Agent': 'Web3CRIT-Scanner/6.0.0'
        },
        timeout: this.timeout
      };

      const req = httpModule.request(options, (res) => {
        let data = '';

        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(data));
            } catch (e) {
              reject(new Error(`Invalid JSON response: ${e.message}`));
            }
          } else if (res.statusCode === 401) {
            reject(new Error('Solodit API authentication failed - check API key'));
          } else if (res.statusCode === 429) {
            reject(new Error('Solodit API rate limit exceeded'));
          } else {
            reject(new Error(`Solodit API error: ${res.statusCode} ${res.statusMessage}`));
          }
        });
      });

      req.on('error', (e) => reject(e));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Solodit API request timeout'));
      });

      if (body) {
        req.write(JSON.stringify(body));
      }

      req.end();
    });
  }

  /**
   * Search Solodit for similar vulnerabilities
   * Uses API when available, falls back to offline knowledge base
   */
  async searchVulnerabilities(finding, retryCount = 0) {
    const attackVector = this.normalizeAttackVector(finding.attackVector || finding.detector);
    const categories = VULN_TYPE_TO_SOLODIT_CATEGORY[attackVector] || [attackVector];
    const keywords = this.extractKeywords(finding);
    const rootCause = this.identifyRootCause(finding);
    const codePatterns = this.extractCodePattern(finding);

    this.stats.queriesTotal++;

    // Use offline matcher if in offline mode
    if (this.offlineMode) {
      this.log('info', `Offline search for: ${attackVector}`);
      const results = this.offlineMatcher.search(finding, categories, keywords, rootCause, codePatterns);
      this.stats.queriesSuccessful++;
      return results;
    }

    // Online API query
    const query = {
      categories: categories,
      keywords: keywords,
      rootCause: rootCause,
      codePatterns: codePatterns,
      severity: finding.severity,
      limit: 10
    };

    try {
      const response = await this.makeRequest('/vulnerabilities/search', 'POST', query);
      this.stats.queriesSuccessful++;
      return response;
    } catch (error) {
      if (retryCount < this.maxRetries) {
        this.log('warn', `Retry ${retryCount + 1}/${this.maxRetries}: ${error.message}`);
        await this.sleep(1000 * (retryCount + 1)); // Exponential backoff
        return this.searchVulnerabilities(finding, retryCount + 1);
      }

      // Fall back to offline mode on API failure
      this.log('warn', `API failed, falling back to offline mode: ${error.message}`);
      this.stats.queriesFailed++;
      const offlineResults = this.offlineMatcher.search(finding, categories, keywords, rootCause, codePatterns);
      return offlineResults;
    }
  }

  /**
   * Calculate match confidence between finding and Solodit result
   */
  calculateMatchConfidence(finding, soloditResult) {
    let confidence = 0;
    let matchReasons = [];

    // Category match (0-25 points)
    const findingCategories = VULN_TYPE_TO_SOLODIT_CATEGORY[
      this.normalizeAttackVector(finding.attackVector)
    ] || [];
    const resultCategories = soloditResult.categories || [];
    const categoryOverlap = findingCategories.filter(c =>
      resultCategories.some(rc => rc.toLowerCase().includes(c.toLowerCase()))
    );
    if (categoryOverlap.length > 0) {
      confidence += Math.min(25, categoryOverlap.length * 10);
      matchReasons.push(`category match: ${categoryOverlap.join(', ')}`);
    }

    // Root cause match (0-25 points)
    const findingRootCause = this.identifyRootCause(finding);
    const resultRootCause = (soloditResult.rootCause || '').toLowerCase();
    if (findingRootCause !== 'unknown' && resultRootCause.includes(findingRootCause.replace(/-/g, ' '))) {
      confidence += 25;
      matchReasons.push(`root cause match: ${findingRootCause}`);
    }

    // Keyword overlap (0-20 points)
    const findingKeywords = this.extractKeywords(finding);
    const resultKeywords = (soloditResult.keywords || []).map(k => k.toLowerCase());
    const keywordOverlap = findingKeywords.filter(k =>
      resultKeywords.some(rk => rk.includes(k) || k.includes(rk))
    );
    if (keywordOverlap.length > 0) {
      confidence += Math.min(20, keywordOverlap.length * 4);
      matchReasons.push(`keyword overlap: ${keywordOverlap.length} terms`);
    }

    // Code pattern match (0-20 points)
    const findingPatterns = this.extractCodePattern(finding);
    const resultPatterns = soloditResult.codePatterns || [];
    const patternOverlap = findingPatterns.filter(p =>
      resultPatterns.some(rp => rp.toLowerCase().includes(p.toLowerCase()))
    );
    if (patternOverlap.length > 0) {
      confidence += Math.min(20, patternOverlap.length * 10);
      matchReasons.push(`code pattern match: ${patternOverlap.join(', ')}`);
    }

    // Severity alignment (0-10 points)
    const severityMap = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
    const findingSev = severityMap[finding.severity] || 0;
    const resultSev = severityMap[soloditResult.severity?.toUpperCase()] || 0;
    if (Math.abs(findingSev - resultSev) <= 1) {
      confidence += 10;
      matchReasons.push('severity aligned');
    }

    return {
      score: Math.min(100, confidence),
      normalized: Math.min(1, confidence / 100),
      reasons: matchReasons
    };
  }

  /**
   * Determine if finding is "confirmed in the wild" based on Solodit matches
   */
  determineValidationStatus(finding, matches, topMatchConfidence) {
    // Confirmed in the wild: high confidence match with real exploit
    if (topMatchConfidence >= 0.7 && matches.some(m => m.exploited === true)) {
      return {
        status: 'confirmed_in_wild',
        label: 'Confirmed in the Wild',
        description: 'Similar vulnerability exploited in production',
        confidence: topMatchConfidence
      };
    }

    // Confirmed pattern: high confidence match with disclosed bug
    if (topMatchConfidence >= 0.6 && matches.length > 0) {
      return {
        status: 'confirmed_pattern',
        label: 'Confirmed Pattern',
        description: 'Matches known vulnerability pattern from audits',
        confidence: topMatchConfidence
      };
    }

    // Likely valid: medium confidence match
    if (topMatchConfidence >= 0.4 && matches.length > 0) {
      return {
        status: 'likely_valid',
        label: 'Likely Valid',
        description: 'Similar to known vulnerabilities',
        confidence: topMatchConfidence
      };
    }

    // Theoretical: no strong matches
    return {
      status: 'theoretical',
      label: 'Theoretical',
      description: 'No strong matches in vulnerability database',
      confidence: topMatchConfidence
    };
  }

  /**
   * Enrich a single finding with Solodit data
   */
  async enrichFinding(finding) {
    // Check cache first
    const cacheKey = this.generateCacheKey(finding);
    const cached = this.getFromCache(cacheKey);
    if (cached !== null) {
      this.log('info', `Cache hit for ${finding.title}`);
      return { ...finding, soloditMetadata: cached };
    }

    // Search Solodit
    const searchResults = await this.searchVulnerabilities(finding);

    if (!searchResults || !searchResults.results || searchResults.results.length === 0) {
      // No matches found
      const metadata = {
        matched: false,
        validationStatus: this.determineValidationStatus(finding, [], 0),
        searchedAt: new Date().toISOString(),
        matchConfidence: 0
      };
      this.setCache(cacheKey, metadata);
      this.stats.theoretical++;
      return { ...finding, soloditMetadata: metadata };
    }

    // Calculate confidence for each match
    const scoredMatches = searchResults.results.map(result => {
      const confidence = this.calculateMatchConfidence(finding, result);
      return { ...result, matchConfidence: confidence };
    });

    // Sort by confidence
    scoredMatches.sort((a, b) => b.matchConfidence.score - a.matchConfidence.score);

    // Get top match
    const topMatch = scoredMatches[0];
    const topConfidence = topMatch.matchConfidence.normalized;

    // Filter to only include matches above threshold
    const relevantMatches = scoredMatches.filter(
      m => m.matchConfidence.normalized >= this.minConfidenceThreshold
    );

    // Determine validation status
    const validationStatus = this.determineValidationStatus(finding, relevantMatches, topConfidence);

    // Build enrichment metadata
    const metadata = {
      matched: relevantMatches.length > 0,
      matchConfidence: topConfidence,
      validationStatus: validationStatus,
      topMatch: relevantMatches.length > 0 ? {
        id: topMatch.id,
        title: topMatch.title,
        protocol: topMatch.protocol,
        severity: topMatch.severity,
        exploited: topMatch.exploited || false,
        bountyAmount: topMatch.bountyAmount,
        disclosedAt: topMatch.disclosedAt,
        references: (topMatch.references || []).slice(0, 3),
        matchReasons: topMatch.matchConfidence.reasons
      } : null,
      similarFindings: relevantMatches.slice(1, 4).map(m => ({
        id: m.id,
        title: m.title,
        protocol: m.protocol,
        confidence: m.matchConfidence.normalized
      })),
      realWorldExploits: relevantMatches
        .filter(m => m.exploited === true)
        .slice(0, 3)
        .map(m => ({
          id: m.id,
          title: m.title,
          protocol: m.protocol,
          lossAmount: m.lossAmount,
          exploitDate: m.exploitDate
        })),
      relatedAudits: relevantMatches
        .filter(m => m.source === 'audit')
        .slice(0, 3)
        .map(m => ({
          id: m.id,
          title: m.title,
          auditor: m.auditor,
          protocol: m.protocol
        })),
      searchedAt: new Date().toISOString()
    };

    // Update stats
    this.stats.findingsEnriched++;
    if (validationStatus.status === 'confirmed_in_wild') {
      this.stats.confirmedInWild++;
    } else if (validationStatus.status === 'theoretical') {
      this.stats.theoretical++;
    }

    // Cache the result
    this.setCache(cacheKey, metadata);

    return { ...finding, soloditMetadata: metadata };
  }

  /**
   * Enrich all findings with Solodit data
   */
  async enrichFindings(findings) {
    if (!this.enabled) {
      this.log('info', 'Solodit enrichment disabled (no API key or explicitly disabled)');
      return findings;
    }

    if (!findings || findings.length === 0) {
      return findings;
    }

    this.log('info', `Enriching ${findings.length} findings with Solodit data...`);

    const enriched = [];

    // Process findings with rate limiting
    for (let i = 0; i < findings.length; i++) {
      const finding = findings[i];

      try {
        const enrichedFinding = await this.enrichFinding(finding);
        enriched.push(enrichedFinding);

        // Rate limiting: small delay between API calls
        if (i < findings.length - 1 && !this.isCacheValid(this.generateCacheKey(findings[i + 1]))) {
          await this.sleep(200); // 200ms between uncached requests
        }
      } catch (error) {
        this.log('error', `Failed to enrich finding "${finding.title}": ${error.message}`);
        // Add finding without enrichment on error
        enriched.push(finding);
      }
    }

    this.log('info', `Enrichment complete. Stats: ${JSON.stringify(this.stats)}`);

    return enriched;
  }

  /**
   * Get enrichment statistics
   */
  getStats() {
    return {
      ...this.stats,
      cacheSize: this.cache.size,
      enabled: this.enabled,
      offlineMode: this.offlineMode,
      knowledgeBaseSize: this.offlineMode ? OFFLINE_EXPLOIT_DATABASE.length : null
    };
  }

  /**
   * Clear cache
   */
  clearCache() {
    this.cache.clear();
    this.cacheTimestamps.clear();
  }

  /**
   * Sleep utility
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Test API connectivity
   */
  async testConnection() {
    if (!this.enabled) {
      return { success: false, error: 'Solodit enrichment not enabled' };
    }

    try {
      const response = await this.makeRequest('/health', 'GET');
      return { success: true, response };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }
}

/**
 * Solodit Finding Formatter
 * Formats enriched findings for display
 */
class SoloditFormatter {
  /**
   * Format validation status badge
   */
  static formatValidationBadge(metadata) {
    if (!metadata || !metadata.validationStatus) {
      return '[UNKNOWN]';
    }

    const status = metadata.validationStatus;
    switch (status.status) {
      case 'confirmed_in_wild':
        return `[CONFIRMED IN WILD - ${Math.round(status.confidence * 100)}%]`;
      case 'confirmed_pattern':
        return `[CONFIRMED PATTERN - ${Math.round(status.confidence * 100)}%]`;
      case 'likely_valid':
        return `[LIKELY VALID - ${Math.round(status.confidence * 100)}%]`;
      case 'theoretical':
        return `[THEORETICAL]`;
      default:
        return `[UNKNOWN]`;
    }
  }

  /**
   * Format Solodit metadata for CLI output
   */
  static formatForCLI(metadata) {
    if (!metadata || !metadata.matched) {
      return null;
    }

    const lines = [];

    // Validation status
    lines.push(`  Solodit: ${this.formatValidationBadge(metadata)}`);

    // Top match
    if (metadata.topMatch) {
      lines.push(`  Best Match: "${metadata.topMatch.title}" (${metadata.topMatch.protocol})`);
      if (metadata.topMatch.exploited) {
        lines.push(`    - EXPLOITED in production`);
      }
      if (metadata.topMatch.bountyAmount) {
        lines.push(`    - Bounty: $${metadata.topMatch.bountyAmount.toLocaleString()}`);
      }
    }

    // Real-world exploits
    if (metadata.realWorldExploits && metadata.realWorldExploits.length > 0) {
      lines.push(`  Related Exploits:`);
      metadata.realWorldExploits.forEach(exp => {
        const loss = exp.lossAmount ? ` ($${exp.lossAmount.toLocaleString()} loss)` : '';
        lines.push(`    - ${exp.protocol}: ${exp.title}${loss}`);
      });
    }

    return lines.join('\n');
  }

  /**
   * Format Solodit metadata for JSON report
   */
  static formatForReport(metadata) {
    if (!metadata) {
      return null;
    }

    return {
      validationStatus: metadata.validationStatus?.label || 'Unknown',
      matchConfidence: metadata.matchConfidence,
      confirmedInWild: metadata.validationStatus?.status === 'confirmed_in_wild',
      topMatch: metadata.topMatch ? {
        title: metadata.topMatch.title,
        protocol: metadata.topMatch.protocol,
        exploited: metadata.topMatch.exploited,
        bountyAmount: metadata.topMatch.bountyAmount,
        references: metadata.topMatch.references
      } : null,
      realWorldExploits: metadata.realWorldExploits || [],
      relatedAudits: metadata.relatedAudits || [],
      similarFindings: metadata.similarFindings || []
    };
  }
}

module.exports = SoloditEnricher;
module.exports.SoloditFormatter = SoloditFormatter;
module.exports.OfflineVulnerabilityMatcher = OfflineVulnerabilityMatcher;
module.exports.VULN_TYPE_TO_SOLODIT_CATEGORY = VULN_TYPE_TO_SOLODIT_CATEGORY;
module.exports.OFFLINE_EXPLOIT_DATABASE = OFFLINE_EXPLOIT_DATABASE;
