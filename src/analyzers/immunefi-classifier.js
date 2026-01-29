/**
 * Immunefi Severity Classifier
 * Maps vulnerability findings to Immunefi bug bounty payout categories
 * Only reports findings that qualify for High/Critical payouts
 *
 * Immunefi Severity Levels:
 * - Critical: Direct theft of funds, permanent freezing, protocol insolvency, governance takeover
 * - High: Theft of unclaimed yield, temporary freezing, griefing with capital requirements
 * - Medium/Low: Filtered out for high-TVL focus
 */

const IMMUNEFI_CATEGORIES = {
  CRITICAL: {
    DIRECT_THEFT: {
      id: 'direct-theft',
      name: 'Direct Theft of Funds',
      description: 'Attacker can steal user deposits, protocol reserves, or treasury funds',
      minScore: 90,
      requiredElements: ['value_extraction', 'no_auth_bypass_needed_OR_auth_bypass_present']
    },
    PERMANENT_FREEZE: {
      id: 'permanent-freeze',
      name: 'Permanent Freezing of Funds',
      description: 'Funds become permanently inaccessible (not temporary DoS)',
      minScore: 85,
      requiredElements: ['fund_lock', 'no_recovery_path']
    },
    PROTOCOL_INSOLVENCY: {
      id: 'protocol-insolvency',
      name: 'Protocol Insolvency',
      description: 'Protocol becomes unable to honor withdrawals or obligations',
      minScore: 90,
      requiredElements: ['accounting_manipulation', 'systemic_impact']
    },
    GOVERNANCE_TAKEOVER: {
      id: 'governance-takeover',
      name: 'Governance Takeover',
      description: 'Attacker gains control of protocol governance/admin functions',
      minScore: 85,
      requiredElements: ['admin_access', 'persistent_control']
    },
    UNAUTHORIZED_MINTING: {
      id: 'unauthorized-minting',
      name: 'Unauthorized Token Minting',
      description: 'Attacker can mint tokens without proper authorization',
      minScore: 90,
      requiredElements: ['mint_capability', 'value_extraction']
    }
  },
  HIGH: {
    YIELD_THEFT: {
      id: 'yield-theft',
      name: 'Theft of Unclaimed Yield',
      description: 'Attacker can steal yield/rewards that belong to other users',
      minScore: 75,
      requiredElements: ['yield_extraction', 'other_user_impact']
    },
    TEMPORARY_FREEZE: {
      id: 'temporary-freeze',
      name: 'Temporary Freezing of Funds',
      description: 'Funds locked temporarily but recoverable (DoS with fund impact)',
      minScore: 70,
      requiredElements: ['fund_lock', 'recovery_possible']
    },
    MANIPULATION_PROFIT: {
      id: 'manipulation-profit',
      name: 'Price/State Manipulation for Profit',
      description: 'Attacker profits by manipulating prices or protocol state',
      minScore: 75,
      requiredElements: ['state_manipulation', 'profit_extraction']
    },
    PRIVILEGE_ESCALATION: {
      id: 'privilege-escalation',
      name: 'Privilege Escalation',
      description: 'Attacker gains elevated permissions without authorization',
      minScore: 70,
      requiredElements: ['auth_bypass', 'elevated_access']
    }
  }
};

// Maps vulnerability types to potential Immunefi categories
const VULNERABILITY_TO_CATEGORY_MAP = {
  // Reentrancy variants
  'reentrancy': ['DIRECT_THEFT', 'PROTOCOL_INSOLVENCY'],
  'cross-function-reentrancy': ['DIRECT_THEFT', 'PROTOCOL_INSOLVENCY'],
  'cross-contract-reentrancy': ['DIRECT_THEFT', 'PROTOCOL_INSOLVENCY'],
  'read-only-reentrancy': ['MANIPULATION_PROFIT'],

  // Access control (multiple name variants)
  'access-control': ['DIRECT_THEFT', 'GOVERNANCE_TAKEOVER', 'UNAUTHORIZED_MINTING'],
  'missing-access-control': ['DIRECT_THEFT', 'GOVERNANCE_TAKEOVER', 'UNAUTHORIZED_MINTING'],
  'broken-access-control': ['DIRECT_THEFT', 'GOVERNANCE_TAKEOVER'],
  'tx-origin': ['DIRECT_THEFT', 'PRIVILEGE_ESCALATION'],

  // Oracle/Price manipulation
  'flash-loan': ['DIRECT_THEFT', 'PROTOCOL_INSOLVENCY', 'MANIPULATION_PROFIT'],
  'flash-loan-oracle': ['DIRECT_THEFT', 'PROTOCOL_INSOLVENCY', 'MANIPULATION_PROFIT'],
  'flash-loan-oracle-manipulation': ['DIRECT_THEFT', 'PROTOCOL_INSOLVENCY'],
  'flash-loan-balance-manipulation': ['DIRECT_THEFT', 'MANIPULATION_PROFIT'],
  'flash-loan-governance': ['GOVERNANCE_TAKEOVER'],
  'balance-manipulation': ['DIRECT_THEFT', 'MANIPULATION_PROFIT'],
  'spot-price-manipulation': ['DIRECT_THEFT', 'MANIPULATION_PROFIT'],
  'oracle-manipulation': ['DIRECT_THEFT', 'MANIPULATION_PROFIT'],
  'stale-price': ['MANIPULATION_PROFIT', 'DIRECT_THEFT'],
  'stale-price-exploitation': ['MANIPULATION_PROFIT', 'DIRECT_THEFT'],

  // Proxy/Upgrade
  'unprotected-initializer': ['GOVERNANCE_TAKEOVER', 'DIRECT_THEFT'],
  'unauthorized-upgrade': ['GOVERNANCE_TAKEOVER', 'DIRECT_THEFT'],
  'storage-collision': ['DIRECT_THEFT', 'PROTOCOL_INSOLVENCY'],
  'proxy': ['GOVERNANCE_TAKEOVER', 'DIRECT_THEFT'],

  // Signature/Replay
  'signature-replay': ['DIRECT_THEFT', 'PRIVILEGE_ESCALATION'],
  'permit-dos': ['TEMPORARY_FREEZE'],
  'permit-replay': ['DIRECT_THEFT'],
  'missing-deadline': ['MANIPULATION_PROFIT'],

  // Fund handling
  'unchecked-call': ['DIRECT_THEFT', 'PERMANENT_FREEZE'],
  'unchecked-transfer': ['DIRECT_THEFT'],
  'delegatecall': ['DIRECT_THEFT', 'GOVERNANCE_TAKEOVER'],
  'delegatecall-injection': ['DIRECT_THEFT', 'GOVERNANCE_TAKEOVER'],
  'selfdestruct': ['PERMANENT_FREEZE', 'DIRECT_THEFT'],

  // TOCTOU
  'toctou': ['DIRECT_THEFT', 'MANIPULATION_PROFIT'],

  // DeFi specific
  'vault-inflation': ['DIRECT_THEFT', 'YIELD_THEFT'],
  'share-manipulation': ['DIRECT_THEFT', 'YIELD_THEFT'],
  'first-depositor': ['DIRECT_THEFT'],
  'first-depositor-inflation': ['DIRECT_THEFT'],
  'donation-attack': ['MANIPULATION_PROFIT', 'YIELD_THEFT'],
  'sandwich-donation': ['MANIPULATION_PROFIT'],
  'rounding-exploit': ['YIELD_THEFT'],

  // Governance
  'governance': ['GOVERNANCE_TAKEOVER'],
  'governance-reentrancy': ['GOVERNANCE_TAKEOVER'],

  // Fallback for unknown (still try to classify based on elements)
  'unknown': ['DIRECT_THEFT', 'MANIPULATION_PROFIT']
};

class ImmunefiClassifier {
  constructor() {
    this.categories = IMMUNEFI_CATEGORIES;
    this.vulnMap = VULNERABILITY_TO_CATEGORY_MAP;
  }

  /**
   * Classify a finding into Immunefi payout category
   * Returns null if finding doesn't qualify for High/Critical
   */
  classifyFinding(finding) {
    const attackVector = this.normalizeAttackVector(finding.attackVector || finding.detector);
    const potentialCategories = this.vulnMap[attackVector] || [];

    if (potentialCategories.length === 0) {
      return null; // No mapping, doesn't qualify
    }

    // Analyze finding for exploit chain elements
    const exploitElements = this.analyzeExploitElements(finding);

    // Try to match to highest severity category first
    for (const categoryId of potentialCategories) {
      const category = this.findCategory(categoryId);
      if (!category) continue;

      const match = this.matchCategory(finding, category, exploitElements);
      if (match.qualifies) {
        return {
          severity: this.getCategorySeverity(categoryId),
          category: category,
          categoryId: categoryId,
          exploitChain: match.exploitChain,
          confidence: match.confidence,
          payoutTier: this.getCategorySeverity(categoryId) === 'CRITICAL' ? 'Critical' : 'High',
          impactDescription: this.generateImpactDescription(category, finding, match)
        };
      }
    }

    return null; // Doesn't qualify for High/Critical
  }

  /**
   * Analyze finding for exploit chain elements
   */
  analyzeExploitElements(finding) {
    const elements = new Set();
    const desc = (finding.description || '').toLowerCase();
    const title = (finding.title || '').toLowerCase();
    const combined = desc + ' ' + title;

    // Value extraction indicators
    if (/drain|steal|extract|profit|arbitrage|theft/.test(combined)) {
      elements.add('value_extraction');
    }
    if (/transfer|withdraw|claim|redeem/.test(combined)) {
      elements.add('value_extraction');
    }

    // Auth bypass indicators
    if (/no.*access.*control|missing.*modifier|bypass|unauthorized/.test(combined)) {
      elements.add('auth_bypass');
      elements.add('auth_bypass_present');
    }
    // High confidence exploitable = no auth bypass needed (directly callable)
    if (finding.exploitable === true && finding.confidence === 'HIGH') {
      elements.add('no_auth_bypass_needed');
    }
    // Also support reentrant attacks that don't need auth bypass
    if (/reentran|drain|steal|exploit/.test(combined) && finding.exploitable === true) {
      elements.add('no_auth_bypass_needed');
    }

    // Fund lock indicators
    if (/lock|freeze|stuck|inaccessible|brick/.test(combined)) {
      elements.add('fund_lock');
    }
    if (/permanent|forever|irrecoverable|destroy/.test(combined)) {
      elements.add('no_recovery_path');
    }
    if (/temporary|dos|delay|block/.test(combined)) {
      elements.add('recovery_possible');
    }

    // Accounting manipulation
    if (/inflation|deflation|accounting|balance.*manipul|share.*manipul/.test(combined)) {
      elements.add('accounting_manipulation');
    }
    if (/insolvency|insolvent|undercollateral/.test(combined)) {
      elements.add('systemic_impact');
    }

    // Admin/Governance
    if (/owner|admin|governance|upgrade|initializ/.test(combined)) {
      elements.add('admin_access');
    }
    if (/takeover|control|persist|permanent.*access/.test(combined)) {
      elements.add('persistent_control');
    }
    if (/elevat|escalat|privilege/.test(combined)) {
      elements.add('elevated_access');
    }

    // Minting
    if (/mint|create.*token|issue.*token/.test(combined)) {
      elements.add('mint_capability');
    }

    // Yield/Rewards
    if (/yield|reward|interest|dividend|fee/.test(combined)) {
      elements.add('yield_extraction');
    }
    if (/other.*user|victim|deposit/.test(combined)) {
      elements.add('other_user_impact');
    }

    // State manipulation
    if (/manipulat|flash.*loan|oracle|price|state/.test(combined)) {
      elements.add('state_manipulation');
    }
    if (/profit|gain|extract|arbitrage/.test(combined)) {
      elements.add('profit_extraction');
    }

    return elements;
  }

  /**
   * Match finding against category requirements
   */
  matchCategory(finding, category, exploitElements) {
    const required = category.requiredElements || [];
    const matched = [];
    const missing = [];

    for (const element of required) {
      // Handle OR conditions (element1_OR_element2)
      if (element.includes('_OR_')) {
        const alternatives = element.split('_OR_');
        const hasAny = alternatives.some(alt => exploitElements.has(alt));
        if (hasAny) {
          matched.push(element);
        } else {
          missing.push(element);
        }
      } else {
        if (exploitElements.has(element)) {
          matched.push(element);
        } else {
          missing.push(element);
        }
      }
    }

    // Calculate match quality
    const matchRatio = required.length > 0 ? matched.length / required.length : 0;
    const scoreThreshold = category.minScore || 70;
    const findingScore = finding.exploitabilityScore || 50;

    // Qualifies if:
    // 1. All required elements present OR high match ratio with high score
    // 2. Finding score meets minimum threshold
    const qualifies = (
      (missing.length === 0 || (matchRatio >= 0.7 && findingScore >= 80)) &&
      findingScore >= scoreThreshold &&
      finding.exploitable !== false
    );

    return {
      qualifies,
      matchedElements: matched,
      missingElements: missing,
      matchRatio,
      confidence: this.calculateConfidence(matchRatio, finding),
      exploitChain: this.buildExploitChain(finding, category, exploitElements)
    };
  }

  /**
   * Build concrete exploit chain description
   */
  buildExploitChain(finding, category, elements) {
    const chain = {
      attackerCapabilities: this.inferAttackerCapabilities(finding, elements),
      entryPoint: this.extractEntryPoint(finding),
      vulnerableOperation: this.extractVulnerableOp(finding),
      impact: category.description,
      profitMechanism: this.inferProfitMechanism(finding, elements),
      steps: []
    };

    // Build step-by-step exploit
    const attackVector = (finding.attackVector || '').toLowerCase();

    if (attackVector.includes('reentrancy')) {
      chain.steps = [
        'Attacker deploys malicious contract with fallback/receive function',
        `Attacker calls ${chain.entryPoint || 'vulnerable function'}`,
        'Vulnerable contract makes external call to attacker',
        'Attacker reenters before state update completes',
        'Attacker drains funds through repeated reentry',
        'State finally updates but funds already extracted'
      ];
    } else if (attackVector.includes('flash-loan') || attackVector.includes('oracle')) {
      chain.steps = [
        'Attacker obtains flash loan (Aave/dYdX/Balancer)',
        'Attacker manipulates price oracle (large swap/donation)',
        `Attacker calls ${chain.entryPoint || 'vulnerable function'} at manipulated price`,
        'Attacker extracts value at favorable rate',
        'Attacker reverses manipulation (swap back)',
        'Attacker repays flash loan, keeps profit'
      ];
    } else if (attackVector.includes('access-control')) {
      chain.steps = [
        'Attacker identifies unprotected privileged function',
        `Attacker calls ${chain.entryPoint || 'admin function'} directly`,
        'Function executes without authorization check',
        chain.profitMechanism || 'Attacker gains unauthorized access/funds'
      ];
    } else if (attackVector.includes('initializer')) {
      chain.steps = [
        'Attacker identifies uninitialized proxy or reinitializable contract',
        'Attacker calls initialize() with attacker-controlled parameters',
        'Attacker sets themselves as owner/admin',
        'Attacker uses admin privileges to drain funds or upgrade maliciously'
      ];
    } else if (attackVector.includes('signature') || attackVector.includes('replay')) {
      chain.steps = [
        'Attacker obtains valid signature from previous transaction',
        'Attacker replays signature (missing nonce/deadline/chainId)',
        `Signature validates and executes ${chain.entryPoint || 'privileged action'}`,
        'Attacker profits from unauthorized repeated execution'
      ];
    } else {
      chain.steps = [
        `Identify vulnerable operation in ${chain.entryPoint || 'target function'}`,
        'Prepare attack transaction',
        'Execute exploit',
        'Extract value or gain unauthorized access'
      ];
    }

    return chain;
  }

  /**
   * Infer required attacker capabilities
   */
  inferAttackerCapabilities(finding, elements) {
    const capabilities = [];
    const desc = (finding.description || '').toLowerCase();

    if (elements.has('state_manipulation') || /flash.*loan|manipulat/.test(desc)) {
      capabilities.push('Flash loan access (Aave, dYdX, Balancer)');
    }
    if (/mev|sandwich|frontrun/.test(desc)) {
      capabilities.push('MEV infrastructure (Flashbots, private mempool)');
    }
    if (/reentran/.test(desc)) {
      capabilities.push('Ability to deploy malicious contract');
    }
    if (capabilities.length === 0) {
      capabilities.push('Standard EOA with gas');
    }

    return capabilities;
  }

  extractEntryPoint(finding) {
    let loc = finding.location || '';
    if (typeof loc !== 'string') {
      loc = String(loc) || '';
    }
    const funcMatch = loc.match(/Function:\s*(\w+)/);
    return funcMatch ? funcMatch[1] + '()' : null;
  }

  extractVulnerableOp(finding) {
    return finding.title || finding.detector;
  }

  inferProfitMechanism(finding, elements) {
    if (elements.has('value_extraction')) {
      return 'Direct fund extraction via vulnerable function';
    }
    if (elements.has('yield_extraction')) {
      return 'Theft of accumulated yield/rewards';
    }
    if (elements.has('profit_extraction')) {
      return 'Arbitrage profit from price manipulation';
    }
    if (elements.has('mint_capability')) {
      return 'Minting tokens and selling on market';
    }
    return 'Unauthorized value extraction';
  }

  calculateConfidence(matchRatio, finding) {
    const baseConfidence = finding.confidence === 'HIGH' ? 0.9 :
                          finding.confidence === 'MEDIUM' ? 0.7 : 0.5;
    return Math.min(1, baseConfidence * (0.5 + matchRatio * 0.5));
  }

  findCategory(categoryId) {
    for (const severity of ['CRITICAL', 'HIGH']) {
      if (this.categories[severity][categoryId]) {
        return this.categories[severity][categoryId];
      }
    }
    return null;
  }

  getCategorySeverity(categoryId) {
    if (this.categories.CRITICAL[categoryId]) return 'CRITICAL';
    if (this.categories.HIGH[categoryId]) return 'HIGH';
    return 'MEDIUM';
  }

  normalizeAttackVector(vector) {
    if (!vector) return '';
    return vector.toLowerCase()
      .replace(/[^a-z0-9-]/g, '-')
      .replace(/-+/g, '-')
      .replace(/^-|-$/g, '');
  }

  generateImpactDescription(category, finding, match) {
    const entryPoint = this.extractEntryPoint(finding);
    const func = entryPoint || 'the vulnerable function';

    return `${category.name}: An attacker can exploit ${func} to ${category.description.toLowerCase()}. ` +
           `This qualifies as Immunefi ${this.getCategorySeverity(category.id) || 'High'} severity. ` +
           `Exploit confidence: ${Math.round(match.confidence * 100)}%.`;
  }

  /**
   * Filter findings to only Immunefi High/Critical
   */
  filterToPayoutLevel(findings) {
    const qualified = [];

    for (const finding of findings) {
      const classification = this.classifyFinding(finding);

      if (classification) {
        qualified.push({
          ...finding,
          immunefiClassification: classification,
          severity: classification.severity, // Upgrade severity based on classification
          payoutTier: classification.payoutTier,
          exploitChain: classification.exploitChain
        });
      }
    }

    // Sort by severity then by exploitability score
    qualified.sort((a, b) => {
      const sevOrder = { 'CRITICAL': 2, 'HIGH': 1 };
      const sevDiff = (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0);
      if (sevDiff !== 0) return sevDiff;
      return (b.exploitabilityScore || 0) - (a.exploitabilityScore || 0);
    });

    return qualified;
  }
}

module.exports = ImmunefiClassifier;
