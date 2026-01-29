/**
 * Base Detector Class (Enhanced)
 * Provides foundation for all vulnerability detectors with:
 * - Exploitability scoring (0-100)
 * - Attack vector classification
 * - Foundry PoC support for high-confidence findings
 */
class BaseDetector {
  constructor(name, description, severity) {
    this.name = name;
    this.description = description;
    this.severity = severity;
    this.findings = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;

    // Traverse the AST
    this.traverse(ast);

    return this.findings;
  }

  traverse(node) {
    if (!node) return;

    // Visit the node
    const methodName = `visit${node.type}`;
    if (typeof this[methodName] === 'function') {
      this[methodName](node);
    }

    // Traverse children
    for (const key in node) {
      if (key === 'loc' || key === 'range') continue;

      const child = node[key];
      if (Array.isArray(child)) {
        child.forEach(c => this.traverse(c));
      } else if (child && typeof child === 'object' && child.type) {
        this.traverse(child);
      }
    }
  }

  /**
   * Add a vulnerability finding with enhanced classification
   *
   * @param {Object} vulnerability - Finding details
   * @param {string} vulnerability.title - Short title
   * @param {string} vulnerability.description - Detailed description
   * @param {string} vulnerability.severity - CRITICAL, HIGH, MEDIUM, LOW, INFO
   * @param {string} vulnerability.confidence - HIGH, MEDIUM, LOW
   * @param {boolean} vulnerability.exploitable - Is this realistically exploitable
   * @param {number} vulnerability.exploitabilityScore - 0-100 score (optional)
   * @param {string} vulnerability.attackVector - Attack classification (optional)
   * @param {string} vulnerability.foundryPoC - Foundry test code for high-confidence findings (optional)
   */
  addFinding(vulnerability) {
    // Calculate exploitability score if not provided
    const exploitabilityScore = vulnerability.exploitabilityScore ||
      this.calculateExploitabilityScore(vulnerability);

    // Determine if this is a high-confidence finding worthy of PoC
    const isHighConfidence = this.isHighConfidenceFinding(vulnerability, exploitabilityScore);

    this.findings.push({
      detector: this.name,
      severity: vulnerability.severity || this.severity,
      confidence: vulnerability.confidence || 'MEDIUM',
      exploitable: vulnerability.exploitable !== undefined ? vulnerability.exploitable : true,
      exploitabilityScore: exploitabilityScore,
      attackVector: vulnerability.attackVector || this.classifyAttackVector(vulnerability),
      title: vulnerability.title,
      description: vulnerability.description,
      location: vulnerability.location,
      fileName: this.fileName,
      line: vulnerability.line,
      column: vulnerability.column,
      code: vulnerability.code,
      recommendation: vulnerability.recommendation,
      references: vulnerability.references || [],
      // Only include PoC for high-confidence findings
      foundryPoC: isHighConfidence ? vulnerability.foundryPoC : undefined,
      isHighConfidence: isHighConfidence
    });
  }

  /**
   * Calculate exploitability score based on finding characteristics
   * Score: 0-100 where higher = more likely exploitable
   *
   * HARDENED: More aggressive scoring to filter noise
   * - Require HIGH confidence for high scores
   * - Penalize theoretical/best-practice issues
   * - Bonus for concrete attack vectors
   */
  calculateExploitabilityScore(vulnerability) {
    let score = 40; // Base score (lowered from 50)

    // Severity impact (unchanged)
    const severityScores = {
      'CRITICAL': 30,
      'HIGH': 20,
      'MEDIUM': 5,  // Reduced from 10
      'LOW': -10,   // Penalty
      'INFO': -30   // Stronger penalty
    };
    score += severityScores[vulnerability.severity] || 0;

    // Confidence impact (increased importance)
    const confidenceScores = {
      'HIGH': 25,   // Increased from 20
      'MEDIUM': 0,
      'LOW': -25    // Stronger penalty
    };
    score += confidenceScores[vulnerability.confidence] || 0;

    // Exploitable flag (stronger impact)
    if (vulnerability.exploitable === false) {
      score -= 40; // Increased penalty
    } else if (vulnerability.exploitable === true) {
      score += 10; // Bonus for confirmed exploitable
    }

    // Bonus for concrete attack vector (not 'unknown')
    if (vulnerability.attackVector && vulnerability.attackVector !== 'unknown') {
      score += 5;
    }

    // Bonus for having Foundry PoC
    if (vulnerability.foundryPoC) {
      score += 10;
    }

    // Clamp to 0-100
    return Math.max(0, Math.min(100, score));
  }

  /**
   * Determine if finding is high-confidence (worthy of PoC)
   */
  isHighConfidenceFinding(vulnerability, exploitabilityScore) {
    // Must have high confidence AND be exploitable AND score >= 70
    if (vulnerability.confidence !== 'HIGH') return false;
    if (vulnerability.exploitable === false) return false;
    if (exploitabilityScore < 70) return false;

    // CRITICAL or HIGH severity
    const highSeverity = ['CRITICAL', 'HIGH'].includes(vulnerability.severity);
    if (!highSeverity) return false;

    return true;
  }

  /**
   * Classify the attack vector based on finding characteristics
   */
  classifyAttackVector(vulnerability) {
    const title = (vulnerability.title || '').toLowerCase();
    const desc = (vulnerability.description || '').toLowerCase();
    const combined = title + ' ' + desc;

    // Attack vector classification
    const vectors = [
      { pattern: /reentrancy|reentrant/i, vector: 'reentrancy' },
      { pattern: /overflow|underflow/i, vector: 'integer-overflow' },
      { pattern: /flash.?loan|oracle.?manipul/i, vector: 'flash-loan' },
      { pattern: /front.?run|sandwich|mev/i, vector: 'frontrunning' },
      { pattern: /access.?control|unauthorized|permission/i, vector: 'access-control' },
      { pattern: /dos|denial|gas.?grief/i, vector: 'denial-of-service' },
      { pattern: /timestamp|block\.number/i, vector: 'timestamp-manipulation' },
      { pattern: /delegate.?call/i, vector: 'delegatecall' },
      { pattern: /selfdestruct|self.?destruct/i, vector: 'selfdestruct' },
      { pattern: /signature|replay/i, vector: 'signature-replay' },
      { pattern: /unchecked.?call|call.?return/i, vector: 'unchecked-call' }
    ];

    for (const { pattern, vector } of vectors) {
      if (pattern.test(combined)) {
        return vector;
      }
    }

    return 'unknown';
  }

  getCodeSnippet(loc) {
    if (!loc || !loc.start) return '';

    const startLine = loc.start.line - 1;
    const endLine = loc.end ? loc.end.line - 1 : startLine;

    return this.sourceLines.slice(
      Math.max(0, startLine),
      Math.min(this.sourceLines.length, endLine + 1)
    ).join('\n');
  }

  getLineContent(lineNumber) {
    if (lineNumber < 1 || lineNumber > this.sourceLines.length) return '';
    return this.sourceLines[lineNumber - 1];
  }
}

module.exports = BaseDetector;
