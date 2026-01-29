const parser = require('@solidity-parser/parser');
const fs = require('fs').promises;
const path = require('path');

// Import enhanced analyzers
const ControlFlowAnalyzer = require('./analyzers/control-flow');
const DataFlowAnalyzer = require('./analyzers/data-flow');

// Import Immunefi classifier and exploit chain modeler
const ImmunefiClassifier = require('./analyzers/immunefi-classifier');
const ExploitChainModeler = require('./analyzers/exploit-chain');
const PocValidator = require('./analyzers/poc-validator');
const SoloditEnricher = require('./analyzers/solodit-enricher');

// Import enhanced detectors only
const ReentrancyEnhancedDetector = require('./detectors/reentrancy-enhanced');
const AccessControlEnhancedDetector = require('./detectors/access-control-enhanced');

// Keep critical detectors that don't need enhancement
const UncheckedCallDetector = require('./detectors/unchecked-call');
const DelegateCallDetector = require('./detectors/delegatecall');
const UnprotectedSelfdestruct = require('./detectors/selfdestruct');

// Advanced Web3 vulnerability detectors
const IntegerOverflowDetector = require('./detectors/integer-overflow');
const FlashLoanDetector = require('./detectors/flash-loan');
const OracleManipulationDetector = require('./detectors/oracle-manipulation');
const FrontRunningDetector = require('./detectors/frontrunning');
const TimestampDependenceDetector = require('./detectors/timestamp-dependence');
const GasGriefingDetector = require('./detectors/gas-griefing');
const DeprecatedFunctionsDetector = require('./detectors/deprecated-functions');

// High-value TVL contract detectors
const ProxyVulnerabilitiesDetector = require('./detectors/proxy-vulnerabilities');
const SignatureReplayDetector = require('./detectors/signature-replay');
const CrossContractReentrancyDetector = require('./detectors/cross-contract-reentrancy');
const TokenStandardComplianceDetector = require('./detectors/token-standard-compliance');
const TOCTOUDetector = require('./detectors/toctou');

// Immunefi-tier detectors (NEW)
const GovernanceAttackDetector = require('./detectors/governance-attacks');
const ShareManipulationDetector = require('./detectors/share-manipulation');
const PermitExploitsDetector = require('./detectors/permit-exploits');

// Advanced high-TVL detectors (Production-grade)
const CallbackReentrancyDetector = require('./detectors/callback-reentrancy');
const RebasingTokenVaultDetector = require('./detectors/rebasing-token-vault');
const AdvancedPriceManipulationDetector = require('./detectors/price-manipulation-advanced');

/**
 * Enhanced Web3CRIT Scanner v6.0 (Production-Grade)
 * Top-tier exploit-driven scanner for high TVL contracts ($5M+)
 * Only reports findings that qualify for Immunefi High/Critical payouts
 *
 * PRODUCTION MODE RULES (--production flag):
 * - HIGH/CRITICAL only emitted if Foundry PoC compiles, executes, and proves impact
 * - Impact = fund drain, unauthorized transfer, role takeover, invariant break, or permanent DoS
 * - If PoC fails to compile, run, or show impact → discarded silently
 * - Severity derived from observed PoC results, not heuristics
 *
 * Features:
 * - Control flow and data flow analysis
 * - Immunefi severity classification
 * - Concrete exploit chain modeling
 * - Assumes adversarial capabilities (flash loans, MEV, malicious contracts)
 * - Foundry PoC execution with impact verification
 */
class Web3CRITScannerEnhanced {
  constructor(options = {}) {
    this.options = {
      verbose: options.verbose || false,
      severity: options.severity || 'all',
      outputFormat: options.outputFormat || 'json',
      onProgress: options.onProgress || null,
      // Exploit-driven mode (only Immunefi High/Critical)
      // Default OFF for backwards compatibility, use --immunefi flag to enable
      exploitDriven: options.exploitDriven || false,
      immunefiOnly: options.immunefiOnly || false, // Strict Immunefi mode
      // PRODUCTION MODE: Strict PoC gating for HIGH/CRITICAL
      productionMode: options.productionMode || false,
      // Foundry PoC validation
      pocValidate: options.pocValidate || false,
      pocRequirePass: options.pocRequirePass || false,
      pocMode: options.pocMode || 'test', // 'test' or 'build'
      foundryRoot: options.foundryRoot || null,
      pocKeepTemp: options.pocKeepTemp || false,
      forkUrl: options.forkUrl || null, // RPC URL for fork testing
      ...options
    };

    // In production mode, automatically enable exploit-driven and poc validation
    if (this.options.productionMode) {
      this.options.exploitDriven = true;
      this.options.immunefiOnly = true;
      this.options.pocValidate = true;
      this.options.pocRequirePass = true;
    }

    // Initialize Immunefi classifier
    this.immunefiClassifier = new ImmunefiClassifier();
    this.pocValidator = new PocValidator({
      enabled: this.options.pocValidate || this.options.productionMode,
      requirePass: this.options.pocRequirePass || this.options.productionMode,
      productionMode: this.options.productionMode || false,
      mode: this.options.pocMode || 'test',
      foundryRoot: this.options.foundryRoot || null,
      keepTemp: this.options.pocKeepTemp || false,
      forkUrl: this.options.forkUrl || null
    });

    // Initialize Solodit enricher for real-world vulnerability correlation
    this.soloditEnricher = new SoloditEnricher({
      apiKey: this.options.soloditApiKey || process.env.SOLODIT_API_KEY,
      baseUrl: this.options.soloditBaseUrl || process.env.SOLODIT_API_URL,
      enabled: this.options.soloditEnrich || false,
      verbose: this.options.verbose,
      timeout: this.options.soloditTimeout || 10000,
      minConfidenceThreshold: this.options.soloditMinConfidence || 0.3
    });

    // Initialize enhanced detectors - ordered by Immunefi severity
    // Production-grade for high-TVL DeFi targets
    this.detectors = [
      // CRITICAL: Direct theft of funds (highest priority)
      new ReentrancyEnhancedDetector(),
      new CallbackReentrancyDetector(),        // NEW: ERC777/ERC1155 callback reentrancy
      new AccessControlEnhancedDetector(),
      new DelegateCallDetector(),
      new UnprotectedSelfdestruct(),
      new ProxyVulnerabilitiesDetector(),
      new CrossContractReentrancyDetector(),

      // CRITICAL: Protocol insolvency / Governance takeover
      new GovernanceAttackDetector(),
      new ShareManipulationDetector(),
      new RebasingTokenVaultDetector(),        // NEW: Aave/Lido rebasing token issues
      new FlashLoanDetector(),
      new OracleManipulationDetector(),
      new AdvancedPriceManipulationDetector(), // NEW: LP token, Curve, Balancer manipulation

      // HIGH: Theft of yield / Manipulation profit
      new SignatureReplayDetector(),
      new PermitExploitsDetector(),
      new UncheckedCallDetector(),
      new TOCTOUDetector(),

      // HIGH: Price manipulation
      new FrontRunningDetector(),
      new IntegerOverflowDetector(),

      // MEDIUM: Conditional inclusion (filtered in exploit-driven mode)
      new TimestampDependenceDetector(),
      new GasGriefingDetector(),
      new DeprecatedFunctionsDetector(),
      new TokenStandardComplianceDetector()
    ];

    this.findings = [];
    this.stats = {
      filesScanned: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      exploitable: 0
    };
  }

  async scanFile(filePath) {
    try {
      const content = await fs.readFile(filePath, 'utf8');
      return await this.scanSource(content, filePath);
    } catch (error) {
      throw new Error(`Failed to read file ${filePath}: ${error.message}`);
    }
  }

  async scanSource(sourceCode, fileName = 'contract.sol') {
    this.stats.filesScanned++;

    // Progress: Parsing
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'parsing',
        message: 'Parsing Solidity code...',
        fileName
      });
    }

    let ast;
    try {
      ast = parser.parse(sourceCode, {
        loc: true,
        range: true,
        tolerant: true
      });
    } catch (error) {
      throw new Error(`Failed to parse Solidity code: ${error.message}`);
    }

    // Progress: Building control flow graph
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'analyzing',
        message: 'Building control flow graph...',
        fileName
      });
    }

    // Build control flow graph
    const cfgAnalyzer = new ControlFlowAnalyzer();
    const cfg = cfgAnalyzer.analyze(ast, sourceCode);

    // Progress: Data flow analysis
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'analyzing',
        message: 'Performing data flow analysis...',
        fileName
      });
    }

    // Perform data flow analysis
    const dataFlowAnalyzer = new DataFlowAnalyzer(cfg);
    const dataFlow = dataFlowAnalyzer.analyze();

    const contractFindings = [];
    const totalDetectors = this.detectors.length;

    // Run enhanced detectors with CFG and data flow info
    for (let i = 0; i < this.detectors.length; i++) {
      const detector = this.detectors[i];

      // Progress: Running detector
      if (this.options.onProgress) {
        this.options.onProgress({
          stage: 'detecting',
          message: `Running detector: ${detector.name}`,
          detector: detector.name,
          current: i + 1,
          total: totalDetectors,
          fileName
        });
      }

      try {
        // Pass CFG and data flow to enhanced detectors
        const detectorFindings = await detector.detect(ast, sourceCode, fileName, cfg, dataFlow);
        contractFindings.push(...detectorFindings);
      } catch (error) {
        if (this.options.verbose) {
          console.error(`Detector ${detector.name} failed: ${error.message}`);
        }
      }
    }

    // Progress: Analyzing results
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'filtering',
        message: 'Classifying for Immunefi payout eligibility...',
        fileName
      });
    }

    // Apply exploit-driven filtering with Immunefi classification
    let filteredFindings;
    if (this.options.exploitDriven || this.options.immunefiOnly || this.options.productionMode) {
      // Model exploit chains
      const exploitModeler = new ExploitChainModeler(cfg, dataFlow);
      const withExploitChains = exploitModeler.modelExploitChains(contractFindings);

      // Classify for Immunefi payouts
      filteredFindings = this.immunefiClassifier.filterToPayoutLevel(withExploitChains);

      // In strict immunefi mode, only keep Critical/High
      if (this.options.immunefiOnly || this.options.productionMode) {
        filteredFindings = filteredFindings.filter(f =>
          f.payoutTier === 'Critical' || f.payoutTier === 'High'
        );
      }

      // PRODUCTION MODE: Gate ALL HIGH/CRITICAL behind PoC execution with impact proof
      if (this.options.productionMode) {
        // Progress: PoC validation
        if (this.options.onProgress) {
          this.options.onProgress({
            stage: 'poc-validation',
            message: 'Validating Foundry PoCs (production mode)...',
            fileName
          });
        }

        const validation = this.pocValidator.validateForProduction(filteredFindings, {
          scanTargetPath: fileName
        });

        filteredFindings = validation.findings;

        // Track stats
        this.stats.pocValidated = validation.stats.validatedHighSeverity;
        this.stats.pocDropped = validation.stats.droppedCount;
        this.stats.productionMode = true;

        // In production mode, only keep findings with proven impact
        filteredFindings = filteredFindings.filter(f => {
          if (['CRITICAL', 'HIGH'].includes(f.severity)) {
            // Must have PoC validation that passed with proven impact
            return f.pocValidation?.ok === true && f.provenImpact;
          }
          // Lower severity findings are still included
          return true;
        });
      } else if (this.options.pocValidate) {
        // Non-production PoC validation (optional)
        const validation = this.pocValidator.validateFindings(filteredFindings, { scanTargetPath: fileName });
        filteredFindings = validation.kept;
        // Track dropped findings for reporting
        this.stats.pocDropped = (this.stats.pocDropped || 0) + validation.dropped.length;
        this.stats.pocKept = (this.stats.pocKept || 0) + validation.kept.length;
      }

      // Solodit enrichment: correlate with real-world exploits
      if (this.soloditEnricher.enabled) {
        // Progress: Solodit enrichment
        if (this.options.onProgress) {
          this.options.onProgress({
            stage: 'solodit-enrichment',
            message: 'Correlating with Solodit vulnerability database...',
            fileName
          });
        }

        filteredFindings = await this.soloditEnricher.enrichFindings(filteredFindings);

        // Track Solodit stats
        const soloditStats = this.soloditEnricher.getStats();
        this.stats.soloditEnriched = soloditStats.findingsEnriched;
        this.stats.soloditConfirmedInWild = soloditStats.confirmedInWild;
        this.stats.soloditTheoretical = soloditStats.theoretical;
      }
    } else {
      // Legacy filtering mode
      filteredFindings = this.filterFindings(contractFindings);
    }

    // Update statistics
    this.updateStats(filteredFindings);
    this.findings.push(...filteredFindings);

    return filteredFindings;
  }

  async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async scanDirectory(dirPath) {
    const files = await this.getSolidityFiles(dirPath);
    const allFindings = [];
    const totalFiles = files.length;

    // Progress: Found files
    if (this.options.onProgress) {
      this.options.onProgress({
        stage: 'discovery',
        message: `Found ${totalFiles} Solidity file(s)`,
        totalFiles
      });
    }

    for (let i = 0; i < files.length; i++) {
      const file = files[i];

      // Progress: Scanning file
      if (this.options.onProgress) {
        this.options.onProgress({
          stage: 'file-scan',
          message: `Scanning file ${i + 1}/${totalFiles}`,
          fileName: file,
          currentFile: i + 1,
          totalFiles
        });
      }

      try {
        const findings = await this.scanFile(file);
        allFindings.push(...findings);
      } catch (error) {
        if (this.options.verbose) {
          console.error(`Error scanning ${file}: ${error.message}`);
        }
      }
    }

    return allFindings;
  }

  async getSolidityFiles(dirPath) {
    const files = [];

    async function traverse(currentPath) {
      const entries = await fs.readdir(currentPath, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(currentPath, entry.name);

        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'node_modules') {
          await traverse(fullPath);
        } else if (entry.isFile() && entry.name.endsWith('.sol')) {
          files.push(fullPath);
        }
      }
    }

    await traverse(dirPath);
    return files;
  }

  /**
   * Filter findings by severity, exploitability, and confidence
   * HARDENED: Aggressive filtering to report only real, exploitable vulnerabilities
   * Optimized for precision over recall (fewer false positives)
   */
  filterFindings(findings) {
    // Filter by severity level
    let filtered = this.filterBySeverity(findings);

    // Deduplicate findings by location (same file:line)
    const seenLocations = new Set();
    filtered = filtered.filter(finding => {
      const locationKey = `${finding.fileName}:${finding.line}:${finding.title}`;
      if (seenLocations.has(locationKey)) {
        return false;
      }
      seenLocations.add(locationKey);
      return true;
    });

    // Apply exploitability-based filtering (HARDENED)
    filtered = filtered.filter(finding => {
      // Always report high-confidence findings with PoC
      if (finding.isHighConfidence === true) {
        return true;
      }

      // CRITICAL severity: require exploitable flag AND (HIGH confidence OR score >= 70)
      if (finding.severity === 'CRITICAL') {
        if (finding.exploitable !== true) return false;
        if (finding.confidence === 'HIGH') return true;
        if (finding.exploitabilityScore >= 70) return true;
        return false;
      }

      // HIGH severity: require HIGH confidence OR (MEDIUM confidence AND exploitable AND score >= 65)
      if (finding.severity === 'HIGH') {
        if (finding.confidence === 'HIGH' && finding.exploitable === true) return true;
        if (finding.confidence === 'MEDIUM' && finding.exploitable === true && finding.exploitabilityScore >= 65) return true;
        return false;
      }

      // MEDIUM severity: require HIGH confidence AND exploitable AND score >= 70
      if (finding.severity === 'MEDIUM') {
        if (finding.confidence === 'HIGH' && finding.exploitable === true && finding.exploitabilityScore >= 70) return true;
        return false;
      }

      // LOW/INFO: Only include with very high score (rare)
      if (finding.severity === 'LOW' || finding.severity === 'INFO') {
        return finding.exploitabilityScore >= 80 && finding.confidence === 'HIGH';
      }

      // Default: filter out
      return false;
    });

    // Sort by exploitability score (highest first)
    filtered.sort((a, b) => {
      // First by severity
      const severityOrder = { 'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFO': 1 };
      const severityDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
      if (severityDiff !== 0) return severityDiff;

      // Then by confidence
      const confOrder = { 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      const confDiff = (confOrder[b.confidence] || 0) - (confOrder[a.confidence] || 0);
      if (confDiff !== 0) return confDiff;

      // Then by exploitability score
      return (b.exploitabilityScore || 0) - (a.exploitabilityScore || 0);
    });

    return filtered;
  }

  filterBySeverity(findings) {
    if (this.options.severity === 'all') {
      return findings;
    }

    const severityLevels = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };

    const minLevel = severityLevels[this.options.severity] || 0;

    return findings.filter(f =>
      severityLevels[f.severity.toLowerCase()] >= minLevel
    );
  }

  updateStats(findings) {
    findings.forEach(finding => {
      this.stats.totalFindings++;
      const severity = finding.severity.toLowerCase();
      if (this.stats[severity] !== undefined) {
        this.stats[severity]++;
      }
      if (finding.exploitable === true) {
        this.stats.exploitable++;
      }
      // Track Immunefi payout eligibility
      if (finding.payoutTier === 'Critical') {
        this.stats.immunefiCritical = (this.stats.immunefiCritical || 0) + 1;
      } else if (finding.payoutTier === 'High') {
        this.stats.immunefiHigh = (this.stats.immunefiHigh || 0) + 1;
      }
    });
  }

  /**
   * Get Immunefi-focused summary for bug bounty submission
   * Groups findings by payout category with exploit chains
   */
  getImmunefiReport() {
    const criticalFindings = this.findings.filter(f => f.payoutTier === 'Critical');
    const highFindings = this.findings.filter(f => f.payoutTier === 'High');

    const formatFinding = (f, index) => ({
      id: index + 1,
      title: f.title,
      severity: f.severity,
      payoutTier: f.payoutTier,
      immunefiCategory: f.immunefiClassification?.category?.name || 'Unknown',
      impact: f.immunefiClassification?.impactDescription || f.description,
      location: f.location,
      file: `${f.fileName}:${f.line}`,
      exploitChain: f.exploitChain ? {
        attackerRequirements: f.exploitChain.requirements,
        steps: f.exploitChain.steps?.map(s => s.action) || [],
        profitMechanism: f.exploitChain.profitPath?.mechanism
      } : null,
      recommendation: f.recommendation,
      poc: f.foundryPoC ? 'Included' : 'Not generated'
    });

    return {
      summary: {
        totalFindings: this.findings.length,
        criticalCount: criticalFindings.length,
        highCount: highFindings.length,
        scanMode: this.options.immunefiOnly ? 'Immunefi Strict' : 'Exploit-Driven'
      },
      criticalFindings: criticalFindings.map(formatFinding),
      highFindings: highFindings.map(formatFinding),
      attackVectors: this.getAttackVectorSummary(),
      generatedAt: new Date().toISOString()
    };
  }

  /**
   * Get summary by attack vector for Immunefi submission
   */
  getAttackVectorSummary() {
    const vectors = {};
    for (const finding of this.findings) {
      const vector = finding.attackVector || 'other';
      if (!vectors[vector]) {
        vectors[vector] = { count: 0, critical: 0, high: 0 };
      }
      vectors[vector].count++;
      if (finding.payoutTier === 'Critical') vectors[vector].critical++;
      if (finding.payoutTier === 'High') vectors[vector].high++;
    }
    return vectors;
  }

  getFindings() {
    // Separate by Immunefi payout tier
    const criticalFindings = this.findings.filter(f => f.payoutTier === 'Critical');
    const highFindings = this.findings.filter(f => f.payoutTier === 'High');
    const highConfidenceFindings = this.findings.filter(f => f.isHighConfidence);

    // Solodit validation status breakdown
    const soloditConfirmedInWild = this.findings.filter(f =>
      f.soloditMetadata?.validationStatus?.status === 'confirmed_in_wild'
    );
    const soloditConfirmedPattern = this.findings.filter(f =>
      f.soloditMetadata?.validationStatus?.status === 'confirmed_pattern'
    );
    const soloditTheoretical = this.findings.filter(f =>
      f.soloditMetadata?.validationStatus?.status === 'theoretical' ||
      !f.soloditMetadata?.matched
    );

    // Build features list
    const features = [
      'Immunefi Severity Classification',
      'Concrete Exploit Chain Modeling',
      'Adversarial Capability Modeling (Flash Loans, MEV)',
      'Control Flow Analysis',
      'Data Flow Analysis',
      'Cross-Function Reentrancy Detection',
      'Cross-Contract Reentrancy Detection',
      'Governance Attack Detection',
      'Vault/Share Manipulation Detection',
      'Permit/Approval Exploit Detection',
      'Modifier Logic Validation',
      'Exploitability Scoring (0-100)',
      'Attack Vector Classification',
      'Foundry PoC Generation',
      'Flash Loan Attack Detection',
      'Front-Running/MEV Protection',
      'Proxy Contract Vulnerabilities (UUPS, Transparent)',
      'Signature Replay Protection',
      'First Depositor Attack Detection'
    ];

    // Add Solodit feature if enabled
    if (this.soloditEnricher.enabled) {
      features.push('Solodit Real-World Vulnerability Correlation');
    }

    return {
      findings: this.findings,
      // Immunefi categorization
      immunefiCritical: criticalFindings,
      immunefiHigh: highFindings,
      highConfidenceFindings: highConfidenceFindings,
      // Solodit validation breakdown
      solodit: this.soloditEnricher.enabled ? {
        confirmedInWild: soloditConfirmedInWild,
        confirmedPattern: soloditConfirmedPattern,
        theoretical: soloditTheoretical,
        stats: this.soloditEnricher.getStats()
      } : null,
      stats: {
        ...this.stats,
        // Immunefi stats
        immunefiCritical: criticalFindings.length,
        immunefiHigh: highFindings.length,
        totalPayoutEligible: criticalFindings.length + highFindings.length,
        highConfidence: highConfidenceFindings.length,
        withPoC: this.findings.filter(f => f.foundryPoC).length,
        withExploitChain: this.findings.filter(f => f.exploitChain).length,
        // Solodit stats
        soloditEnabled: this.soloditEnricher.enabled,
        soloditConfirmedInWild: soloditConfirmedInWild.length,
        soloditConfirmedPattern: soloditConfirmedPattern.length,
        soloditTheoretical: soloditTheoretical.length
      },
      analysis: {
        engine: 'exploit-driven',
        version: '6.0.0',
        mode: this.options.immunefiOnly ? 'immunefi-strict' : 'exploit-driven',
        soloditEnabled: this.soloditEnricher.enabled,
        features: features
      }
    };
  }

  /**
   * Get high-confidence findings with Foundry PoC templates
   * Only returns findings that meet the high-confidence threshold
   */
  getHighConfidenceFindings() {
    return this.findings.filter(f => f.isHighConfidence && f.foundryPoC);
  }

  /**
   * Generate Foundry test file with all high-confidence PoCs
   * @param {string} contractName - Name for the test file
   * @returns {string} Complete Foundry test file content
   */
  generateFoundryTestFile(contractName = 'VulnerabilityExploits') {
    const pocFindings = this.getHighConfidenceFindings();

    if (pocFindings.length === 0) {
      return null;
    }

    const criticalCount = pocFindings.filter(f => f.payoutTier === 'Critical').length;
    const highCount = pocFindings.filter(f => f.payoutTier === 'High').length;

    const header = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Foundry Proof of Concept Tests
 * Generated by Web3CRIT Scanner v6.0.0 (Exploit-Driven Mode)
 *
 * Immunefi Payout-Eligible Findings: ${pocFindings.length}
 *   - Critical: ${criticalCount}
 *   - High: ${highCount}
 *
 * To run: forge test --match-contract ${contractName} -vvv
 */
`;

    const contracts = pocFindings.map((finding, index) => {
      const testName = this.sanitizeTestName(finding.title);
      const attackVector = finding.attackVector || 'unknown';

      return `
/**
 * Finding #${index + 1}: ${finding.title}
 * Severity: ${finding.severity}
 * Confidence: ${finding.confidence}
 * Exploitability Score: ${finding.exploitabilityScore}/100
 * Attack Vector: ${attackVector}
 * File: ${finding.fileName}:${finding.line}
 *
 * Description: ${finding.description}
 */
${finding.foundryPoC}
`;
    }).join('\n');

    return header + contracts;
  }

  /**
   * Sanitize a title into a valid Solidity test function name
   */
  sanitizeTestName(title) {
    return title
      .replace(/[^a-zA-Z0-9\s]/g, '')
      .split(/\s+/)
      .map((word, i) => i === 0 ? word.toLowerCase() : word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join('');
  }

  /**
   * Get summary of findings by attack vector
   */
  getFindingsSummary() {
    const byVector = {};
    const bySeverity = {};

    for (const finding of this.findings) {
      // By attack vector
      const vector = finding.attackVector || 'unknown';
      if (!byVector[vector]) {
        byVector[vector] = { count: 0, highConfidence: 0, findings: [] };
      }
      byVector[vector].count++;
      if (finding.isHighConfidence) {
        byVector[vector].highConfidence++;
      }
      byVector[vector].findings.push({
        title: finding.title,
        severity: finding.severity,
        exploitabilityScore: finding.exploitabilityScore
      });

      // By severity
      const severity = finding.severity;
      if (!bySeverity[severity]) {
        bySeverity[severity] = 0;
      }
      bySeverity[severity]++;
    }

    return {
      total: this.findings.length,
      highConfidence: this.findings.filter(f => f.isHighConfidence).length,
      withPoC: this.findings.filter(f => f.foundryPoC).length,
      byAttackVector: byVector,
      bySeverity: bySeverity,
      topExploitable: this.findings
        .filter(f => f.exploitabilityScore >= 70)
        .sort((a, b) => b.exploitabilityScore - a.exploitabilityScore)
        .slice(0, 5)
        .map(f => ({
          title: f.title,
          severity: f.severity,
          score: f.exploitabilityScore,
          vector: f.attackVector
        }))
    };
  }

  reset() {
    this.findings = [];
    this.stats = {
      filesScanned: 0,
      totalFindings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      exploitable: 0
    };
  }
}

module.exports = Web3CRITScannerEnhanced;
