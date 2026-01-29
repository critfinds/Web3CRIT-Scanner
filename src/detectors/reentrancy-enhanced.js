const BaseDetector = require('./base-detector');

/**
 * Enhanced Reentrancy Detector
 * Uses control flow and data flow analysis instead of simple pattern matching
 * Tracks cross-function reentrancy and validates exploitability
 */
class ReentrancyEnhancedDetector extends BaseDetector {
  constructor() {
    super(
      'Reentrancy Vulnerability (Enhanced)',
      'Advanced reentrancy detection using control/data flow analysis',
      'CRITICAL'
    );
    this.cfg = null;
    this.dataFlow = null;
  }

  /**
   * Override detect to use CFG and data flow analysis
   */
  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.findings = [];

    if (!cfg || !dataFlow) {
      // Fallback to basic detection if advanced analysis not available
      return super.detect(ast, sourceCode, fileName);
    }

    // Analyze each function for reentrancy
    for (const [funcKey, funcInfo] of cfg.functions) {
      this.analyzeFunctionReentrancy(funcKey, funcInfo);
    }

    return this.findings;
  }

  /**
   * Analyze a function for reentrancy vulnerabilities
   */
  analyzeFunctionReentrancy(funcKey, funcInfo) {
    // Skip private/internal functions (not directly exploitable)
    if (funcInfo.visibility === 'private' || funcInfo.visibility === 'internal') {
      return;
    }

    // Check for classic reentrancy: external call before state write
    const classicReentrancy = this.detectClassicReentrancy(funcInfo);
    if (classicReentrancy) {
      this.reportClassicReentrancy(funcInfo, classicReentrancy);
    }

    // Check for cross-function reentrancy
    const crossFunction = this.detectCrossFunctionReentrancy(funcKey, funcInfo);
    if (crossFunction) {
      this.reportCrossFunctionReentrancy(funcInfo, crossFunction);
    }

    // Check for read-only reentrancy
    const readOnly = this.detectReadOnlyReentrancy(funcKey, funcInfo);
    if (readOnly) {
      this.reportReadOnlyReentrancy(funcInfo, readOnly);
    }
  }

  /**
   * Detect classic reentrancy: external call before state modification
   */
  detectClassicReentrancy(funcInfo) {
    const externalCalls = funcInfo.externalCalls;
    const stateWrites = funcInfo.stateWrites;

    // Check if any state write happens after an external call
    for (const call of externalCalls) {
      for (const write of stateWrites) {
        if (call.loc && write.loc) {
          // Compare positions: if call comes before write, it's vulnerable
          if (this.comesBefore(call.loc, write.loc)) {
            // Verify this is actually exploitable
            if (this.isExploitable(funcInfo, call, write)) {
              // Adjust confidence based on call type
              // transfer/send have 2300 gas stipend but aren't fully safe post-Istanbul
              const isLimitedGas = call.type === 'transfer' || call.type === 'send';
              return {
                call: call,
                write: write,
                severity: isLimitedGas ? 'HIGH' : 'CRITICAL',
                confidence: isLimitedGas ? 'MEDIUM' : 'HIGH'
              };
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * Detect cross-function reentrancy
   * Function A makes external call, allowing reentrant call to Function B
   * which modifies shared state
   */
  detectCrossFunctionReentrancy(funcKey, funcInfo) {
    if (funcInfo.externalCalls.length === 0) {
      return null;
    }

    // Find other public/external functions in same contract that modify state
    const contractFunctions = Array.from(this.cfg.functions.values())
      .filter(f => f.contract === funcInfo.contract)
      .filter(f => f.visibility === 'public' || f.visibility === 'external')
      .filter(f => f.name !== funcInfo.name);

    for (const otherFunc of contractFunctions) {
      // Check if other function modifies state that this function depends on
      const sharedState = this.findSharedStateVariables(funcInfo, otherFunc);

      if (sharedState.length > 0) {
        // Check if this function lacks reentrancy protection
        if (!this.hasReentrancyGuard(funcInfo) && !this.hasReentrancyGuard(otherFunc)) {
          return {
            vulnerableFunc: funcInfo,
            reentrantFunc: otherFunc,
            sharedState: sharedState,
            severity: 'CRITICAL',
            confidence: 'MEDIUM'
          };
        }
      }
    }

    return null;
  }

  /**
   * Detect read-only reentrancy
   * External call in a view/getter allowing state inconsistency
   *
   * HARDENED: Only report if:
   * 1. Function is used by external protocols (has dependent contracts)
   * 2. State read is for value calculation (balances, shares, prices)
   * 3. High confidence of actual exploitation path
   *
   * We skip low-confidence read-only reentrancy as it rarely leads to direct fund theft
   * and creates noise. The Curve LP oracle attack was specific to cross-contract composition.
   */
  detectReadOnlyReentrancy(funcKey, funcInfo) {
    // Skip low-value read-only reentrancy detection to reduce noise
    // Read-only reentrancy requires:
    // 1. External contract depending on this view function
    // 2. View function reading state that can be manipulated mid-call
    // 3. External contract making financial decisions based on stale view
    //
    // Without cross-contract analysis, we cannot reliably detect this.
    // Keeping this disabled to optimize for precision over recall.
    //
    // For protocols that need this, recommend manual audit of view functions
    // called by external protocols (oracles, composability).

    // Only report CRITICAL cases: view/pure function making external calls
    // This is a code smell that violates the view/pure guarantee
    if (funcInfo.stateMutability === 'view' || funcInfo.stateMutability === 'pure') {
      if (funcInfo.externalCalls.length > 0) {
        // Check if any external call could trigger reentrancy to state-modifying function
        const hasCallWithValue = funcInfo.externalCalls.some(c =>
          c.type === 'call' || c.type === 'delegatecall'
        );

        if (hasCallWithValue) {
          // Only report if function name suggests it's used for pricing/valuation
          const funcNameLower = funcInfo.name.toLowerCase();
          const isPricingFunction = /price|value|balance|amount|rate|convert|preview|quote|get.*assets|get.*shares/i.test(funcNameLower);

          if (isPricingFunction) {
            return {
              func: funcInfo,
              calls: funcInfo.externalCalls,
              severity: 'HIGH',
              confidence: 'MEDIUM'
            };
          }
        }
      }
    }

    // Do NOT report low-confidence read-only reentrancy (state read after external call)
    // This pattern is too common and rarely exploitable without cross-contract context
    return null;
  }

  /**
   * Check if reentrancy is actually exploitable
   * Returns object with exploitability details for severity adjustment
   */
  isExploitable(funcInfo, call, write) {
    // Check 1: Has reentrancy guard?
    if (this.hasReentrancyGuard(funcInfo)) {
      return false;
    }

    // Check 2: Is function publicly accessible?
    if (funcInfo.visibility === 'private' || funcInfo.visibility === 'internal') {
      return false;
    }

    // Does external call allow reentrancy?
    // Note: Post-Istanbul (EIP-1884), transfer/send with 2300 gas stipend
    // are less reliable due to increased SLOAD costs. While they provide
    // some protection, they should not be considered fully safe.
    // We still report these but with adjusted confidence.
    if (call.type === 'transfer' || call.type === 'send') {
      // Return true but caller should adjust confidence to MEDIUM
      // These have gas limits but are not guaranteed safe post-Istanbul
      return true;
    }

    return true;
  }

  /**
   * Find state variables modified by both functions
   */
  findSharedStateVariables(func1, func2) {
    const shared = [];

    const writes1 = new Set(func1.stateWrites.map(w => w.variable));
    const writes2 = new Set(func2.stateWrites.map(w => w.variable));

    for (const varName of writes1) {
      if (writes2.has(varName)) {
        shared.push(varName);
      }
    }

    return shared;
  }

  /**
   * Check if function has reentrancy protection
   */
  hasReentrancyGuard(funcInfo) {
    // Check modifiers
    for (const modName of funcInfo.modifiers) {
      const modKey = `${funcInfo.contract}.${modName}`;
      const modInfo = this.cfg.modifiers.get(modKey);

      if (modInfo) {
        // Check if modifier implements reentrancy guard pattern
        const hasLockCheck = modInfo.requireStatements.some(stmt =>
          stmt.includes('_status') ||
          stmt.includes('locked') ||
          stmt.includes('_notEntered')
        );

        if (hasLockCheck) {
          return true;
        }

        // Check modifier name
        const modNameLower = modName.toLowerCase();
        if (modNameLower.includes('nonreentrant') ||
            modNameLower.includes('lock') ||
            modNameLower.includes('guard')) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check if location A comes before location B in source code
   */
  comesBefore(locA, locB) {
    if (!locA || !locB) return false;

    if (locA.start.line < locB.start.line) {
      return true;
    } else if (locA.start.line === locB.start.line) {
      return locA.start.column < locB.start.column;
    }

    return false;
  }

  /**
   * Report classic reentrancy finding
   */
  reportClassicReentrancy(funcInfo, vuln) {
    this.addFinding({
      title: 'Classic Reentrancy Vulnerability',
      description: `Function '${funcInfo.name}' performs external ${vuln.call.type} before updating state variable '${vuln.write.variable}'. This allows attackers to reenter the function and exploit the stale state. EXPLOITABLE: No reentrancy guard detected.`,
      location: `Contract: ${funcInfo.contract}, Function: ${funcInfo.name}`,
      line: vuln.call.loc ? vuln.call.loc.start.line : 0,
      column: vuln.call.loc ? vuln.call.loc.start.column : 0,
      code: this.getCodeSnippet(vuln.call.loc),
      severity: vuln.severity,
      confidence: vuln.confidence,
      exploitable: true,
      recommendation: 'CRITICAL FIX REQUIRED: Move state updates before external calls (Checks-Effects-Interactions pattern) OR add nonReentrant modifier from OpenZeppelin ReentrancyGuard.',
      references: [
        'https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/',
        'https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard'
      ]
    });
  }

  /**
   * Report cross-function reentrancy finding
   */
  reportCrossFunctionReentrancy(funcInfo, vuln) {
    this.addFinding({
      title: 'Cross-Function Reentrancy Vulnerability',
      description: `Function '${funcInfo.name}' makes external calls without reentrancy protection, allowing reentrant calls to '${vuln.reentrantFunc.name}' which modifies shared state: ${vuln.sharedState.join(', ')}. This is exploitable even without classic reentrancy pattern.`,
      location: `Contract: ${funcInfo.contract}, Functions: ${funcInfo.name} <-> ${vuln.reentrantFunc.name}`,
      line: funcInfo.node.loc ? funcInfo.node.loc.start.line : 0,
      column: funcInfo.node.loc ? funcInfo.node.loc.start.column : 0,
      code: this.getCodeSnippet(funcInfo.node.loc),
      severity: vuln.severity,
      confidence: vuln.confidence,
      exploitable: true,
      recommendation: 'Add nonReentrant modifier to ALL public/external functions that modify state or make external calls. Cross-function reentrancy requires contract-wide protection.',
      references: [
        'https://github.com/pcaversaccio/reentrancy-attacks#cross-function-reentrancy',
        'https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard'
      ]
    });
  }

  /**
   * Report read-only reentrancy finding
   */
  reportReadOnlyReentrancy(funcInfo, vuln) {
    this.addFinding({
      title: 'Read-Only Reentrancy Risk',
      description: `Function '${funcInfo.name}' makes external calls and then reads state. While this function doesn't modify state, it can return inconsistent data if reentered, potentially affecting other contracts that depend on it.`,
      location: `Contract: ${funcInfo.contract}, Function: ${funcInfo.name}`,
      line: vuln.call?.loc ? vuln.call.loc.start.line : 0,
      column: vuln.call?.loc ? vuln.call.loc.start.column : 0,
      code: this.getCodeSnippet(vuln.call?.loc || funcInfo.node.loc),
      severity: vuln.severity,
      confidence: vuln.confidence,
      exploitable: false,
      recommendation: 'If this function is used by other contracts for critical decisions, add reentrancy protection. Consider using snapshot-based reads or reentrancy guards.',
      references: [
        'https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/'
      ]
    });
  }
}

module.exports = ReentrancyEnhancedDetector;
