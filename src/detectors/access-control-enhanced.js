const BaseDetector = require('./base-detector');

/**
 * Enhanced Access Control Detector
 * Validates what modifiers actually do instead of just checking existence
 * Detects broken access control logic
 */
class AccessControlEnhancedDetector extends BaseDetector {
  constructor() {
    super(
      'Access Control Vulnerability (Enhanced)',
      'Advanced access control validation - checks modifier logic, not just presence',
      'CRITICAL'
    );
    this.cfg = null;
    this.dataFlow = null;
  }

  /**
   * Override detect to use CFG analysis
   */
  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.findings = [];

    if (!cfg) {
      // Fallback to basic detection
      return super.detect(ast, sourceCode, fileName);
    }

    // Analyze each function for access control issues
    for (const [funcKey, funcInfo] of cfg.functions) {
      this.analyzeFunctionAccessControl(funcKey, funcInfo);
    }

    // Analyze modifiers for broken logic
    for (const [modKey, modInfo] of cfg.modifiers) {
      this.analyzeModifierLogic(modKey, modInfo);
    }

    return this.findings;
  }

  /**
   * Analyze function access control
   */
  analyzeFunctionAccessControl(funcKey, funcInfo) {
    // Skip constructors
    if (funcInfo.isConstructor) {
      return;
    }

    // Check if function needs access control
    if (this.needsAccessControl(funcInfo)) {
      const protection = this.analyzeAccessProtection(funcInfo);

      if (protection.level === 'none') {
        this.reportMissingAccessControl(funcInfo, protection);
      } else if (protection.level === 'weak') {
        this.reportWeakAccessControl(funcInfo, protection);
      } else if (protection.level === 'broken') {
        this.reportBrokenAccessControl(funcInfo, protection);
      }
    }
  }

  /**
   * Determine if function needs access control
   */
  needsAccessControl(funcInfo) {
    // Private/internal functions don't need explicit access control
    if (funcInfo.visibility === 'private' || funcInfo.visibility === 'internal') {
      return false;
    }

    // View/pure functions with no state changes don't need access control
    if ((funcInfo.stateMutability === 'view' || funcInfo.stateMutability === 'pure') &&
        funcInfo.stateWrites.length === 0) {
      return false;
    }

    // Check if function has internal access control (require/assert checks in body)
    if (this.hasInternalAccessControl(funcInfo)) {
      return false;
    }

    // Check if function is a self-service withdrawal pattern (users withdraw own funds)
    if (this.isSelfServiceWithdrawal(funcInfo)) {
      return false;
    }

    // Check if function performs sensitive operations
    return this.hasSensitiveOperations(funcInfo);
  }

  /**
   * Check if function has internal access control checks
   * (access control via require/assert inside function body instead of modifier)
   */
  hasInternalAccessControl(funcInfo) {
    if (!funcInfo.node || !funcInfo.node.body) return false;

    const funcCode = this.getCodeSnippet(funcInfo.node.loc);
    if (!funcCode) return false;

    // Check for common internal access control patterns
    const internalAccessPatterns = [
      /require\s*\(\s*msg\.sender\s*==\s*\w+/i,  // require(msg.sender == owner)
      /require\s*\(\s*\w+\s*==\s*msg\.sender/i,  // require(pendingOwner == msg.sender)
      /assert\s*\(\s*msg\.sender\s*==\s*\w+/i,
      /if\s*\(\s*msg\.sender\s*!=\s*\w+\)\s*revert/i,  // if (msg.sender != owner) revert
      /onlyOwner|onlyAdmin|onlyRole/i,  // Modifier names in function
    ];

    return internalAccessPatterns.some(pattern => pattern.test(funcCode));
  }

  /**
   * Check if function is a self-service withdrawal pattern
   * (users can only withdraw their own funds based on msg.sender)
   */
  isSelfServiceWithdrawal(funcInfo) {
    const funcNameLower = funcInfo.name.toLowerCase().replace(/[_\s]/g, '');

    // Check if function name suggests self-service pattern
    const selfServiceNames = ['withdraw', 'withdrawfunds', 'claim', 'redeem', 'collect'];
    if (!selfServiceNames.some(name => funcNameLower.includes(name))) {
      return false;
    }

    if (!funcInfo.node || !funcInfo.node.body) return false;

    const funcCode = this.getCodeSnippet(funcInfo.node.loc);
    if (!funcCode) return false;

    // Check if function accesses user-specific storage using msg.sender
    // e.g., balances[msg.sender] or pendingWithdrawals[msg.sender]
    const selfServicePatterns = [
      /\[\s*msg\.sender\s*\]/,  // mapping[msg.sender]
      /balances\s*\[\s*msg\.sender\s*\]/i,
      /pending\w*\s*\[\s*msg\.sender\s*\]/i,
    ];

    return selfServicePatterns.some(pattern => pattern.test(funcCode));
  }

  /**
   * Check if function performs sensitive operations
   */
  hasSensitiveOperations(funcInfo) {
    // Check for dangerous operations
    const dangerousOps = ['delegatecall', 'selfdestruct', 'suicide'];
    if (funcInfo.externalCalls.some(call => dangerousOps.includes(call.type))) {
      return true;
    }

    // Check for direct value-moving operations by inspecting code for transfer/mint/burn patterns.
    // This is intentionally conservative to avoid name-only false positives (e.g., withdrawInfo()).
    if (funcInfo.node && funcInfo.node.loc) {
      const code = (this.getCodeSnippet(funcInfo.node.loc) || '').toLowerCase();
      const valueMovingPatterns = [
        /\.transfer\s*\(/,        // ERC20/ETH transfer-like
        /\.transferfrom\s*\(/,    // ERC20 transferFrom
        /\.send\s*\(/,            // ETH send
        /\.call\s*\{[^}]*value/i, // call{value: ...}
        /\b_mint\s*\(/,
        /\bmint\s*\(/,
        /\b_burn\s*\(/,
        /\bburn\s*\(/,
        /\bselfdestruct\s*\(/,
      ];
      if (valueMovingPatterns.some(p => p.test(code))) {
        return true;
      }
    }

    // Check if modifies critical state
    if (this.modifiesCriticalState(funcInfo)) {
      return true;
    }

    return false;
  }

  /**
   * Check if function modifies critical state variables
   */
  modifiesCriticalState(funcInfo) {
    const criticalVars = ['owner', 'admin', 'paused', 'implementation'];

    return funcInfo.stateWrites.some(write => {
      const varName = write.variable.toLowerCase();
      return criticalVars.some(cv => varName.includes(cv));
    });
  }

  /**
   * Analyze what access protection a function has
   */
  analyzeAccessProtection(funcInfo) {
    if (funcInfo.modifiers.length === 0) {
      return {
        level: 'none',
        reason: 'No access control modifiers'
      };
    }

    // Analyze each modifier
    const modifierAnalysis = funcInfo.modifiers.map(modName => {
      const modKey = `${funcInfo.contract}.${modName}`;
      const modInfo = this.cfg.modifiers.get(modKey);

      if (!modInfo) {
        return {
          name: modName,
          effective: 'unknown',
          reason: 'Modifier not found in contract'
        };
      }

      return this.evaluateModifierEffectiveness(modInfo);
    });

    // Determine overall protection level
    const hasEffectiveProtection = modifierAnalysis.some(m => m.effective === 'strong');
    const hasBrokenProtection = modifierAnalysis.some(m => m.effective === 'broken');
    const hasWeakProtection = modifierAnalysis.some(m => m.effective === 'weak');

    if (hasBrokenProtection) {
      return {
        level: 'broken',
        modifiers: modifierAnalysis,
        reason: 'Modifier exists but logic is broken'
      };
    } else if (hasEffectiveProtection) {
      return {
        level: 'strong',
        modifiers: modifierAnalysis
      };
    } else if (hasWeakProtection) {
      return {
        level: 'weak',
        modifiers: modifierAnalysis,
        reason: 'Modifier provides weak protection'
      };
    }

    return {
      level: 'none',
      modifiers: modifierAnalysis,
      reason: 'Modifiers do not provide access control'
    };
  }

  /**
   * Evaluate how effective a modifier is at access control
   */
  evaluateModifierEffectiveness(modInfo) {
    if (!modInfo.checksAccess) {
      return {
        name: modInfo.name,
        effective: 'none',
        reason: 'Modifier does not check access'
      };
    }

    // Check for common broken patterns
    const brokenPatterns = this.detectBrokenPatterns(modInfo);
    if (brokenPatterns.length > 0) {
      return {
        name: modInfo.name,
        effective: 'broken',
        reason: `Broken pattern: ${brokenPatterns.join(', ')}`
      };
    }

    // Check for weak patterns
    const weakPatterns = this.detectWeakPatterns(modInfo);
    if (weakPatterns.length > 0) {
      return {
        name: modInfo.name,
        effective: 'weak',
        reason: `Weak pattern: ${weakPatterns.join(', ')}`
      };
    }

    // Modifier appears to provide strong protection
    return {
      name: modInfo.name,
      effective: 'strong',
      reason: modInfo.checksOwnership ? 'Checks ownership' :
              modInfo.checksRole ? 'Checks role' :
              'Checks access control'
    };
  }

  /**
   * Detect broken access control patterns
   */
  detectBrokenPatterns(modInfo) {
    const broken = [];

    // Check if modifier has empty body
    if (modInfo.requireStatements.length === 0) {
      broken.push('Empty modifier - no checks');
    }

    // Check for always-true conditions
    modInfo.requireStatements.forEach(stmt => {
      if (stmt === 'true' || stmt === '1 == 1') {
        broken.push('Always-true condition');
      }
    });

    // Check for tx.origin instead of msg.sender (phishing risk)
    modInfo.requireStatements.forEach(stmt => {
      if (stmt.includes('tx.origin') && !stmt.includes('msg.sender')) {
        broken.push('Uses tx.origin (vulnerable to phishing)');
      }
    });

    return broken;
  }

  /**
   * Detect weak access control patterns
   */
  detectWeakPatterns(modInfo) {
    const weak = [];

    // Check for balance-based access control (flash loan vulnerable)
    modInfo.requireStatements.forEach(stmt => {
      if (stmt.includes('balanceOf') || stmt.includes('.balance >')) {
        weak.push('Balance-based access control (flash loan risk)');
      }
    });

    // Check for timestamp-based access (miner manipulation)
    modInfo.requireStatements.forEach(stmt => {
      if (stmt.includes('block.timestamp') || stmt.includes('now')) {
        weak.push('Timestamp-based check (miner manipulation risk)');
      }
    });

    return weak;
  }

  /**
   * Analyze modifier logic for vulnerabilities
   */
  analyzeModifierLogic(modKey, modInfo) {
    // Check for modifier that claims to provide access control but doesn't
    const broken = this.detectBrokenPatterns(modInfo);

    if (broken.length > 0) {
      this.reportBrokenModifier(modInfo, broken);
    }
  }

  /**
   * Report missing access control
   */
  reportMissingAccessControl(funcInfo, protection) {
    this.addFinding({
      title: 'Missing Access Control on Sensitive Function',
      description: `Function '${funcInfo.name}' performs sensitive operations without access control. ${protection.reason}. This allows ANY user to call this function.`,
      location: `Contract: ${funcInfo.contract}, Function: ${funcInfo.name}`,
      line: funcInfo.node.loc ? funcInfo.node.loc.start.line : 0,
      column: funcInfo.node.loc ? funcInfo.node.loc.start.column : 0,
      code: this.getCodeSnippet(funcInfo.node.loc),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      recommendation: 'Add access control modifier (e.g., onlyOwner) to restrict who can call this function. Use OpenZeppelin Ownable or AccessControl contracts.',
      references: [
        'https://docs.openzeppelin.com/contracts/4.x/access-control',
        'https://swcregistry.io/docs/SWC-105'
      ]
    });
  }

  /**
   * Report weak access control
   */
  reportWeakAccessControl(funcInfo, protection) {
    const modifierDetails = protection.modifiers.map(m =>
      `${m.name}: ${m.reason}`
    ).join('; ');

    this.addFinding({
      title: 'Weak Access Control Pattern',
      description: `Function '${funcInfo.name}' uses weak access control that can be bypassed. ${modifierDetails}. This may be exploitable.`,
      location: `Contract: ${funcInfo.contract}, Function: ${funcInfo.name}`,
      line: funcInfo.node.loc ? funcInfo.node.loc.start.line : 0,
      column: funcInfo.node.loc ? funcInfo.node.loc.start.column : 0,
      code: this.getCodeSnippet(funcInfo.node.loc),
      severity: 'HIGH',
      confidence: 'MEDIUM',
      exploitable: true,
      recommendation: 'Replace weak access control with proper ownership or role-based checks. Avoid balance-based or timestamp-based access control.',
      references: [
        'https://docs.openzeppelin.com/contracts/4.x/access-control'
      ]
    });
  }

  /**
   * Report broken access control
   */
  reportBrokenAccessControl(funcInfo, protection) {
    const modifierDetails = protection.modifiers.map(m =>
      `${m.name}: ${m.reason}`
    ).join('; ');

    this.addFinding({
      title: 'Broken Access Control - Logic Error',
      description: `Function '${funcInfo.name}' has access control modifier BUT it contains logic errors that make it ineffective. ${modifierDetails}. CRITICAL: Access control appears to exist but does not work.`,
      location: `Contract: ${funcInfo.contract}, Function: ${funcInfo.name}`,
      line: funcInfo.node.loc ? funcInfo.node.loc.start.line : 0,
      column: funcInfo.node.loc ? funcInfo.node.loc.start.column : 0,
      code: this.getCodeSnippet(funcInfo.node.loc),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      recommendation: 'Fix the modifier logic immediately. This is more dangerous than missing access control because developers may assume the function is protected.',
      references: [
        'https://docs.openzeppelin.com/contracts/4.x/access-control'
      ]
    });
  }

  /**
   * Report broken modifier
   */
  reportBrokenModifier(modInfo, issues) {
    this.addFinding({
      title: 'Broken Access Control Modifier',
      description: `Modifier '${modInfo.name}' contains logic errors: ${issues.join(', ')}. Functions using this modifier are NOT protected.`,
      location: `Contract: ${modInfo.contract}, Modifier: ${modInfo.name}`,
      line: modInfo.node.loc ? modInfo.node.loc.start.line : 0,
      column: modInfo.node.loc ? modInfo.node.loc.start.column : 0,
      code: this.getCodeSnippet(modInfo.node.loc),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      recommendation: 'Fix modifier logic immediately. All functions using this modifier are vulnerable.',
      references: [
        'https://docs.soliditylang.org/en/latest/contracts.html#function-modifiers'
      ]
    });
  }
}

module.exports = AccessControlEnhancedDetector;
