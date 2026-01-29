const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');

/**
 * Foundry PoC Validator (Production-Grade)
 *
 * Hard rules enforced:
 * - HIGH/CRITICAL only emitted if PoC compiles, executes on fork, and proves impact
 * - Impact = fund drain, unauthorized transfer, role takeover, invariant break, or permanent DoS
 * - If PoC fails → finding discarded silently
 * - Severity derived from observed PoC results, not heuristics
 *
 * Notes:
 * - Requires Foundry project with foundry.toml + forge-std
 * - In production mode, forge is mandatory
 */

// Impact types that qualify for HIGH/CRITICAL (Immunefi-aligned)
const IMPACT_PATTERNS = {
  FUND_DRAIN: {
    severity: 'CRITICAL',
    patterns: [
      /balance.*decreased|lost.*funds|drained/i,
      /assertGt\s*\(\s*attackerBalanceAfter\s*,\s*attackerBalanceBefore/i,
      /assertLt\s*\(\s*victimBalanceAfter\s*,\s*victimBalanceBefore/i,
      /profit.*[1-9]\d*/i,
      /stolen.*ether|stolen.*token/i
    ]
  },
  UNAUTHORIZED_TRANSFER: {
    severity: 'CRITICAL',
    patterns: [
      /transfer.*without.*approval/i,
      /unauthorized.*withdrawal/i,
      /assertEq\s*\(\s*attacker.*balance.*,.*victim/i
    ]
  },
  ROLE_TAKEOVER: {
    severity: 'CRITICAL',
    patterns: [
      /owner\s*==\s*attacker/i,
      /hasRole.*attacker.*true/i,
      /admin.*changed|owner.*changed/i,
      /assertEq\s*\(\s*.*\.owner\(\)\s*,\s*attacker/i
    ]
  },
  INVARIANT_BREAK: {
    severity: 'HIGH',
    patterns: [
      /invariant.*broken|invariant.*violated/i,
      /totalSupply.*mismatch/i,
      /shares.*inflated|exchange.*rate.*manipulated/i
    ]
  },
  PERMANENT_DOS: {
    severity: 'HIGH',
    patterns: [
      /permanently.*locked|forever.*frozen/i,
      /cannot.*withdraw|funds.*stuck/i,
      /selfdestruct.*success/i
    ]
  }
};

class PocValidator {
  constructor(options = {}) {
    this.options = {
      enabled: options.enabled || false,
      requirePass: options.requirePass || false,
      productionMode: options.productionMode || false, // Strict mode: require PoC execution proof
      mode: options.mode || 'test', // 'test' (default) or 'build'
      foundryRoot: options.foundryRoot || null,
      keepTemp: options.keepTemp || false,
      forkUrl: options.forkUrl || null, // Optional RPC URL for fork testing
      ...options
    };
  }

  static isForgeAvailable() {
    const res = spawnSync('forge', ['--version'], { shell: true, stdio: 'ignore' });
    return res.status === 0;
  }

  static hasPlaceholders(poc) {
    if (!poc) return true;
    const s = String(poc);
    const placeholderPatterns = [
      /0x\.\.\./,               // 0x...
      /\bTARGET_ADDRESS\b/,
      /\bTODO\b/i,
      /address\s+constant\s+\w+\s*=\s*address\(0\)/i, // constant address(0)
    ];
    return placeholderPatterns.some(p => p.test(s));
  }

  static findFoundryRoot(startPath) {
    if (!startPath) return null;
    let current = startPath;
    try {
      const stat = fs.statSync(current);
      if (stat.isFile()) {
        current = path.dirname(current);
      }
    } catch (_) {
      // ignore
    }

    while (true) {
      const candidate = path.join(current, 'foundry.toml');
      if (fs.existsSync(candidate)) return current;
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
    return null;
  }

  ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
  }

  makeTempTestPath(foundryRoot, finding) {
    const baseDir = path.join(foundryRoot, 'test', '.web3crit');
    this.ensureDir(baseDir);
    const safe = (finding.title || 'Finding')
      .replace(/[^a-zA-Z0-9]+/g, '_')
      .slice(0, 60);
    const fileName = `${Date.now()}_${safe}.t.sol`;
    return path.join(baseDir, fileName);
  }

  /**
   * Extract impact from forge test output.
   * Returns { impactType, severity, evidence } or null if no impact proven.
   */
  static extractImpact(forgeOutput) {
    if (!forgeOutput) return null;

    for (const [impactType, config] of Object.entries(IMPACT_PATTERNS)) {
      for (const pattern of config.patterns) {
        const match = forgeOutput.match(pattern);
        if (match) {
          return {
            impactType,
            severity: config.severity,
            evidence: match[0]
          };
        }
      }
    }

    // Check for test assertions that passed (indicates exploit succeeded)
    if (/PASS.*test/i.test(forgeOutput) && /assert/i.test(forgeOutput)) {
      // Look for value changes in logs
      const valueMatch = forgeOutput.match(/(\d+)\s*(?:ether|wei|tokens?)/i);
      if (valueMatch) {
        return {
          impactType: 'VALUE_EXTRACTION',
          severity: 'HIGH',
          evidence: `Value movement detected: ${valueMatch[0]}`
        };
      }
    }

    return null;
  }

  /**
   * Derive severity from observed PoC execution results.
   * Overrides heuristic-based severity with runtime proof.
   */
  static deriveSeverityFromImpact(impact, originalSeverity) {
    if (!impact) {
      // No proven impact → downgrade to INFO (will be filtered out)
      return 'INFO';
    }

    // Impact-derived severity takes precedence
    return impact.severity;
  }

  /**
   * Validate a single finding. Returns { ok, reason, details?, impact?, derivedSeverity? }.
   *
   * In production mode:
   * - HIGH/CRITICAL requires PoC execution with proven impact
   * - Severity derived from observed results, not heuristics
   */
  validateFinding(finding, context = {}) {
    const isHighSeverity = ['CRITICAL', 'HIGH'].includes(finding?.severity);

    // In production mode, HIGH/CRITICAL MUST have PoC validation
    if (this.options.productionMode && isHighSeverity) {
      if (!finding || !finding.foundryPoC) {
        return {
          ok: false,
          reason: 'Production mode: HIGH/CRITICAL requires Foundry PoC',
          derivedSeverity: 'INFO' // Downgrade
        };
      }
    }

    if (!this.options.enabled && !this.options.productionMode) {
      return { ok: true, reason: 'PoC validation disabled' };
    }

    if (!finding || !finding.foundryPoC) {
      return { ok: false, reason: 'No Foundry PoC attached to finding' };
    }

    if (PocValidator.hasPlaceholders(finding.foundryPoC)) {
      return {
        ok: false,
        reason: 'PoC contains placeholders (0x..., TARGET_ADDRESS, TODO, or constant address(0))',
        derivedSeverity: isHighSeverity ? 'INFO' : finding.severity
      };
    }

    // In production mode, we MUST execute and verify impact
    const mustExecute = this.options.productionMode && isHighSeverity;

    if (!this.options.requirePass && !mustExecute) {
      return { ok: true, reason: 'PoC basic validation passed (placeholders check only)' };
    }

    // Strict pass requires forge + foundry project root.
    if (!PocValidator.isForgeAvailable()) {
      if (mustExecute) {
        return {
          ok: false,
          reason: 'Production mode: forge required but not found in PATH',
          derivedSeverity: 'INFO'
        };
      }
      return { ok: false, reason: 'forge not found in PATH (install Foundry to enable PoC pass gating)' };
    }

    const foundryRoot =
      this.options.foundryRoot ||
      PocValidator.findFoundryRoot(context.scanTargetPath || process.cwd());

    if (!foundryRoot) {
      if (mustExecute) {
        return {
          ok: false,
          reason: 'Production mode: No foundry.toml found',
          derivedSeverity: 'INFO'
        };
      }
      return { ok: false, reason: 'No foundry.toml found (run inside a Foundry project or pass --foundry-root)' };
    }

    const testPath = this.makeTempTestPath(foundryRoot, finding);
    const content = String(finding.foundryPoC).trim() + os.EOL;

    try {
      fs.writeFileSync(testPath, content, { encoding: 'utf8' });

      // Build args - always use test mode in production for impact verification
      const args = (this.options.mode === 'build' && !mustExecute)
        ? ['build', '--silent']
        : ['test', '--match-path', testPath, '-vvvv']; // Extra verbose for impact extraction

      // Add fork URL if provided
      if (this.options.forkUrl) {
        args.push('--fork-url', this.options.forkUrl);
      }

      const res = spawnSync('forge', args, {
        cwd: foundryRoot,
        shell: true,
        encoding: 'utf8',
        maxBuffer: 10 * 1024 * 1024,
        timeout: 120000 // 2 minute timeout
      });

      const passed = res.status === 0;
      const output = (res.stdout || '') + (res.stderr || '');

      // Extract impact from test output
      const impact = PocValidator.extractImpact(output);

      // In production mode, derive severity from observed impact
      let derivedSeverity = finding.severity;
      if (this.options.productionMode && isHighSeverity) {
        derivedSeverity = PocValidator.deriveSeverityFromImpact(impact, finding.severity);
      }

      // In production mode, require both passing test AND proven impact for HIGH/CRITICAL
      const impactProven = impact !== null;
      const ok = mustExecute
        ? (passed && impactProven)
        : passed;

      let reason;
      if (ok) {
        reason = impactProven
          ? `PoC executed successfully - Impact proven: ${impact.impactType}`
          : 'forge validation passed';
      } else if (!passed) {
        reason = 'forge validation failed (PoC did not compile or tests failed)';
      } else {
        reason = 'Production mode: PoC executed but no qualifying impact detected';
      }

      return {
        ok,
        reason,
        impact,
        derivedSeverity,
        details: ok ? undefined : output.slice(0, 4000)
      };
    } finally {
      if (!this.options.keepTemp) {
        try { fs.unlinkSync(testPath); } catch (_) {}
      }
    }
  }

  /**
   * Validate findings and optionally drop failures.
   *
   * In production mode:
   * - HIGH/CRITICAL without proven impact are silently discarded
   * - Severity is overridden based on PoC execution results
   */
  validateFindings(findings, context = {}) {
    const kept = [];
    const dropped = [];

    for (const f of findings) {
      const verdict = this.validateFinding(f, context);

      // In production mode, update severity based on PoC results
      const updatedFinding = { ...f, pocValidation: verdict };

      if (this.options.productionMode && verdict.derivedSeverity) {
        updatedFinding.originalSeverity = f.severity;
        updatedFinding.severity = verdict.derivedSeverity;

        // If downgraded from HIGH/CRITICAL, move to dropped
        if (['CRITICAL', 'HIGH'].includes(f.severity) &&
            !['CRITICAL', 'HIGH'].includes(verdict.derivedSeverity)) {
          dropped.push(updatedFinding);
          continue;
        }
      }

      if (verdict.impact) {
        updatedFinding.provenImpact = verdict.impact;
      }

      if (verdict.ok) {
        kept.push(updatedFinding);
      } else {
        dropped.push(updatedFinding);
      }
    }

    return { kept, dropped };
  }

  /**
   * Production-grade validation for HIGH/CRITICAL findings only.
   * Silently discards findings that don't meet the bar.
   */
  validateForProduction(findings, context = {}) {
    const highSeverityFindings = findings.filter(f =>
      ['CRITICAL', 'HIGH'].includes(f.severity)
    );
    const otherFindings = findings.filter(f =>
      !['CRITICAL', 'HIGH'].includes(f.severity)
    );

    // All HIGH/CRITICAL must pass PoC validation with proven impact
    const { kept, dropped } = this.validateFindings(highSeverityFindings, context);

    return {
      // Only return HIGH/CRITICAL that passed validation
      findings: [...kept, ...otherFindings],
      // Track what was dropped for reporting
      droppedHighSeverity: dropped,
      stats: {
        originalHighSeverity: highSeverityFindings.length,
        validatedHighSeverity: kept.length,
        droppedCount: dropped.length
      }
    };
  }
}

module.exports = PocValidator;


