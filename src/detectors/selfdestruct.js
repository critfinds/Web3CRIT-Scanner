const BaseDetector = require('./base-detector');

/**
 * Unprotected Selfdestruct Detector (Hardened)
 *
 * Only reports CRITICAL findings with concrete fund-theft impact:
 * - Unprotected selfdestruct (anyone can destroy and steal funds)
 * - Weak access control on selfdestruct (bypassable protection)
 *
 * Does NOT report:
 * - Properly protected selfdestruct (admin-only with valid checks)
 * - Informational "selfdestruct present" notices
 */
class UnprotectedSelfdestructDetector extends BaseDetector {
  constructor() {
    super(
      'Unprotected Selfdestruct',
      'Detects exploitable selfdestruct calls that enable fund theft',
      'CRITICAL'
    );
    this.reportedLocations = new Set(); // Dedupe by location
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.reportedLocations = new Set();
    return super.detect(ast, sourceCode, fileName, cfg, dataFlow);
  }

  visitFunctionDefinition(node) {
    // Store current function context for nested checks
    // NOTE: Do NOT call this.traverse() here - base class handles traversal
    this.currentFunction = node;
  }

  visitFunctionCall(node) {
    const code = this.getCodeSnippet(node.loc);
    const line = node.loc ? node.loc.start.line : 0;

    // Check for selfdestruct or suicide (deprecated)
    if (code.includes('selfdestruct(') || code.includes('suicide(')) {
      // Dedupe: only report once per line
      const locationKey = `${this.fileName}:${line}`;
      if (this.reportedLocations.has(locationKey)) {
        return;
      }
      this.reportedLocations.add(locationKey);

      this.checkSelfdestructCall(node, code, line);
    }
  }

  checkSelfdestructCall(node, code, line) {
    const functionContext = this.currentFunction;
    const functionName = functionContext?.name || 'fallback/receive';
    const visibility = functionContext?.visibility || 'public';

    // Skip private/internal functions (not directly exploitable)
    if (visibility === 'private' || visibility === 'internal') {
      return;
    }

    // Check access control quality
    const accessAnalysis = this.analyzeAccessControl(functionContext, code);

    // Determine if user controls recipient (increases severity)
    const userControlledRecipient = this.isUserControlledRecipient(code);

    if (accessAnalysis.level === 'none') {
      // CRITICAL: Completely unprotected selfdestruct
      this.addFinding({
        title: 'Unprotected Selfdestruct',
        description: `Function '${functionName}' contains selfdestruct without ANY access control. ` +
          `Any user can destroy the contract and ${userControlledRecipient ? 'redirect all funds to their address' : 'steal all funds'}.\n\n` +
          `Attack: Simply call ${functionName}() to destroy contract and extract ${userControlledRecipient ? 'funds to attacker address' : 'all ETH'}.`,
        location: `Function: ${functionName}`,
        line: line,
        column: node.loc ? node.loc.start.column : 0,
        code: code,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 100,
        attackVector: 'selfdestruct',
        recommendation: 'Remove selfdestruct entirely, or add strict multi-sig + timelock protection. Note: selfdestruct is deprecated (EIP-6049) and will change behavior in future upgrades.',
        references: [
          'https://swcregistry.io/docs/SWC-106',
          'https://eips.ethereum.org/EIPS/eip-6049'
        ],
        foundryPoC: this.generateSelfdestructPoC(functionName, userControlledRecipient)
      });
    } else if (accessAnalysis.level === 'broken') {
      // CRITICAL: Access control exists but is broken/bypassable
      this.addFinding({
        title: 'Broken Access Control on Selfdestruct',
        description: `Function '${functionName}' has selfdestruct with BROKEN access control: ${accessAnalysis.reason}. ` +
          `Attacker can bypass the check and destroy the contract.\n\n` +
          `Vulnerability: ${accessAnalysis.reason}`,
        location: `Function: ${functionName}`,
        line: line,
        column: node.loc ? node.loc.start.column : 0,
        code: code,
        severity: 'CRITICAL',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 95,
        attackVector: 'selfdestruct',
        recommendation: `Fix the access control: ${accessAnalysis.fix}`,
        references: [
          'https://swcregistry.io/docs/SWC-106'
        ]
      });
    } else if (accessAnalysis.level === 'weak') {
      // HIGH: Weak access control (tx.origin, balance-based, timestamp)
      this.addFinding({
        title: 'Weak Access Control on Selfdestruct',
        description: `Function '${functionName}' has selfdestruct with WEAK access control: ${accessAnalysis.reason}. ` +
          `This may be exploitable under certain conditions.`,
        location: `Function: ${functionName}`,
        line: line,
        column: node.loc ? node.loc.start.column : 0,
        code: code,
        severity: 'HIGH',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 75,
        attackVector: 'selfdestruct',
        recommendation: `Strengthen access control: ${accessAnalysis.fix}`,
        references: [
          'https://swcregistry.io/docs/SWC-106'
        ]
      });
    }
    // Note: Strong access control = no finding (not a vulnerability)
  }

  analyzeAccessControl(functionNode, code) {
    if (!functionNode) {
      return { level: 'none', reason: 'No function context (fallback/receive)' };
    }

    // Check for modifiers
    const modifiers = functionNode.modifiers || [];
    if (modifiers.length === 0) {
      // Check for inline require statements
      if (this.hasInlineAccessControl(code)) {
        return this.analyzeInlineAccessControl(code);
      }
      return { level: 'none', reason: 'No access control modifiers or require checks' };
    }

    // Analyze modifier quality
    for (const modifier of modifiers) {
      const modName = (modifier.name || '').toLowerCase();

      // Check for known strong patterns
      if (/^only(owner|admin|governance|role)$/i.test(modName)) {
        // Need to verify the modifier actually works (check CFG if available)
        if (this.cfg) {
          const modKey = `${this.currentContract}.${modifier.name}`;
          const modInfo = this.cfg.modifiers?.get(modKey);
          if (modInfo && modInfo.requireStatements.length === 0) {
            return { level: 'broken', reason: 'Modifier has empty body - no actual check', fix: 'Implement proper ownership check in modifier' };
          }
        }
        return { level: 'strong', reason: 'Protected by ownership modifier' };
      }
    }

    // Check code for weak patterns
    return this.analyzeInlineAccessControl(code);
  }

  hasInlineAccessControl(code) {
    return /require\s*\(|if\s*\(.*revert/i.test(code);
  }

  analyzeInlineAccessControl(code) {
    const codeLower = code.toLowerCase();

    // Check for tx.origin (phishing vulnerable)
    if (/require\s*\(\s*tx\.origin\s*==|tx\.origin\s*==.*require/i.test(code)) {
      return { level: 'weak', reason: 'Uses tx.origin (vulnerable to phishing attacks)', fix: 'Use msg.sender instead of tx.origin' };
    }

    // Check for timestamp-based (manipulable)
    if (/require\s*\(.*block\.timestamp|block\.timestamp.*require/i.test(code)) {
      return { level: 'weak', reason: 'Uses block.timestamp (manipulable by miners, will eventually pass)', fix: 'Use proper ownership check, not time-based' };
    }

    // Check for balance-based (flash loan vulnerable)
    if (/require\s*\(.*\.balance\s*>|\.balance\s*>=.*require/i.test(code)) {
      return { level: 'weak', reason: 'Uses balance-based access control (flash loan vulnerable)', fix: 'Use ownership check, not balance-based' };
    }

    // Check for proper msg.sender check
    if (/require\s*\(\s*msg\.sender\s*==\s*(owner|admin|_owner)/i.test(code)) {
      return { level: 'strong', reason: 'Protected by msg.sender ownership check' };
    }

    // Check for always-true conditions
    if (/require\s*\(\s*true\s*\)|require\s*\(\s*1\s*==\s*1\s*\)/i.test(code)) {
      return { level: 'broken', reason: 'Always-true require condition', fix: 'Implement actual access control check' };
    }

    // Has require but unclear what it checks
    if (/require\s*\(/i.test(code)) {
      return { level: 'unknown', reason: 'Has require but unclear protection' };
    }

    return { level: 'none', reason: 'No access control detected' };
  }

  isUserControlledRecipient(code) {
    // Check if recipient is user-controllable
    const userControlledPatterns = [
      /selfdestruct\s*\(\s*payable\s*\(\s*msg\.sender\s*\)\s*\)/,
      /selfdestruct\s*\(\s*msg\.sender\s*\)/,
      /selfdestruct\s*\(\s*payable\s*\(\s*[_a-zA-Z]\w*\s*\)\s*\)/,  // Parameter
      /selfdestruct\s*\(\s*[_a-zA-Z]\w*\s*\)/  // Parameter without payable
    ];
    return userControlledPatterns.some(p => p.test(code));
  }

  generateSelfdestructPoC(functionName, userControlled) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * PoC: Unprotected Selfdestruct Exploit
 * Demonstrates complete fund theft via unprotected selfdestruct
 */
contract SelfdestructExploit is Test {
    address victim;
    address attacker = address(0xBAD);

    function setUp() public {
        // Deploy victim contract and fund it
        // victim = address(new VictimContract());
        // vm.deal(victim, 100 ether);
    }

    function testExploit() public {
        uint256 victimBalanceBefore = victim.balance;
        uint256 attackerBalanceBefore = attacker.balance;

        vm.prank(attacker);
        // VictimContract(victim).${functionName}(${userControlled ? 'payable(attacker)' : ''});

        // Assert: Contract destroyed, funds stolen
        // assertEq(victim.code.length, 0, "Contract should be destroyed");
        // assertEq(attacker.balance, attackerBalanceBefore + victimBalanceBefore, "Attacker should have stolen funds");
    }
}`;
  }
}

module.exports = UnprotectedSelfdestructDetector;
