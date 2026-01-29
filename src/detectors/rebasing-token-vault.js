const BaseDetector = require('./base-detector');

/**
 * Rebasing Token Vault Detector
 *
 * Detects critical vulnerabilities when vaults/pools integrate with rebasing tokens:
 * - Aave aTokens (balance increases from interest)
 * - Lido stETH (balance changes from staking rewards/slashing)
 * - Ampleforth AMPL (global rebases)
 * - Compound cTokens (exchange rate appreciation)
 *
 * Attack vectors:
 * 1. Share dilution: Rebasing rewards go to vault, not depositors
 * 2. First depositor + rebase: Attacker deposits 1 wei, waits for rebase, steals from next depositor
 * 3. Accounting mismatch: Vault tracks nominal amounts, actual balance differs
 * 4. Negative rebase: Slashing causes insufficient funds for withdrawals
 *
 * Immunefi Critical: Direct theft via accounting manipulation
 */
class RebasingTokenVaultDetector extends BaseDetector {
  constructor() {
    super(
      'Rebasing Token Vault',
      'Detects vulnerabilities in vaults integrating rebasing tokens (aTokens, stETH, AMPL)',
      'CRITICAL'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.rebasingPatterns = [];
    this.vaultPatterns = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.rebasingPatterns = [];
    this.vaultPatterns = [];

    // First pass: identify rebasing token usage and vault patterns
    this.detectRebasingTokenUsage();
    this.detectVaultPatterns();

    // Traverse AST for detailed analysis
    this.traverse(ast);

    // Analyze interactions
    this.analyzeRebasingVaultInteractions();

    return this.findings;
  }

  /**
   * Detect rebasing token interfaces/usage in code
   */
  detectRebasingTokenUsage() {
    const code = this.sourceCode;

    // Aave aToken patterns
    const aavePatterns = [
      { pattern: /IAToken|AToken|aToken/i, type: 'Aave aToken', risk: 'CRITICAL' },
      { pattern: /IPool\.supply|lendingPool\.deposit/i, type: 'Aave deposit', risk: 'HIGH' },
      { pattern: /scaledBalanceOf|getScaledUserBalanceAndSupply/i, type: 'Aave scaled balance', risk: 'MEDIUM' },
    ];

    // Lido stETH patterns
    const lidoPatterns = [
      { pattern: /IStETH|stETH|wstETH/i, type: 'Lido stETH', risk: 'CRITICAL' },
      { pattern: /getSharesByPooledEth|getPooledEthByShares/i, type: 'Lido share conversion', risk: 'HIGH' },
      { pattern: /submit\s*\(\s*\)/i, type: 'Lido staking', risk: 'MEDIUM' },
    ];

    // Ampleforth/elastic supply patterns
    const elasticPatterns = [
      { pattern: /IAMPL|Ampleforth|rebase/i, type: 'Elastic supply', risk: 'CRITICAL' },
      { pattern: /scaledTotalSupply|scaledBalance/i, type: 'Scaled accounting', risk: 'HIGH' },
    ];

    // Compound cToken patterns
    const compoundPatterns = [
      { pattern: /ICToken|cToken|CErc20/i, type: 'Compound cToken', risk: 'HIGH' },
      { pattern: /exchangeRateCurrent|exchangeRateStored/i, type: 'Compound exchange rate', risk: 'MEDIUM' },
      { pattern: /mint\s*\(.*\)|redeem\s*\(.*\)|redeemUnderlying/i, type: 'Compound ops', risk: 'MEDIUM' },
    ];

    const allPatterns = [...aavePatterns, ...lidoPatterns, ...elasticPatterns, ...compoundPatterns];

    for (const { pattern, type, risk } of allPatterns) {
      if (pattern.test(code)) {
        this.rebasingPatterns.push({ type, risk, pattern });
      }
    }
  }

  /**
   * Detect vault/share-based contract patterns
   */
  detectVaultPatterns() {
    const code = this.sourceCode;

    const vaultIndicators = [
      /totalAssets|totalShares|totalSupply/i,
      /convertToAssets|convertToShares|previewDeposit|previewWithdraw/i,
      /deposit.*shares|withdraw.*assets/i,
      /ERC4626|Vault|Pool|Strategy/i,
      /function\s+deposit\s*\(|function\s+withdraw\s*\(/i,
    ];

    this.isVaultContract = vaultIndicators.some(p => p.test(code));
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;

    // Check inheritance for vault patterns
    const baseContracts = (node.baseContracts || [])
      .map(b => b.baseName?.namePath || '')
      .join(' ');

    if (/ERC4626|Vault|Strategy|Pool/i.test(baseContracts)) {
      this.isVaultContract = true;
    }
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';

    if (!node.body) return;

    const funcCode = this.getCodeSnippet(node.loc);
    const funcName = (node.name || '').toLowerCase();

    // Skip internal/private
    if (node.visibility === 'private' || node.visibility === 'internal') {
      return;
    }

    // Analyze deposit/withdraw for rebasing issues
    if (/deposit|stake|supply/i.test(funcName)) {
      this.analyzeDepositFunction(funcCode, node);
    }

    if (/withdraw|redeem|unstake/i.test(funcName)) {
      this.analyzeWithdrawFunction(funcCode, node);
    }

    // Check for totalAssets using balanceOf (vulnerable to rebasing)
    this.checkTotalAssetsImplementation(funcCode, node);

    // Check for share calculation vulnerabilities
    this.checkShareCalculation(funcCode, node);
  }

  /**
   * Analyze deposit functions for rebasing vulnerabilities
   */
  analyzeDepositFunction(funcCode, node) {
    if (this.rebasingPatterns.length === 0) return;

    // Check if deposit uses raw balanceOf for share calculation
    const usesBalanceOf = /balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/i.test(funcCode);
    const usesTransferAmount = /amount|_amount|assets/i.test(funcCode);

    // Vulnerable pattern: shares = amount * totalShares / balanceOf(this)
    // If token rebases between deposit transactions, share calculation is wrong
    if (usesBalanceOf && !this.hasRebaseProtection(funcCode)) {
      const rebasingType = this.rebasingPatterns[0].type;

      this.addFinding({
        title: 'Rebasing Token Deposit Vulnerability',
        description: `Deposit function '${this.currentFunction}' uses balanceOf for share calculation with ${rebasingType}.\n\n` +
          `Attack scenario:\n` +
          `1. Attacker deposits 1 wei, gets 1 share\n` +
          `2. ${rebasingType} rebases (interest accrues)\n` +
          `3. Vault's balanceOf increases WITHOUT new deposits\n` +
          `4. Next depositor's shares = amount * 1 / (1 + rebaseAmount)\n` +
          `5. Depositor gets fewer shares than deserved\n` +
          `6. Attacker withdraws with inflated share value\n\n` +
          `This is a variant of the ERC4626 inflation attack specific to rebasing tokens.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: node.loc?.start?.line || 0,
        column: node.loc?.start?.column || 0,
        code: funcCode.substring(0, 400),
        severity: 'CRITICAL',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 95,
        attackVector: 'rebasing-token-vault',
        recommendation: `For ${rebasingType}:\n` +
          `1. Use internal accounting (track deposited amounts, not balanceOf)\n` +
          `2. For Aave: Use scaledBalanceOf instead of balanceOf\n` +
          `3. For Lido: Use wstETH (non-rebasing wrapper) or track shares\n` +
          `4. Add virtual shares/assets offset (OZ recommendation)\n` +
          `5. Consider fee-on-transfer style balance checking`,
        references: [
          'https://docs.aave.com/developers/tokens/atoken',
          'https://docs.lido.fi/contracts/wsteth',
          'https://blog.openzeppelin.com/a-]novel-defense-against-erc4626-inflation-attacks'
        ],
        foundryPoC: this.generateRebasingDepositPoC(rebasingType)
      });
    }
  }

  /**
   * Analyze withdraw functions for rebasing vulnerabilities
   */
  analyzeWithdrawFunction(funcCode, node) {
    if (this.rebasingPatterns.length === 0) return;

    // Check for insufficient balance handling during negative rebases
    const checksBalance = /require\s*\(.*balance|if\s*\(.*balance\s*</i.test(funcCode);
    const hasSlashingProtection = /slashing|negativeRebase|minBalance/i.test(funcCode);

    // Vulnerable to Lido slashing events
    if (this.rebasingPatterns.some(p => p.type.includes('Lido')) && !hasSlashingProtection) {
      this.addFinding({
        title: 'Negative Rebase (Slashing) Not Handled',
        description: `Withdraw function '${this.currentFunction}' integrates Lido stETH but doesn't handle slashing scenarios.\n\n` +
          `Risk:\n` +
          `1. Validator slashing event occurs\n` +
          `2. stETH balance decreases (negative rebase)\n` +
          `3. Vault has insufficient tokens for all withdrawal claims\n` +
          `4. Last withdrawers cannot withdraw (bank run)\n` +
          `5. Or protocol becomes insolvent\n\n` +
          `This occurred during Ethereum merge testing when stETH depegged.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: node.loc?.start?.line || 0,
        column: node.loc?.start?.column || 0,
        code: funcCode.substring(0, 300),
        severity: 'HIGH',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 70,
        attackVector: 'rebasing-token-vault',
        recommendation: `1. Track user shares, not absolute amounts\n` +
          `2. Implement pro-rata withdrawal during undercollateralization\n` +
          `3. Add slashing buffer/insurance mechanism\n` +
          `4. Use wstETH which abstracts rebasing complexity`,
        references: [
          'https://docs.lido.fi/guides/steth-integration-guide'
        ]
      });
    }
  }

  /**
   * Check totalAssets implementation for rebasing issues
   */
  checkTotalAssetsImplementation(funcCode, node) {
    const funcName = (node.name || '').toLowerCase();

    if (funcName === 'totalassets' || funcName === '_totalassets') {
      // Check if it just returns balanceOf (vulnerable with rebasing tokens)
      if (/return\s+\w+\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/i.test(funcCode)) {
        if (this.rebasingPatterns.length > 0) {
          this.addFinding({
            title: 'totalAssets Uses balanceOf With Rebasing Token',
            description: `totalAssets() returns raw balanceOf with rebasing token integration.\n\n` +
              `Problem: Rebasing tokens change balance without transfers:\n` +
              `- Aave aTokens: Balance increases from interest\n` +
              `- Lido stETH: Balance changes from rewards/slashing\n` +
              `- AMPL: Global rebases change all balances\n\n` +
              `Impact:\n` +
              `- Share price manipulation via rebase timing\n` +
              `- Sandwich attacks around rebase events\n` +
              `- First depositor attacks amplified by rebases`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: node.loc?.start?.line || 0,
            code: funcCode.substring(0, 200),
            severity: 'HIGH',
            confidence: 'HIGH',
            exploitable: true,
            exploitabilityScore: 80,
            attackVector: 'rebasing-token-vault',
            recommendation: `1. Use internal accounting that tracks deposits/withdrawals\n` +
              `2. For Aave: totalAssets = aToken.scaledBalanceOf(this) * liquidityIndex\n` +
              `3. For Lido: Track shares instead of stETH balance\n` +
              `4. Add virtual offset for inflation protection`
          });
        }
      }
    }
  }

  /**
   * Check share calculations for rebasing-specific issues
   */
  checkShareCalculation(funcCode, node) {
    // Check for division without rebasing consideration
    const hasDivision = /totalSupply\s*[><=!]\s*0\s*\?\s*.*\s*:\s*.*\s*\*\s*totalSupply\s*\/\s*totalAssets/i.test(funcCode) ||
      /amount\s*\*\s*totalSupply\s*\/\s*totalAssets/i.test(funcCode);

    if (hasDivision && this.rebasingPatterns.length > 0 && !this.hasRebaseProtection(funcCode)) {
      // Already covered by deposit analysis, skip duplicate
    }
  }

  /**
   * Check if function has rebasing-specific protections
   */
  hasRebaseProtection(funcCode) {
    const protections = [
      /scaledBalance|scaledTotalSupply/i,  // Aave scaled values
      /wstETH|wrap.*stETH/i,               // Lido wrapped version
      /virtualAssets|virtualShares/i,       // OZ inflation protection
      /internalBalance|_totalDeposited/i,   // Internal accounting
      /checkpoint|snapshot/i,               // Historical tracking
    ];

    return protections.some(p => p.test(funcCode));
  }

  /**
   * Analyze overall rebasing + vault interaction
   */
  analyzeRebasingVaultInteractions() {
    if (!this.isVaultContract || this.rebasingPatterns.length === 0) {
      return;
    }

    // Check if contract uses rebasing tokens without proper handling
    const code = this.sourceCode;

    // Look for dangerous combinations
    const hasDirectBalanceOf = /\.balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)/i.test(code);
    const hasShareMath = /totalSupply\s*[/*]/i.test(code);
    const hasProtection = this.hasRebaseProtection(code);

    if (hasDirectBalanceOf && hasShareMath && !hasProtection) {
      // General warning about rebasing integration
      const tokenTypes = this.rebasingPatterns.map(p => p.type).join(', ');

      this.addFinding({
        title: 'Vault Uses Rebasing Tokens Without Proper Accounting',
        description: `Contract '${this.currentContract}' appears to be a vault that integrates rebasing tokens (${tokenTypes}) ` +
          `but uses direct balanceOf for share calculations.\n\n` +
          `This is a critical vulnerability class that has caused multiple exploits:\n` +
          `- Rebasing rewards get trapped in contract (not distributed to depositors)\n` +
          `- Share price manipulation via rebase timing/MEV\n` +
          `- First depositor attacks amplified\n` +
          `- Potential insolvency during negative rebases (Lido slashing)`,
        location: `Contract: ${this.currentContract}`,
        line: 1,
        severity: 'CRITICAL',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 85,
        attackVector: 'rebasing-token-vault',
        recommendation: `CRITICAL: Review rebasing token integration:\n` +
          `1. Never use balanceOf for share calculations with rebasing tokens\n` +
          `2. Implement internal deposit tracking\n` +
          `3. For Aave: Use scaledBalanceOf and rayMul with liquidityIndex\n` +
          `4. For Lido: Use wstETH or track shares directly\n` +
          `5. Add virtual offset (10^decimals initial shares) per OZ recommendation`,
        references: [
          'https://docs.aave.com/developers/guides/interest-bearing-tokens',
          'https://docs.lido.fi/guides/steth-integration-guide',
          'https://blog.openzeppelin.com/a-novel-defense-against-erc4626-inflation-attacks'
        ]
      });
    }
  }

  generateRebasingDepositPoC(tokenType) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * PoC: Rebasing Token Vault Inflation Attack
 * Target: ${tokenType} integrated vault
 *
 * Demonstrates how rebasing amplifies share manipulation
 */
contract RebasingVaultExploit is Test {
    // IVault vault;
    // IERC20 rebasingToken; // aToken, stETH, etc.

    function testRebasingInflationAttack() public {
        // Setup: Deploy vault with ${tokenType}

        // Step 1: Attacker deposits minimal amount (1 wei)
        // uint256 attackerShares = vault.deposit(1, attacker);
        // assert(attackerShares == 1); // Gets 1 share

        // Step 2: Wait for rebase event
        // For Aave: Interest accrues
        // For Lido: Staking rewards distribute
        // For AMPL: Global rebase occurs
        // vm.warp(block.timestamp + 1 days);

        // Simulate rebase: vault's balanceOf increases
        // deal(address(rebasingToken), address(vault), 1000e18);

        // Step 3: Victim deposits 500e18
        // uint256 victimShares = vault.deposit(500e18, victim);
        // Expected: ~500e18 shares
        // Actual: 500e18 * 1 / 1000e18 = 0 shares (or dust)

        // Step 4: Attacker withdraws all
        // uint256 attackerAssets = vault.redeem(1, attacker, attacker);
        // Attacker gets: ~1000e18 + 500e18 = 1500e18 assets!

        // Result: Attacker stole victim's deposit via rebase timing
    }
}`;
  }
}

module.exports = RebasingTokenVaultDetector;
