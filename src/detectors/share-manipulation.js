const BaseDetector = require('./base-detector');

/**
 * Share/Vault Manipulation Detector
 * Detects vulnerabilities in vault/share-based systems:
 * - First depositor / vault inflation attacks
 * - Share price manipulation
 * - Donation attacks
 * - Rounding exploitation
 *
 * Immunefi Critical: Direct theft of depositor funds
 */
class ShareManipulationDetector extends BaseDetector {
  constructor() {
    super(
      'Share Manipulation',
      'Detects vault share manipulation vulnerabilities for fund theft',
      'CRITICAL'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.vaultPatterns = [];
    this.shareCalculations = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.vaultPatterns = [];
    this.shareCalculations = [];

    this.traverse(ast);
    this.analyzeVaultPatterns();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;

    // Identify vault-like contracts
    const baseContracts = (node.baseContracts || []).map(b =>
      b.baseName?.namePath || ''
    ).join(' ');

    const isVault = /Vault|ERC4626|Strategy|Pool|Staking|Yield/i.test(this.currentContract) ||
                   /Vault|ERC4626|Strategy|Pool|Staking|Yield/i.test(baseContracts);

    if (isVault) {
      this.vaultPatterns.push({
        contract: this.currentContract,
        node: node
      });
    }
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';

    if (!node.body) return;

    const funcCode = this.getCodeSnippet(node.loc);
    const funcName = (node.name || '').toLowerCase();

    // Skip internal functions
    if (node.visibility === 'private' || node.visibility === 'internal') {
      return;
    }

    // Detect deposit/mint functions
    if (/deposit|mint|stake|supply/i.test(funcName)) {
      this.analyzeDepositFunction(funcCode, node);
    }

    // Detect withdraw/redeem functions
    if (/withdraw|redeem|unstake|remove/i.test(funcName)) {
      this.analyzeWithdrawFunction(funcCode, node);
    }

    // Detect share calculation functions
    if (/convertToShares|convertToAssets|previewDeposit|previewMint|pricePerShare/i.test(funcName)) {
      this.analyzeShareCalculation(funcCode, node);
    }

    // Detect general share/asset ratio calculations
    this.detectSharePriceManipulation(funcCode, node);
  }

  /**
   * Analyze deposit function for first depositor attacks
   */
  analyzeDepositFunction(funcCode, node) {
    // Check for share minting logic
    const hasShareMinting = /shares\s*=|_mint\s*\(|mint\s*\(/.test(funcCode);

    if (!hasShareMinting) return;

    // Check for first depositor protection
    const hasFirstDepositorProtection =
      /totalSupply\s*\(\s*\)\s*==\s*0.*?[+]|MINIMUM_LIQUIDITY|dead.*shares|_mint.*0x.*dead|virtualAssets|virtualShares/i.test(funcCode);

    const hasMinDeposit = /require.*amount\s*>=|MIN_DEPOSIT|minimumDeposit/i.test(funcCode);

    if (!hasFirstDepositorProtection && !hasMinDeposit) {
      // Check if it's a division-based share calculation
      const hasDivisionCalc = /\/\s*totalSupply|\/\s*totalAssets|\*\s*totalSupply.*\/|shares\s*=.*\//.test(funcCode);

      if (hasDivisionCalc) {
        this.addFinding({
          title: 'First Depositor Vault Inflation Attack',
          description: `Function '${this.currentFunction}' in vault '${this.currentContract}' is vulnerable to first depositor attack:

Attack scenario:
1. Attacker is first depositor, deposits minimal amount (1 wei)
2. Attacker receives 1 share (1:1 for first deposit)
3. Attacker donates large amount directly to vault (transfers tokens)
4. Share price inflates: 1 share = 1 wei + donation
5. Victim deposits X tokens
6. Due to rounding: victim receives 0 shares (X < share price)
7. Attacker redeems 1 share, receives victim's deposit + original donation

This results in complete theft of victim deposits.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          column: node.loc?.start?.column || 0,
          code: funcCode.substring(0, 400),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 95,
          attackVector: 'first-depositor-inflation',
          recommendation: `Implement first depositor protection:

1. Virtual shares/assets (OpenZeppelin ERC4626 pattern):
   function _decimalsOffset() internal pure returns (uint8) { return 3; }

2. Minimum initial deposit:
   require(totalSupply() > 0 || amount >= MIN_DEPOSIT);

3. Dead shares on first deposit:
   if (totalSupply() == 0) {
       _mint(address(0xdead), MINIMUM_SHARES);
   }

4. Use internal accounting instead of balanceOf()`,
          references: [
            'https://blog.openzeppelin.com/a-]]]novel-defense-against-erc4626-inflation-attacks',
            'https://docs.openzeppelin.com/contracts/4.x/erc4626'
          ],
          foundryPoC: this.generateFirstDepositorPoC()
        });
      }
    }
  }

  /**
   * Analyze withdraw function for manipulation
   */
  analyzeWithdrawFunction(funcCode, node) {
    // Check for rounding direction
    const hasRoundDown = /mulDiv.*DOWN|roundDown|\/ totalSupply/i.test(funcCode);
    const hasRoundUp = /mulDiv.*UP|roundUp|ceil/i.test(funcCode);

    // Withdrawals should round down (in favor of vault)
    if (hasRoundUp && !hasRoundDown) {
      this.addFinding({
        title: 'Withdrawal Rounds Up (Favors User)',
        description: `Function '${this.currentFunction}' appears to round up on withdrawal calculations. This allows users to extract more value than entitled through repeated small withdrawals.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: node.loc?.start?.line || 0,
        code: funcCode.substring(0, 200),
        severity: 'HIGH',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 70,
        attackVector: 'rounding-exploit',
        recommendation: 'Round down for withdrawals (in favor of vault): assets = shares.mulDiv(totalAssets, totalSupply, Math.Rounding.Down)'
      });
    }

    // Check for flash loan withdrawal
    if (/balanceOf\s*\(address\s*\(this\)\)|\.balance/.test(funcCode)) {
      if (!/internalBalance|_totalAssets|checkpoint/i.test(funcCode)) {
        this.addFinding({
          title: 'Withdrawal Uses Manipulable Balance',
          description: `Function '${this.currentFunction}' calculates withdrawal amounts using real-time balance (balanceOf/balance) which can be manipulated via flash loans or donations.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 200),
          severity: 'HIGH',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 80,
          attackVector: 'balance-manipulation',
          recommendation: 'Use internal accounting that tracks deposits/withdrawals rather than raw balanceOf(). Implement donation attack protection.'
        });
      }
    }
  }

  /**
   * Analyze share calculation for manipulation vectors
   */
  analyzeShareCalculation(funcCode, node) {
    // Division by totalSupply without protection
    if (/\/\s*totalSupply\s*\(\s*\)/.test(funcCode)) {
      if (!/totalSupply\s*\(\s*\)\s*==\s*0|totalSupply\s*>\s*0|virtualShares/i.test(funcCode)) {
        this.addFinding({
          title: 'Division by Zero Risk in Share Calculation',
          description: `Function '${this.currentFunction}' divides by totalSupply without checking for zero. When totalSupply is 0, this reverts, potentially causing DoS or undefined behavior.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 200),
          severity: 'HIGH',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 65,
          attackVector: 'division-by-zero',
          recommendation: 'Handle zero totalSupply case: return totalSupply == 0 ? assets : assets.mulDiv(totalSupply, totalAssets)'
        });
      }
    }

    // totalAssets from external call (manipulable)
    if (/totalAssets\s*\(\s*\)/.test(funcCode)) {
      // Check if totalAssets uses balanceOf
      const totalAssetsPattern = /function\s+totalAssets[^{]*\{[^}]*balanceOf/;
      if (totalAssetsPattern.test(this.sourceCode)) {
        this.addFinding({
          title: 'totalAssets() Uses Manipulable balanceOf()',
          description: `Share calculations use totalAssets() which appears to use balanceOf(). Attacker can manipulate share price by donating tokens directly to the vault before/after key operations.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 200),
          severity: 'HIGH',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 75,
          attackVector: 'donation-attack',
          recommendation: `Use internal accounting for totalAssets:
- Track deposits/withdrawals in state variable
- Add virtual assets offset: totalAssets() + 1
- Consider using balanceOf only as upper bound check`
        });
      }
    }
  }

  /**
   * Detect share price manipulation patterns
   */
  detectSharePriceManipulation(funcCode, node) {
    // Direct balance usage in share calculation
    const shareCalculationWithBalance =
      /shares.*=.*balanceOf|shares.*=.*\.balance|pricePerShare.*balanceOf/i.test(funcCode);

    if (shareCalculationWithBalance) {
      this.shareCalculations.push({
        function: this.currentFunction,
        node: node,
        code: funcCode,
        usesDirectBalance: true
      });
    }

    // Exchange rate calculation
    if (/exchangeRate|pricePerShare|sharePrice|getExchangeRate/i.test(this.currentFunction || '')) {
      if (/balanceOf|\.balance/.test(funcCode)) {
        this.addFinding({
          title: 'Exchange Rate Manipulable via Donation',
          description: `Function '${this.currentFunction}' calculates exchange rate using real-time balance. Attacker can sandwich victim transactions:

1. Frontrun: Donate tokens to inflate exchange rate
2. Victim deposits at inflated rate, receives fewer shares
3. Backrun: Withdraw to capture victim's lost value`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 200),
          severity: 'HIGH',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 80,
          attackVector: 'sandwich-donation',
          recommendation: 'Use internal accounting. Add donation attack protection by separating "balance" from "accounting".'
        });
      }
    }
  }

  /**
   * Cross-analyze vault patterns
   */
  analyzeVaultPatterns() {
    // Check ERC4626 compliance issues
    if (this.vaultPatterns.length > 0 && /ERC4626|Vault/i.test(this.sourceCode)) {
      // Check for decimal offset (OZ protection)
      const hasDecimalOffset = /_decimalsOffset|virtualAssets|virtualShares/i.test(this.sourceCode);

      if (!hasDecimalOffset) {
        // Already covered by first depositor finding, but add context
      }

      // Check for preview function accuracy
      const hasPreview = /previewDeposit|previewMint|previewWithdraw|previewRedeem/i.test(this.sourceCode);
      if (hasPreview) {
        // Check if previews account for fees
        const previewAccountsFees = /fee|slippage|preview.*fee/i.test(this.sourceCode);
        if (!previewAccountsFees && /fee|Fee/i.test(this.sourceCode)) {
          this.addFinding({
            title: 'Preview Functions May Not Account for Fees',
            description: `Vault implements fees but preview functions may not accurately reflect them. This can cause user transactions to fail or receive unexpected amounts.`,
            location: `Contract: ${this.vaultPatterns[0].contract}`,
            line: this.vaultPatterns[0].node.loc?.start?.line || 0,
            severity: 'MEDIUM',
            confidence: 'LOW',
            exploitable: false,
            exploitabilityScore: 40,
            attackVector: 'preview-mismatch',
            recommendation: 'Ensure preview functions return accurate values inclusive of fees per ERC4626 spec.'
          });
        }
      }
    }
  }

  generateFirstDepositorPoC() {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "forge-std/console.sol";

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface IVault {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

contract FirstDepositorAttack is Test {
    IVault vault;
    IERC20 asset;

    address attacker = address(0xBAD);
    address victim = address(0xBEEF);

    function setUp() public {
        // Deploy vault and asset token
        // vault = IVault(address(new VulnerableVault(address(asset))));
        // Fund accounts
        // deal(address(asset), attacker, 10000e18);
        // deal(address(asset), victim, 1000e18);
    }

    function testFirstDepositorAttack() public {
        uint256 victimDeposit = 1000e18;
        uint256 donationAmount = 10000e18;

        // Step 1: Attacker deposits 1 wei first
        vm.startPrank(attacker);
        // asset.approve(address(vault), type(uint256).max);
        // vault.deposit(1, attacker);
        console.log("Attacker shares after first deposit:", vault.balanceOf(attacker));
        // Attacker has 1 share

        // Step 2: Attacker donates large amount directly to vault
        // asset.transfer(address(vault), donationAmount);
        console.log("Vault balance after donation:", asset.balanceOf(address(vault)));
        // Vault now has 1 + donationAmount tokens, still 1 share

        vm.stopPrank();

        // Step 3: Victim deposits
        vm.startPrank(victim);
        // asset.approve(address(vault), type(uint256).max);

        // uint256 victimSharesBefore = vault.totalSupply();
        // vault.deposit(victimDeposit, victim);
        // uint256 victimShares = vault.balanceOf(victim);

        console.log("Victim shares received:", vault.balanceOf(victim));
        // Victim receives 0 shares due to rounding!
        // victimDeposit / (1 + donationAmount) = 0 (rounds down)

        vm.stopPrank();

        // Step 4: Attacker redeems their 1 share
        vm.startPrank(attacker);
        // uint256 attackerAssets = vault.redeem(1, attacker, attacker);
        // console.log("Attacker receives:", attackerAssets);
        // Attacker gets: original donation + victim's deposit!
        vm.stopPrank();

        // Verify attack success
        // assertEq(vault.balanceOf(victim), 0, "Victim should have 0 shares");
        // assertGt(attackerAssets, donationAmount, "Attacker should profit");
    }
}`;
  }
}

module.exports = ShareManipulationDetector;
