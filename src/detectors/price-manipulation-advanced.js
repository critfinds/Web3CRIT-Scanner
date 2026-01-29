const BaseDetector = require('./base-detector');

/**
 * Advanced Price Manipulation Detector
 *
 * Detects sophisticated price manipulation vectors in high-TVL DeFi:
 * - Multi-block price manipulation (sustained manipulation)
 * - Cross-pool arbitrage exploitation
 * - Curve/Balancer-specific vulnerabilities
 * - Liquidation price manipulation
 * - LP token price manipulation
 *
 * Based on real Immunefi bounties:
 * - Cream Finance ($130M) - Oracle manipulation
 * - Harvest Finance ($34M) - USDC/USDT pool manipulation
 * - Warp Finance ($7.7M) - LP token pricing
 * - Inverse Finance ($15M) - Price oracle attack
 *
 * Immunefi Critical: Direct theft via price manipulation
 */
class AdvancedPriceManipulationDetector extends BaseDetector {
  constructor() {
    super(
      'Advanced Price Manipulation',
      'Detects sophisticated price manipulation vulnerabilities in DeFi',
      'CRITICAL'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.priceReads = [];
    this.valueOperations = [];
    this.poolInteractions = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.priceReads = [];
    this.valueOperations = [];
    this.poolInteractions = [];

    // Detect protocol patterns
    this.detectProtocolPatterns();

    this.traverse(ast);
    this.analyzePriceManipulationVectors();

    return this.findings;
  }

  /**
   * Detect which DeFi protocols are being used
   */
  detectProtocolPatterns() {
    const code = this.sourceCode;

    this.protocols = {
      uniswapV2: /IUniswapV2|UniswapV2|getReserves|addLiquidity|removeLiquidity/i.test(code),
      uniswapV3: /IUniswapV3|UniswapV3|slot0|sqrtPriceX96|observe/i.test(code),
      curve: /ICurve|CurvePool|get_dy|get_virtual_price|exchange/i.test(code),
      balancer: /IBalancer|BalancerVault|getPoolTokens|flashLoan/i.test(code),
      aave: /IAave|LendingPool|getReserveData|getUserAccountData/i.test(code),
      compound: /IComptroller|ICToken|getAccountLiquidity|exchangeRate/i.test(code),
      chainlink: /AggregatorV3|latestRoundData|latestAnswer/i.test(code),
    };

    this.isLendingProtocol = this.protocols.aave || this.protocols.compound ||
      /borrow|liquidat|collateral|healthFactor/i.test(code);

    this.isAMM = this.protocols.uniswapV2 || this.protocols.uniswapV3 ||
      this.protocols.curve || this.protocols.balancer;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';

    if (!node.body) return;
    if (node.visibility === 'private' || node.visibility === 'internal') return;

    const funcCode = this.getCodeSnippet(node.loc);
    const funcName = (node.name || '').toLowerCase();

    // Detect LP token pricing issues
    this.detectLPTokenPricing(funcCode, node);

    // Detect Curve-specific vulnerabilities
    this.detectCurveVulnerabilities(funcCode, node);

    // Detect Balancer-specific vulnerabilities
    this.detectBalancerVulnerabilities(funcCode, node);

    // Detect liquidation price manipulation
    this.detectLiquidationManipulation(funcCode, node);

    // Detect cross-pool price reliance
    this.detectCrossPoolReliance(funcCode, node);

    // Detect same-block price usage
    this.detectSameBlockPricing(funcCode, node);
  }

  /**
   * Detect LP token pricing vulnerabilities
   * Attack: Manipulate reserves → inflate/deflate LP token price → exploit
   */
  detectLPTokenPricing(funcCode, node) {
    // LP token value = sqrt(reserve0 * reserve1) * 2 / totalSupply
    // Or: LP token value = (reserve0/supply + reserve1/supply) * prices
    const lpPricingPatterns = [
      /getReserves.*totalSupply|totalSupply.*getReserves/i,
      /sqrt\s*\(.*reserve.*reserve/i,
      /lpToken.*price|price.*lpToken/i,
      /underlying.*lp|lp.*underlying/i,
    ];

    const hasLPPricing = lpPricingPatterns.some(p => p.test(funcCode));

    if (hasLPPricing) {
      // Check if price is used in value operations
      const usedForValue = /collateral|borrow|liquidat|mint.*share|withdraw/i.test(funcCode);

      if (usedForValue) {
        // Check for manipulation protection
        const hasProtection = /twap|average|delay|snapshot|checkpoint/i.test(funcCode);

        if (!hasProtection) {
          this.addFinding({
            title: 'LP Token Price Manipulation Vulnerability',
            description: `Function '${this.currentFunction}' uses LP token pricing for value operations without manipulation protection.\n\n` +
              `Attack (Warp Finance style):\n` +
              `1. Flash loan large amount of underlying tokens\n` +
              `2. Add to pool, manipulating reserves\n` +
              `3. LP token price artificially inflated\n` +
              `4. Use overvalued LP as collateral or calculate shares\n` +
              `5. Extract value (borrow, mint shares, etc.)\n` +
              `6. Remove liquidity, repay flash loan\n\n` +
              `Real-world exploits:\n` +
              `- Warp Finance: $7.7M stolen\n` +
              `- Value DeFi: $6M stolen\n` +
              `- Cheese Bank: $3.3M stolen`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: node.loc?.start?.line || 0,
            code: funcCode.substring(0, 400),
            severity: 'CRITICAL',
            confidence: 'HIGH',
            exploitable: true,
            exploitabilityScore: 95,
            attackVector: 'lp-token-manipulation',
            recommendation: `1. Use TWAP for LP token pricing\n` +
              `2. Use fair LP pricing: 2 * sqrt(r0 * r1) / supply (Alpha Homora formula)\n` +
              `3. Add minimum liquidity checks\n` +
              `4. Verify reserves haven't changed in same block\n` +
              `5. Consider Chainlink LP token price feeds`,
            references: [
              'https://cmichel.io/pricing-lp-tokens/',
              'https://blog.alphafinance.io/fair-lp-token-pricing/'
            ],
            foundryPoC: this.generateLPManipulationPoC()
          });
        }
      }
    }
  }

  /**
   * Detect Curve-specific vulnerabilities
   */
  detectCurveVulnerabilities(funcCode, node) {
    if (!this.protocols.curve) return;

    // Curve virtual price manipulation
    const usesVirtualPrice = /get_virtual_price|virtualPrice/i.test(funcCode);

    if (usesVirtualPrice) {
      // Check if used during reentrancy-susceptible operations
      const hasReentrancyRisk = /\.call\s*\{|withdraw|remove_liquidity/i.test(funcCode);

      if (hasReentrancyRisk) {
        this.addFinding({
          title: 'Curve Read-Only Reentrancy via virtual_price',
          description: `Function '${this.currentFunction}' reads Curve virtual_price which is vulnerable to read-only reentrancy.\n\n` +
            `Attack (2022 Curve/Vyper exploits):\n` +
            `1. Call remove_liquidity on Curve pool\n` +
            `2. During callback (ETH transfer), reenter victim contract\n` +
            `3. Victim reads stale virtual_price (not yet updated)\n` +
            `4. Virtual price appears higher than actual\n` +
            `5. Attacker profits from price discrepancy\n\n` +
            `This affected multiple protocols integrating Curve.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 300),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 90,
          attackVector: 'curve-readonly-reentrancy',
          recommendation: `1. Add reentrancy guard that covers virtual_price reads\n` +
            `2. Use Curve's reentrancy lock: raw_call(pool, method_id("claim_admin_fees()"))\n` +
            `3. Cache virtual_price at start of transaction\n` +
            `4. Don't use virtual_price for immediate pricing decisions`,
          references: [
            'https://chainsecurity.com/heartbreak-curve-lp-oracle-manipulation/'
          ]
        });
      }
    }

    // Curve get_dy spot price
    const usesGetDy = /get_dy\s*\(|calc_token_amount/i.test(funcCode);

    if (usesGetDy) {
      const usedForValue = /collateral|borrow|mint|price/i.test(funcCode);

      if (usedForValue) {
        this.addFinding({
          title: 'Curve Spot Price (get_dy) Used for Valuation',
          description: `Function '${this.currentFunction}' uses Curve's get_dy for pricing, which returns spot price and is manipulable.\n\n` +
            `Issue: get_dy returns current exchange rate, which can be manipulated by:\n` +
            `1. Large swaps that move the curve\n` +
            `2. Flash loans providing temporary liquidity\n` +
            `3. Imbalanced pool additions\n\n` +
            `For valuation, use oracle prices or time-weighted calculations.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 200),
          severity: 'HIGH',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 75,
          attackVector: 'curve-spot-price',
          recommendation: `1. Use Chainlink price feeds for token valuation\n` +
            `2. Implement TWAP over Curve trades\n` +
            `3. Add slippage protection for swaps`
        });
      }
    }
  }

  /**
   * Detect Balancer-specific vulnerabilities
   */
  detectBalancerVulnerabilities(funcCode, node) {
    if (!this.protocols.balancer) return;

    // Balancer flash loan + pool manipulation
    const hasFlashLoan = /flashLoan|onFlashLoan|receiveFlashLoan/i.test(funcCode);
    const hasPoolOps = /getPoolTokens|joinPool|exitPool/i.test(funcCode);

    if (hasFlashLoan && hasPoolOps) {
      this.addFinding({
        title: 'Balancer Flash Loan Pool Manipulation Risk',
        description: `Function '${this.currentFunction}' combines Balancer flash loans with pool operations.\n\n` +
          `Risk: Balancer flash loans are free (no fee for returning same block), enabling:\n` +
          `1. Borrow all pool tokens via flash loan\n` +
          `2. Manipulate pool balances/prices\n` +
          `3. Execute exploit during manipulation\n` +
          `4. Return tokens\n\n` +
          `Ensure price reads don't occur during flashloan-susceptible states.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: node.loc?.start?.line || 0,
        code: funcCode.substring(0, 300),
        severity: 'HIGH',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 70,
        attackVector: 'balancer-flash-manipulation',
        recommendation: `1. Don't read pool prices during flash loan callbacks\n` +
          `2. Verify pool state hasn't changed unexpectedly\n` +
          `3. Use external oracles for pricing\n` +
          `4. Add reentrancy protection`
      });
    }

    // Balancer getRate for valuation
    const usesGetRate = /getRate\s*\(|getRateProviders/i.test(funcCode);

    if (usesGetRate) {
      const usedForCollateral = /collateral|borrow|health|liquidat/i.test(funcCode);

      if (usedForCollateral) {
        this.addFinding({
          title: 'Balancer Rate Provider Used for Collateral Valuation',
          description: `Function uses Balancer rate provider for collateral valuation.\n\n` +
            `Risk: Rate providers can be manipulated or become stale.\n` +
            `Some rate providers read from pools that can be manipulated.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 60,
          attackVector: 'balancer-rate-manipulation',
          recommendation: `1. Verify rate provider source is manipulation-resistant\n` +
            `2. Add sanity bounds on rate changes\n` +
            `3. Consider backup oracles`
        });
      }
    }
  }

  /**
   * Detect liquidation price manipulation
   */
  detectLiquidationManipulation(funcCode, node) {
    if (!this.isLendingProtocol) return;

    const funcName = (node.name || '').toLowerCase();

    if (/liquidat/i.test(funcName) || /liquidat/i.test(funcCode)) {
      // Check if liquidation uses spot prices
      const usesSpotPrice = /getReserves|slot0|get_dy|balanceOf.*balanceOf/i.test(funcCode);
      const usesOracle = /latestRoundData|getAssetPrice|oracle/i.test(funcCode);

      if (usesSpotPrice && !usesOracle) {
        this.addFinding({
          title: 'Liquidation Uses Manipulable Spot Price',
          description: `Liquidation function '${this.currentFunction}' uses spot prices instead of oracles.\n\n` +
            `Attack (Inverse Finance style):\n` +
            `1. Open leveraged position at normal prices\n` +
            `2. Flash loan to manipulate spot price downward\n` +
            `3. Trigger liquidation of victims (including self-liquidation for profit)\n` +
            `4. Restore price, repay flash loan\n` +
            `5. Profit from liquidation bonus\n\n` +
            `Inverse Finance lost $15M to this attack pattern.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 300),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 95,
          attackVector: 'liquidation-manipulation',
          recommendation: `1. Use Chainlink oracles for liquidation prices\n` +
            `2. Add circuit breakers for rapid price changes\n` +
            `3. Implement time-delayed liquidations\n` +
            `4. Use TWAP as fallback\n` +
            `5. Add maximum liquidation amounts per block`,
          references: [
            'https://rekt.news/inverse-finance-rekt/'
          ]
        });
      }

      // Check for same-block liquidation
      const allowsSameBlockLiquidation = !/blockNumber.*!=|lastUpdate.*<|delay/i.test(funcCode);

      if (allowsSameBlockLiquidation && usesOracle) {
        this.addFinding({
          title: 'Same-Block Liquidation Allowed',
          description: `Liquidation in '${this.currentFunction}' can occur in the same block as position changes.\n\n` +
            `Risk:\n` +
            `1. Attacker manipulates oracle in block N\n` +
            `2. Opens position + liquidates victim in same block\n` +
            `3. Oracle manipulation is never observed externally\n\n` +
            `This enables atomic MEV-style liquidation attacks.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          severity: 'HIGH',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 70,
          attackVector: 'same-block-liquidation',
          recommendation: `1. Require minimum time between position change and liquidation\n` +
            `2. Use block.number checks to prevent same-block liquidation\n` +
            `3. Implement gradual liquidation with time delays`
        });
      }
    }
  }

  /**
   * Detect cross-pool price reliance
   */
  detectCrossPoolReliance(funcCode, node) {
    // Multiple pool reads in same function
    const poolPatterns = [
      /getReserves/gi,
      /slot0/gi,
      /get_dy/gi,
      /getPoolTokens/gi,
    ];

    let poolReadCount = 0;
    for (const pattern of poolPatterns) {
      const matches = funcCode.match(pattern);
      if (matches) poolReadCount += matches.length;
    }

    if (poolReadCount >= 2) {
      // Multiple pools read - check for arbitrage/manipulation risk
      this.addFinding({
        title: 'Cross-Pool Price Dependency Detected',
        description: `Function '${this.currentFunction}' reads prices from multiple pools.\n\n` +
          `Risk: Cross-pool manipulation attack:\n` +
          `1. Attacker manipulates Pool A price up\n` +
          `2. Contract reads Pool A price for valuation\n` +
          `3. Attacker uses overvalued position\n` +
          `4. Attacker manipulates Pool B for arbitrage profit\n\n` +
          `This creates complex manipulation opportunities.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: node.loc?.start?.line || 0,
        code: funcCode.substring(0, 300),
        severity: 'HIGH',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 65,
        attackVector: 'cross-pool-manipulation',
        recommendation: `1. Use same oracle source for related assets\n` +
          `2. Add cross-pool price deviation checks\n` +
          `3. Implement maximum price impact limits\n` +
          `4. Consider circuit breakers for extreme deviations`
      });
    }
  }

  /**
   * Detect same-block price usage issues
   */
  detectSameBlockPricing(funcCode, node) {
    // Check if price is read and used without block delay
    const readsPriceOrReserves = /getReserves|slot0|latestRoundData|getAssetPrice|balanceOf/i.test(funcCode);
    const hasValueOperation = /mint|burn|swap|borrow|withdraw|deposit/i.test(funcCode);
    const hasBlockCheck = /block\.number\s*!=|lastBlock|blockDelay|_lastUpdateBlock/i.test(funcCode);

    if (readsPriceOrReserves && hasValueOperation && !hasBlockCheck) {
      // Check if it's a swap function (expected behavior)
      const funcName = (node.name || '').toLowerCase();
      if (/^swap|^exchange/i.test(funcName)) {
        return; // Swaps need current price
      }

      this.addFinding({
        title: 'Price Used Without Block Delay Protection',
        description: `Function '${this.currentFunction}' reads prices and performs value operations in potentially same block.\n\n` +
          `Risk: Atomic manipulation attack:\n` +
          `1. Manipulate price in transaction 1 of block\n` +
          `2. Call vulnerable function in transaction 2\n` +
          `3. Restore price in transaction 3\n` +
          `All in same block, appearing atomic to external observers.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: node.loc?.start?.line || 0,
        severity: 'MEDIUM',
        confidence: 'LOW',
        exploitable: true,
        exploitabilityScore: 55,
        attackVector: 'same-block-pricing',
        recommendation: `1. Track last update block for price-sensitive operations\n` +
          `2. Require price to be at least 1 block old\n` +
          `3. Use commit-reveal pattern for large operations`
      });
    }
  }

  /**
   * Analyze collected price manipulation vectors
   */
  analyzePriceManipulationVectors() {
    // Check for dangerous protocol combinations
    if (this.protocols.uniswapV2 && this.isLendingProtocol) {
      // UniV2 spot price + lending = classic attack surface
      const hasOracleProtection = this.protocols.chainlink ||
        /twap|timeWeighted|average/i.test(this.sourceCode);

      if (!hasOracleProtection) {
        this.addFinding({
          title: 'Lending Protocol Uses Uniswap V2 Spot Prices',
          description: `Contract combines lending functionality with Uniswap V2 price reads without oracle protection.\n\n` +
            `This is the classic attack pattern used in:\n` +
            `- bZx ($8M)\n` +
            `- Harvest Finance ($34M)\n` +
            `- Cream Finance ($130M)\n\n` +
            `UniV2 reserves can be manipulated within a single transaction via flash loans.`,
          location: `Contract: ${this.currentContract}`,
          line: 1,
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 95,
          attackVector: 'univ2-lending-manipulation',
          recommendation: `CRITICAL: Never use UniV2 spot prices for lending:\n` +
            `1. Use Chainlink price feeds\n` +
            `2. Implement UniV2 TWAP (30+ minute window)\n` +
            `3. Add price deviation circuit breakers\n` +
            `4. Consider using UniV3 TWAP`,
          references: [
            'https://samczsun.com/taking-undercollateralized-loans-for-fun-and-for-profit/'
          ]
        });
      }
    }
  }

  generateLPManipulationPoC() {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * PoC: LP Token Price Manipulation (Warp Finance style)
 */
contract LPManipulationExploit is Test {
    // ILendingProtocol lending;
    // IUniswapV2Pair lpToken;
    // IERC20 token0;
    // IERC20 token1;

    function testLPManipulation() public {
        // Setup: Get flash loan for manipulation capital

        // Step 1: Add massive liquidity to inflate LP price
        // uint256 loanAmount = 10_000_000e18;
        // token0.approve(address(router), loanAmount);
        // token1.approve(address(router), loanAmount);
        // router.addLiquidity(...);

        // LP token price is now artificially high

        // Step 2: Deposit inflated LP as collateral
        // lpToken.approve(address(lending), lpBalance);
        // lending.depositCollateral(address(lpToken), lpBalance);

        // Step 3: Borrow against inflated collateral
        // uint256 maxBorrow = lending.getMaxBorrow(address(this));
        // lending.borrow(maxBorrow);

        // Step 4: Remove liquidity (deflates LP price)
        // router.removeLiquidity(...);

        // Step 5: Repay flash loan
        // Profit = borrowed amount - flash loan fee

        // Victim: Lending protocol is now undercollateralized
    }
}`;
  }
}

module.exports = AdvancedPriceManipulationDetector;
