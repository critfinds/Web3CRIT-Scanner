const BaseDetector = require('./base-detector');

/**
 * Advanced Price Oracle Manipulation Detector
 * Detects vulnerable oracle patterns that can be exploited via flash loans or market manipulation
 *
 * Attack vectors detected:
 * 1. Spot price usage (getReserves, balanceOf ratio) - Flash loan manipulable
 * 2. TWAP with insufficient window - Can be manipulated over time
 * 3. Single oracle source - No redundancy
 * 4. Stale price data - Missing freshness checks
 * 5. Missing price bounds - No sanity checks on price
 * 6. Chainlink-specific issues - Missing L2 sequencer checks
 */
class OracleManipulationDetector extends BaseDetector {
  constructor() {
    super(
      'Oracle Manipulation',
      'Detects vulnerable price oracle patterns exploitable via flash loans',
      'CRITICAL'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.oracleUsages = [];
    this.chainlinkFeeds = [];
    this.twapUsages = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.oracleUsages = [];
    this.chainlinkFeeds = [];
    this.twapUsages = [];

    this.traverse(ast);

    // Analyze collected oracle patterns
    this.analyzeOraclePatterns();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';

    if (!node.body) return;

    const funcCode = this.getCodeSnippet(node.loc);
    const funcName = (node.name || '').toLowerCase();

    // Skip view functions that don't affect value
    if (node.stateMutability === 'pure') return;

    // Check for spot price patterns
    this.detectSpotPriceUsage(funcCode, node);

    // Check for TWAP usage
    this.detectTWAPUsage(funcCode, node);

    // Check for Chainlink usage
    this.detectChainlinkUsage(funcCode, node);

    // Check for price-dependent value calculations
    this.detectPriceDependentOperations(funcCode, node);
  }

  detectSpotPriceUsage(funcCode, node) {
    // Uniswap V2 spot price patterns - highly manipulable
    const uniV2Patterns = [
      { pattern: /\.getReserves\s*\(\s*\)/, name: 'getReserves', risk: 'CRITICAL' },
      { pattern: /reserve0\s*[\/\*]\s*reserve1|reserve1\s*[\/\*]\s*reserve0/, name: 'reserve_ratio', risk: 'CRITICAL' },
    ];

    // Uniswap V3 spot price - still manipulable within tick
    const uniV3Patterns = [
      { pattern: /slot0\s*\(\s*\)/, name: 'slot0', risk: 'HIGH' },
      { pattern: /sqrtPriceX96/, name: 'sqrtPriceX96', risk: 'HIGH' },
    ];

    // Balance ratio patterns - highly manipulable
    const balancePatterns = [
      { pattern: /balanceOf[^]*\/[^]*balanceOf/, name: 'balance_ratio', risk: 'CRITICAL' },
      { pattern: /getBalance[^]*\/[^]*getBalance/, name: 'balance_ratio', risk: 'CRITICAL' },
    ];

    // AMM-specific price functions
    const ammPatterns = [
      { pattern: /\.getAmountOut\s*\(/, name: 'getAmountOut', risk: 'HIGH' },
      { pattern: /\.getAmountsOut\s*\(/, name: 'getAmountsOut', risk: 'HIGH' },
      { pattern: /\.quote\s*\(/, name: 'quote', risk: 'HIGH' },
      { pattern: /calcSpotPrice/, name: 'calcSpotPrice', risk: 'CRITICAL' },
    ];

    const allPatterns = [...uniV2Patterns, ...uniV3Patterns, ...balancePatterns, ...ammPatterns];

    for (const { pattern, name, risk } of allPatterns) {
      if (pattern.test(funcCode)) {
        // Check if it's used in a meaningful value calculation
        const flowsToValue = this.flowsToValueOperation(funcCode);

        this.oracleUsages.push({
          function: this.currentFunction,
          node: node,
          type: 'spot_price',
          source: name,
          risk: risk,
          flowsToValue: flowsToValue,
          code: funcCode
        });
      }
    }
  }

  detectTWAPUsage(funcCode, node) {
    const twapPatterns = [
      { pattern: /observe\s*\(/, name: 'uniswap_observe', type: 'uniswap_v3' },
      { pattern: /consult\s*\(/, name: 'oracle_consult', type: 'generic' },
      { pattern: /TWAP|twap/, name: 'twap', type: 'generic' },
      { pattern: /cumulativePrice|priceCumulative/, name: 'cumulative', type: 'uniswap_v2' },
    ];

    for (const { pattern, name, type } of twapPatterns) {
      if (pattern.test(funcCode)) {
        // Check TWAP window
        const windowAnalysis = this.analyzeTWAPWindow(funcCode);

        this.twapUsages.push({
          function: this.currentFunction,
          node: node,
          source: name,
          type: type,
          windowSeconds: windowAnalysis.window,
          windowSafe: windowAnalysis.safe,
          code: funcCode
        });
      }
    }
  }

  detectChainlinkUsage(funcCode, node) {
    const chainlinkPatterns = [
      /latestRoundData\s*\(\s*\)/,
      /latestAnswer\s*\(\s*\)/,
      /AggregatorV3Interface/,
      /priceFeed/i,
    ];

    if (chainlinkPatterns.some(p => p.test(funcCode))) {
      const analysis = this.analyzeChainlinkUsage(funcCode);

      this.chainlinkFeeds.push({
        function: this.currentFunction,
        node: node,
        checks: analysis,
        code: funcCode
      });
    }
  }

  detectPriceDependentOperations(funcCode, node) {
    // Check if price is used in critical operations
    const criticalOps = [
      /collateral\s*[\/\*]/i,
      /liquidat/i,
      /borrow/i,
      /mint.*price|price.*mint/i,
      /redeem.*price|price.*redeem/i,
      /swap.*price|price.*swap/i,
    ];

    if (criticalOps.some(p => p.test(funcCode))) {
      // This function uses price in critical operations
      // Will be cross-referenced with oracle findings
    }
  }

  analyzeChainlinkUsage(funcCode) {
    return {
      checksRoundId: /roundId\s*[><=!]/i.test(funcCode) || /require.*roundId/i.test(funcCode),
      checksTimestamp: /updatedAt|timestamp/i.test(funcCode) && /[><=]/i.test(funcCode),
      checksStaleness: /block\.timestamp\s*-\s*updatedAt|updatedAt.*block\.timestamp/i.test(funcCode),
      checksAnswer: /answer\s*[><=!]\s*0|require.*answer/i.test(funcCode),
      checksSequencer: /sequencer|L2|isSequencerUp/i.test(funcCode),
      usesLatestAnswer: /latestAnswer/i.test(funcCode), // Deprecated
      hasHeartbeat: /heartbeat|HEARTBEAT|maxDelay/i.test(funcCode),
    };
  }

  analyzeTWAPWindow(funcCode) {
    // Try to extract TWAP window
    const windowPatterns = [
      /(\d+)\s*(?:seconds|minutes|hours)/i,
      /TWAP_WINDOW\s*=\s*(\d+)/i,
      /window\s*=\s*(\d+)/i,
      /period\s*=\s*(\d+)/i,
    ];

    let window = null;
    for (const pattern of windowPatterns) {
      const match = funcCode.match(pattern);
      if (match) {
        let value = parseInt(match[1]);
        // Convert to seconds if needed
        if (/minutes/i.test(match[0])) value *= 60;
        if (/hours/i.test(match[0])) value *= 3600;
        window = value;
        break;
      }
    }

    // Safe window is generally considered 30+ minutes for TWAP
    // Less than 10 minutes is dangerous
    return {
      window: window,
      safe: window === null || window >= 1800 // 30 minutes
    };
  }

  flowsToValueOperation(funcCode) {
    // Check if oracle result flows to value-affecting operation
    const valueOps = [
      /transferFrom|transfer|safeTransfer/i,
      /mint\s*\(/i,
      /burn\s*\(/i,
      /liquidate/i,
      /borrow/i,
      /repay/i,
      /\.call\s*\{.*value/i,
    ];

    return valueOps.some(p => p.test(funcCode));
  }

  analyzeOraclePatterns() {
    // HARDENED: Use data flow analysis to verify oracle values flow to value-moving operations
    // This significantly reduces false positives from pattern-only detection
    const oracleValueFlows = this.dataFlow?.oracleValueFlows || [];

    // Analyze spot price usages - require data flow proof
    for (const usage of this.oracleUsages) {
      // Check if we have data flow evidence that oracle flows to value operation
      const hasDataFlowProof = oracleValueFlows.some(flow =>
        flow.function.includes(usage.function) ||
        flow.contract === this.currentContract
      );

      // Require either data flow proof OR strong heuristic evidence
      const hasStrongEvidence = usage.flowsToValue && usage.risk === 'CRITICAL';

      if (usage.risk === 'CRITICAL' && (hasDataFlowProof || hasStrongEvidence)) {
        this.reportSpotPriceVulnerability(usage);
      } else if (usage.risk === 'HIGH' && hasDataFlowProof) {
        // Only report HIGH risk if we have data flow proof
        this.reportHighRiskOracleUsage(usage);
      }
      // Skip reporting if no data flow proof - reduces false positives
    }

    // Analyze TWAP usages - only report very short windows
    for (const usage of this.twapUsages) {
      // Tighten: only report if window is dangerously short (< 10 minutes)
      // 10-30 minute windows are marginal, not critical
      if (usage.windowSeconds !== null && usage.windowSeconds < 600) {
        this.reportShortTWAPWindow(usage);
      }
    }

    // Analyze Chainlink usages - only report missing critical checks
    for (const feed of this.chainlinkFeeds) {
      this.analyzeChainlinkVulnerabilities(feed);
    }
  }

  analyzeChainlinkVulnerabilities(feed) {
    const { checks, node, code } = feed;

    // Critical: Using deprecated latestAnswer
    if (checks.usesLatestAnswer) {
      this.addFinding({
        title: 'Deprecated Chainlink latestAnswer() Usage',
        description: `Function '${feed.function}' uses deprecated latestAnswer(). This function is deprecated and returns stale data without any indication of staleness. Use latestRoundData() instead.`,
        location: `Contract: ${this.currentContract}, Function: ${feed.function}`,
        line: node.loc?.start?.line || 0,
        column: node.loc?.start?.column || 0,
        code: code.substring(0, 200),
        severity: 'CRITICAL',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 85,
        attackVector: 'stale-price-exploitation',
        recommendation: `Replace latestAnswer() with latestRoundData() and add proper checks:
(uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound) = priceFeed.latestRoundData();
require(answer > 0, "Invalid price");
require(updatedAt > block.timestamp - MAX_DELAY, "Stale price");
require(answeredInRound >= roundId, "Stale round");`,
        references: [
          'https://docs.chain.link/data-feeds/api-reference'
        ]
      });
    }

    // High: No staleness check
    if (!checks.checksStaleness && !checks.checksTimestamp) {
      this.addFinding({
        title: 'Missing Chainlink Staleness Check',
        description: `Function '${feed.function}' uses Chainlink price feed without checking for stale data. During network congestion or oracle issues, stale prices can be exploited for arbitrage or liquidation attacks.`,
        location: `Contract: ${this.currentContract}, Function: ${feed.function}`,
        line: node.loc?.start?.line || 0,
        column: node.loc?.start?.column || 0,
        code: code.substring(0, 200),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 75,
        attackVector: 'stale-price-exploitation',
        recommendation: `Add staleness check:
require(block.timestamp - updatedAt < MAX_STALENESS, "Price is stale");

Where MAX_STALENESS is set based on the feed's heartbeat (e.g., 3600 for 1-hour heartbeat feeds).`,
        references: [
          'https://docs.chain.link/data-feeds#check-the-timestamp-of-the-latest-answer'
        ]
      });
    }

    // High: No answer validation
    if (!checks.checksAnswer) {
      this.addFinding({
        title: 'Missing Chainlink Answer Validation',
        description: `Function '${feed.function}' uses Chainlink price without validating the answer. A zero or negative price (which can occur during circuit breakers) could cause division by zero or incorrect calculations.`,
        location: `Contract: ${this.currentContract}, Function: ${feed.function}`,
        line: node.loc?.start?.line || 0,
        column: node.loc?.start?.column || 0,
        code: code.substring(0, 200),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 70,
        attackVector: 'invalid-price-exploitation',
        recommendation: `Add answer validation:
require(answer > 0, "Invalid price from oracle");`
      });
    }

    // Medium: No L2 sequencer check (for L2 deployments)
    if (!checks.checksSequencer && this.mightBeL2Contract()) {
      this.addFinding({
        title: 'Missing L2 Sequencer Uptime Check',
        description: `Contract may be deployed on L2 but doesn't check sequencer uptime. When the L2 sequencer is down, price feeds are not updated and can become stale without the staleness check detecting it.`,
        location: `Contract: ${this.currentContract}, Function: ${feed.function}`,
        line: node.loc?.start?.line || 0,
        column: node.loc?.start?.column || 0,
        code: code.substring(0, 200),
        severity: 'MEDIUM',
        confidence: 'LOW',
        exploitable: true,
        exploitabilityScore: 50,
        attackVector: 'l2-sequencer-exploitation',
        recommendation: `For L2 deployments, add sequencer uptime feed check:
(, int256 answer, uint256 startedAt,,) = sequencerUptimeFeed.latestRoundData();
bool isSequencerUp = answer == 0;
require(isSequencerUp, "Sequencer is down");
require(block.timestamp - startedAt > GRACE_PERIOD, "Grace period not over");`,
        references: [
          'https://docs.chain.link/data-feeds/l2-sequencer-feeds'
        ]
      });
    }
  }

  reportSpotPriceVulnerability(usage) {
    this.addFinding({
      title: 'Flash Loan Exploitable Spot Price Oracle',
      description: `Function '${usage.function}' uses ${usage.source} for price calculation which can be manipulated within a single transaction via flash loans.

Attack scenario:
1. Attacker takes flash loan of large amount
2. Manipulates spot price (e.g., large swap shifts reserves)
3. Executes target function at manipulated price
4. Reverts manipulation and repays flash loan
5. Profits from price discrepancy

This pattern has caused losses exceeding $300M in DeFi exploits.`,
      location: `Contract: ${this.currentContract}, Function: ${usage.function}`,
      line: usage.node.loc?.start?.line || 0,
      column: usage.node.loc?.start?.column || 0,
      code: usage.code.substring(0, 300),
      severity: 'CRITICAL',
      confidence: 'HIGH',
      exploitable: true,
      exploitabilityScore: 95,
      attackVector: 'flash-loan-oracle-manipulation',
      recommendation: `Replace spot price with manipulation-resistant oracle:
1. Use Chainlink price feeds for standard assets
2. Use Uniswap V3 TWAP with 30+ minute window
3. Use multiple oracle sources and take median
4. Add price deviation checks against reference oracle

Example TWAP usage:
uint32[] memory secondsAgos = new uint32[](2);
secondsAgos[0] = 1800; // 30 minutes ago
secondsAgos[1] = 0;    // now
(int56[] memory tickCumulatives,) = pool.observe(secondsAgos);
int24 avgTick = int24((tickCumulatives[1] - tickCumulatives[0]) / 1800);`,
      references: [
        'https://samczsun.com/so-you-want-to-use-a-price-oracle/',
        'https://docs.uniswap.org/concepts/protocol/oracle'
      ],
      foundryPoC: this.generateFlashLoanOraclePoC(usage)
    });
  }

  reportHighRiskOracleUsage(usage) {
    this.addFinding({
      title: 'High-Risk Oracle Price Source',
      description: `Function '${usage.function}' uses ${usage.source} which is manipulable under certain conditions. While not as easily exploited as spot prices, this can still be manipulated with sufficient capital or over multiple blocks.`,
      location: `Contract: ${this.currentContract}, Function: ${usage.function}`,
      line: usage.node.loc?.start?.line || 0,
      column: usage.node.loc?.start?.column || 0,
      code: usage.code.substring(0, 200),
      severity: 'HIGH',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 65,
      attackVector: 'oracle-manipulation',
      recommendation: `Add additional safeguards:
1. Compare against secondary oracle source
2. Add price deviation bounds (e.g., max 5% change)
3. Add time delay for price-sensitive operations
4. Consider using Chainlink for primary price source`
    });
  }

  reportShortTWAPWindow(usage) {
    this.addFinding({
      title: 'TWAP Window Too Short',
      description: `Function '${usage.function}' uses TWAP with window of ${usage.windowSeconds || 'unknown'} seconds. Short TWAP windows can be manipulated by sustaining price manipulation across multiple blocks.

A well-funded attacker can manipulate prices for several minutes, making short TWAPs vulnerable.`,
      location: `Contract: ${this.currentContract}, Function: ${usage.function}`,
      line: usage.node.loc?.start?.line || 0,
      column: usage.node.loc?.start?.column || 0,
      code: usage.code.substring(0, 200),
      severity: 'HIGH',
      confidence: 'MEDIUM',
      exploitable: true,
      exploitabilityScore: 60,
      attackVector: 'twap-manipulation',
      recommendation: `Increase TWAP window to at least 30 minutes (1800 seconds):
uint32 constant TWAP_WINDOW = 1800; // 30 minutes

Longer windows are more resistant to manipulation but less responsive to legitimate price changes. Consider the tradeoff based on your use case.`
    });
  }

  mightBeL2Contract() {
    // Heuristics to detect if this might be an L2 contract
    const l2Indicators = [
      /optimism|arbitrum|polygon|zksync|base|scroll|linea/i,
      /L2|layer2|layer-2/i,
    ];
    return l2Indicators.some(p => p.test(this.sourceCode));
  }

  generateFlashLoanOraclePoC(usage) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Flash Loan Oracle Manipulation
 * Exploits ${usage.source} usage in ${usage.function}
 */
contract FlashLoanOracleExploit is Test {
    // Interfaces would be defined here
    // ILendingPool flashLoanProvider;
    // IUniswapV2Pair targetPair;
    // IVulnerableProtocol target;

    function testExploit() public {
        // Step 1: Take flash loan
        uint256 loanAmount = 1_000_000e18; // Large amount
        // flashLoanProvider.flashLoan(address(this), token, loanAmount, "");
    }

    function executeOperation(
        address asset,
        uint256 amount,
        uint256 premium,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // Step 2: Manipulate the oracle
        // For Uniswap V2 reserves manipulation:
        // token.transfer(address(targetPair), amount);
        // targetPair.sync(); // Updates reserves

        // Step 3: Execute vulnerable function at manipulated price
        // target.${usage.function}(...);

        // Step 4: Reverse manipulation
        // (swap back or let it auto-correct)

        // Step 5: Repay flash loan
        // IERC20(asset).transfer(msg.sender, amount + premium);

        return true;
    }
}`;
  }
}

module.exports = OracleManipulationDetector;
