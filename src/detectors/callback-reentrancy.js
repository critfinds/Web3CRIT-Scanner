const BaseDetector = require('./base-detector');

/**
 * Callback Reentrancy Detector (ERC777, ERC1155, ERC721)
 *
 * Detects reentrancy via token callback hooks - a critical attack vector
 * for high-TVL DeFi protocols that was exploited in:
 * - Uniswap/Lendf.Me ($25M, 2020)
 * - Cream Finance ($130M, 2021)
 * - Fei Protocol ($80M, 2022)
 *
 * Attack vectors:
 * 1. ERC777 tokensToSend/tokensReceived hooks
 * 2. ERC1155 onERC1155Received callbacks
 * 3. ERC721 onERC721Received callbacks
 * 4. Flash loan callbacks (onFlashLoan)
 *
 * Immunefi Critical: Direct theft via callback-triggered reentrancy
 */
class CallbackReentrancyDetector extends BaseDetector {
  constructor() {
    super(
      'Callback Reentrancy',
      'Detects reentrancy via ERC777/ERC1155/ERC721/FlashLoan callbacks',
      'CRITICAL'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.tokenInteractions = [];
    this.stateChanges = [];
    this.externalCalls = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.tokenInteractions = [];
    this.stateChanges = [];
    this.externalCalls = [];

    this.traverse(ast);
    this.analyzeCallbackVulnerabilities();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;

    // Check if contract handles tokens that have callbacks
    const baseContracts = (node.baseContracts || [])
      .map(b => b.baseName?.namePath || '')
      .join(' ');

    // Detect if this is a callback-receiving contract
    this.isCallbackReceiver = /IERC1155Receiver|ERC1155Holder|IERC721Receiver|ERC721Holder|IERC777Recipient|IERC777Sender/i.test(baseContracts);
  }

  visitFunctionDefinition(node) {
    this.currentFunction = node.name || 'constructor';
    const funcCode = this.getCodeSnippet(node.loc);

    // Skip pure/view functions (can't have reentrancy with state changes)
    if (node.stateMutability === 'pure' || node.stateMutability === 'view') {
      return;
    }

    // Skip internal/private functions (analyze public entry points)
    if (node.visibility === 'private' || node.visibility === 'internal') {
      return;
    }

    // Detect token transfer patterns that trigger callbacks
    this.detectCallbackTriggers(funcCode, node);

    // Detect if function is itself a callback handler
    this.detectCallbackHandlers(funcCode, node);
  }

  /**
   * Detect functions that make token transfers which could trigger callbacks
   */
  detectCallbackTriggers(funcCode, node) {
    const funcName = this.currentFunction;

    // ERC777 transfer triggers tokensToSend/tokensReceived hooks
    const erc777Patterns = [
      { pattern: /\.send\s*\([^)]*\)/i, token: 'ERC777', callback: 'tokensReceived' },
      { pattern: /\.transfer\s*\([^)]*\)/i, token: 'ERC777/ERC20', callback: 'tokensReceived (if ERC777)' },
      { pattern: /\.transferFrom\s*\([^)]*\)/i, token: 'ERC777/ERC20', callback: 'tokensReceived (if ERC777)' },
      { pattern: /\.operatorSend\s*\([^)]*\)/i, token: 'ERC777', callback: 'tokensReceived' },
    ];

    // ERC1155 safe transfers trigger onERC1155Received
    const erc1155Patterns = [
      { pattern: /\.safeTransferFrom\s*\([^)]*\)/i, token: 'ERC1155/ERC721', callback: 'onERC1155Received/onERC721Received' },
      { pattern: /\.safeBatchTransferFrom\s*\([^)]*\)/i, token: 'ERC1155', callback: 'onERC1155BatchReceived' },
      { pattern: /\._safeTransfer\s*\([^)]*\)/i, token: 'ERC1155/ERC721', callback: 'onERC1155Received/onERC721Received' },
      { pattern: /\._safeMint\s*\([^)]*\)/i, token: 'ERC721/ERC1155', callback: 'onERC721Received/onERC1155Received' },
    ];

    // Flash loan callbacks
    const flashLoanPatterns = [
      { pattern: /\.flashLoan\s*\([^)]*\)/i, token: 'FlashLoan', callback: 'onFlashLoan/executeOperation' },
      { pattern: /\.flash\s*\([^)]*\)/i, token: 'Uniswap V3', callback: 'uniswapV3FlashCallback' },
      { pattern: /\.swap\s*\([^)]*\)/i, token: 'Uniswap V2/V3', callback: 'uniswapV2Call/uniswapV3SwapCallback' },
    ];

    const allPatterns = [...erc777Patterns, ...erc1155Patterns, ...flashLoanPatterns];

    for (const { pattern, token, callback } of allPatterns) {
      if (pattern.test(funcCode)) {
        // Check if there's state modification after the call
        const hasStateChangeAfter = this.detectStateChangeAfterCall(funcCode, pattern);
        const hasReentrancyGuard = /nonReentrant|_status|_locked|ReentrancyGuard/i.test(funcCode);

        if (hasStateChangeAfter && !hasReentrancyGuard) {
          this.tokenInteractions.push({
            function: funcName,
            tokenType: token,
            callback: callback,
            line: node.loc?.start?.line || 0,
            code: funcCode,
            node: node
          });
        }
      }
    }
  }

  /**
   * Detect if this function is a callback handler that could be exploited
   */
  detectCallbackHandlers(funcCode, node) {
    const funcName = this.currentFunction;

    // Known callback function names
    const callbackNames = [
      'onERC1155Received',
      'onERC1155BatchReceived',
      'onERC721Received',
      'tokensReceived',
      'tokensToSend',
      'onFlashLoan',
      'executeOperation',      // Aave flash loan
      'uniswapV2Call',
      'uniswapV3FlashCallback',
      'uniswapV3SwapCallback',
      'pancakeCall',
      'BiswapCall',
      'onTokenTransfer',       // Chainlink
      'receiveFlashLoan',      // Balancer
    ];

    if (callbackNames.some(cb => funcName.toLowerCase() === cb.toLowerCase())) {
      // This is a callback handler - check for dangerous operations
      const hasDangerousOps = this.detectDangerousCallbackOperations(funcCode);

      if (hasDangerousOps.length > 0) {
        this.addFinding({
          title: 'Dangerous Callback Handler',
          description: `Callback handler '${funcName}' performs dangerous operations: ${hasDangerousOps.join(', ')}.\n\n` +
            `Attack scenario:\n` +
            `1. Attacker deploys malicious contract that inherits callback interface\n` +
            `2. Attacker triggers token operation that calls back to their contract\n` +
            `3. Callback re-enters vulnerable function before state is finalized\n` +
            `4. Attacker extracts value due to stale state`,
          location: `Contract: ${this.currentContract}, Function: ${funcName}`,
          line: node.loc?.start?.line || 0,
          column: node.loc?.start?.column || 0,
          code: funcCode.substring(0, 400),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 90,
          attackVector: 'callback-reentrancy',
          recommendation: `1. Add nonReentrant modifier to callback handlers\n` +
            `2. Follow checks-effects-interactions pattern\n` +
            `3. Update state BEFORE making external calls\n` +
            `4. Consider using pull-payment pattern instead of push`,
          references: [
            'https://eips.ethereum.org/EIPS/eip-777',
            'https://eips.ethereum.org/EIPS/eip-1155',
            'https://blog.openzeppelin.com/reentrancy-after-istanbul'
          ],
          foundryPoC: this.generateCallbackPoC(funcName)
        });
      }
    }
  }

  /**
   * Detect dangerous operations within callback handlers
   */
  detectDangerousCallbackOperations(funcCode) {
    const dangerous = [];

    // External calls
    if (/\.call\s*\{|\.call\s*\(|\.delegatecall\s*\(|\.transfer\s*\(|\.send\s*\(/i.test(funcCode)) {
      dangerous.push('external calls');
    }

    // State modifications (balance changes, mapping updates)
    if (/balances\s*\[|_balances\s*\[|shares\s*\[|deposits\s*\[/i.test(funcCode)) {
      dangerous.push('balance state changes');
    }

    // Token minting/burning
    if (/_mint\s*\(|_burn\s*\(/i.test(funcCode)) {
      dangerous.push('token minting/burning');
    }

    // Value extraction
    if (/withdraw|redeem|claim|harvest/i.test(funcCode)) {
      dangerous.push('value extraction');
    }

    return dangerous;
  }

  /**
   * Detect if state changes occur after a callback-triggering call
   */
  detectStateChangeAfterCall(funcCode, callPattern) {
    const match = funcCode.match(callPattern);
    if (!match) return false;

    const afterCall = funcCode.substring(match.index + match[0].length);

    // Look for state-changing patterns after the call
    const stateChangePatterns = [
      /\w+\s*\[.*\]\s*[+\-*/]?=/,          // mapping[key] = value
      /\w+\s*=\s*[^=]/,                     // variable = value (not comparison)
      /\+\+\w+|\w+\+\+|--\w+|\w+--/,       // increment/decrement
      /_mint\s*\(|_burn\s*\(/,             // token operations
      /\.push\s*\(|\.pop\s*\(/,            // array operations
      /delete\s+\w+/,                       // deletion
    ];

    return stateChangePatterns.some(p => p.test(afterCall));
  }

  /**
   * Analyze collected interactions for callback vulnerabilities
   */
  analyzeCallbackVulnerabilities() {
    for (const interaction of this.tokenInteractions) {
      // Check CFG for reentrancy guard
      let hasGuard = false;
      if (this.cfg?.functions) {
        const funcKey = `${this.currentContract}.${interaction.function}`;
        const funcInfo = this.cfg.functions.get(funcKey);
        if (funcInfo?.modifiers?.some(m =>
          /nonreentrant|reentrancyguard|locked/i.test(m.name || ''))) {
          hasGuard = true;
        }
      }

      if (!hasGuard) {
        this.addFinding({
          title: `${interaction.tokenType} Callback Reentrancy`,
          description: `Function '${interaction.function}' makes ${interaction.tokenType} transfer that triggers '${interaction.callback}' callback, ` +
            `then modifies state. An attacker can exploit this by:\n\n` +
            `1. Deploying contract that implements ${interaction.callback}\n` +
            `2. In callback, re-enter ${interaction.function}\n` +
            `3. Exploit stale state before original call completes\n\n` +
            `This is the attack pattern used in:\n` +
            `- Uniswap/Lendf.Me ($25M exploit)\n` +
            `- Cream Finance ($130M exploit)\n` +
            `- Multiple DeFi protocol incidents`,
          location: `Contract: ${this.currentContract}, Function: ${interaction.function}`,
          line: interaction.line,
          code: interaction.code.substring(0, 400),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 95,
          attackVector: 'callback-reentrancy',
          recommendation: `1. Add ReentrancyGuard (nonReentrant modifier)\n` +
            `2. Update ALL state BEFORE token transfers\n` +
            `3. Consider using OpenZeppelin's ReentrancyGuard\n` +
            `4. For flash loans, validate loan amount matches expected`,
          references: [
            'https://swcregistry.io/docs/SWC-107',
            'https://blog.openzeppelin.com/reentrancy-after-istanbul'
          ],
          foundryPoC: this.generateCallbackPoC(interaction.function, interaction.tokenType)
        });
      }
    }
  }

  generateCallbackPoC(funcName, tokenType = 'ERC1155') {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * PoC: ${tokenType} Callback Reentrancy Exploit
 * Target: ${funcName}
 *
 * Attack: Re-enter via token callback before state update
 */
interface IVictim {
    function ${funcName}(address, uint256, bytes calldata) external;
}

contract CallbackAttacker is Test {
    IVictim victim;
    uint256 public attackCount;

    function setUp() public {
        // victim = IVictim(VICTIM_ADDRESS);
    }

    // ERC1155 callback - triggers on safeTransferFrom
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4) {
        attackCount++;
        if (attackCount < 5) {
            // Re-enter victim contract
            // victim.${funcName}(...);
        }
        return this.onERC1155Received.selector;
    }

    // ERC777 callback
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external {
        attackCount++;
        if (attackCount < 5) {
            // Re-enter victim
        }
    }

    function testExploit() public {
        // 1. Trigger ${funcName} with attacker as recipient
        // 2. Callback re-enters before state finalized
        // 3. Extract value multiple times
    }
}`;
  }
}

module.exports = CallbackReentrancyDetector;
