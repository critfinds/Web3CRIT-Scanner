const BaseDetector = require('./base-detector');

/**
 * Signature Replay Attack Detector
 * Detects vulnerabilities in contracts using off-chain signatures for meta-transactions
 * 
 * Detects:
 * - Missing nonce in signature verification
 * - Reusable signatures without expiration
 * - Missing chain ID in signature (cross-chain replay)
 * - Weak signature verification (no EIP-712)
 * - Missing signature validation checks
 * - Replay protection bypasses
 */
class SignatureReplayDetector extends BaseDetector {
  constructor() {
    super(
      'Signature Replay Vulnerability',
      'Detects missing replay protection in contracts using off-chain signatures (meta-transactions, permit, etc.)',
      'HIGH'
    );
    this.currentContract = null;
    this.signatureFunctions = [];
    this.nonceTracking = new Map(); // function -> has nonce
    this.eip712Usage = false;
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;

    // Check for EIP-712 usage
    this.eip712Usage = this.detectEIP712Usage(sourceCode);

    this.traverse(ast);

    // Post-traversal analysis
    this.analyzeSignatureFunctions();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    this.signatureFunctions = [];
    this.nonceTracking = new Map();
  }

  visitFunctionDefinition(node) {
    const funcName = node.name || '';
    const funcCode = this.getCodeSnippet(node.loc);
    const funcCodeLower = funcCode.toLowerCase();

    // Detect signature verification functions
    if (this.isSignatureFunction(funcCode, funcName)) {
      const sigInfo = {
        name: funcName,
        node: node,
        code: funcCode,
        hasNonce: this.hasNonceProtection(funcCode),
        hasExpiration: this.hasExpirationProtection(funcCode),
        hasChainId: this.hasChainIdProtection(funcCode),
        usesEIP712: this.usesEIP712InFunction(funcCode),
        usesEcrecover: funcCodeLower.includes('ecrecover'),
        usesSignature: funcCodeLower.includes('signature') || funcCodeLower.includes('sig')
      };

      this.signatureFunctions.push(sigInfo);
      this.nonceTracking.set(funcName, sigInfo.hasNonce);

      // Analyze this function for vulnerabilities
      this.analyzeSignatureFunction(sigInfo);
    }
  }

  /**
   * Check if function uses signature verification
   */
  isSignatureFunction(code, funcName) {
    const codeLower = code.toLowerCase();
    const funcNameLower = funcName.toLowerCase();

    // Common signature function patterns
    const signaturePatterns = [
      /ecrecover\s*\(/i,
      /verify\s*\(.*signature/i,
      /permit\s*\(/i,
      /meta.*transaction/i,
      /off.*chain.*sign/i,
      /ECDSA\.recover/i,
      /SignatureChecker/i,
      /_verify/i,
      /verifySignature/i,
      /checkSignature/i
    ];

    // Function name patterns
    const namePatterns = [
      'permit',
      'meta',
      'verify',
      'signature',
      'nonce'
    ];

    // IMPORTANT: do NOT classify generic "execute*" functions as signature-based.
    // This prevents false positives on functions like executeFlashLoan(), execute(), etc.
    const hasSignatureOps = signaturePatterns.some(pattern => pattern.test(code));
    const nameIndicatesSig = namePatterns.some(pattern => funcNameLower.includes(pattern));

    return hasSignatureOps || nameIndicatesSig;
  }

  /**
   * Analyze a signature function for vulnerabilities
   */
  analyzeSignatureFunction(sigInfo) {
    const { name, code, node, hasNonce, hasExpiration, hasChainId, usesEIP712, usesEcrecover } = sigInfo;

    // Critical: Missing nonce protection
    if (!hasNonce) {
      this.addFinding({
        title: 'Missing Nonce Protection in Signature Verification',
        description: `Function '${name}' uses signature verification but lacks nonce tracking. Signatures can be replayed multiple times, allowing attackers to execute the same transaction repeatedly.`,
        location: `Contract: ${this.currentContract}, Function: ${name}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'CRITICAL',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 90,
        attackVector: 'signature-replay',
        recommendation: 'Implement nonce tracking: mapping(address => uint256) public nonces; Increment nonce after each signature use. Include nonce in signature hash.',
        references: [
          'https://swcregistry.io/docs/SWC-121',
          'https://eips.ethereum.org/EIPS/eip-2612',
          'https://docs.openzeppelin.com/contracts/4.x/api/utils#SignatureChecker'
        ],
        foundryPoC: this.generateNonceReplayPoC(this.currentContract, name)
      });
    }

    // High: Missing expiration
    if (!hasExpiration) {
      this.addFinding({
        title: 'Missing Expiration in Signature',
        description: `Function '${name}' accepts signatures without expiration timestamp. Old signatures remain valid indefinitely, increasing attack surface.`,
        location: `Contract: ${this.currentContract}, Function: ${name}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: true,
        exploitabilityScore: 70,
        attackVector: 'signature-replay',
        recommendation: 'Include deadline/expiration timestamp in signature hash. Verify deadline > block.timestamp before processing.',
        references: [
          'https://eips.ethereum.org/EIPS/eip-2612',
          'https://docs.openzeppelin.com/contracts/4.x/api/utils#SignatureChecker'
        ]
      });
    }

    // High: Missing chain ID (cross-chain replay)
    if (!hasChainId && !this.eip712Usage) {
      this.addFinding({
        title: 'Missing Chain ID in Signature (Cross-Chain Replay Risk)',
        description: `Function '${name}' does not include chain ID in signature verification. Signatures valid on one chain can be replayed on another chain (e.g., mainnet signature used on testnet).`,
        location: `Contract: ${this.currentContract}, Function: ${name}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 75,
        attackVector: 'cross-chain-replay',
        recommendation: 'Include chain ID in signature hash. Use EIP-712 for structured data signing which includes domain separator with chain ID.',
        references: [
          'https://eips.ethereum.org/EIPS/eip-712',
          'https://eips.ethereum.org/EIPS/eip-2612'
        ]
      });
    }

    // Medium: Using ecrecover directly (not EIP-712)
    if (usesEcrecover && !usesEIP712) {
      this.addFinding({
        title: 'Direct ecrecover Usage Without EIP-712',
        description: `Function '${name}' uses ecrecover directly instead of EIP-712 structured data signing. This is error-prone and lacks type safety. Malformed signatures may be accepted.`,
        location: `Contract: ${this.currentContract}, Function: ${name}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        exploitable: false,
        exploitabilityScore: 40,
        attackVector: 'signature-verification',
        recommendation: 'Use EIP-712 for structured data signing. Consider OpenZeppelin\'s SignatureChecker or ECDSA library for safer signature verification.',
        references: [
          'https://eips.ethereum.org/EIPS/eip-712',
          'https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA'
        ]
      });
    }

    // Check for weak signature validation
    if (this.hasWeakSignatureValidation(code)) {
      this.addFinding({
        title: 'Weak Signature Validation',
        description: `Function '${name}' has insufficient signature validation. Missing checks for zero address, signature malleability, or invalid signature format.`,
        location: `Contract: ${this.currentContract}, Function: ${name}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 60,
        attackVector: 'signature-validation',
        recommendation: 'Validate recovered address is not zero. Check signature length (65 bytes). Use OpenZeppelin\'s ECDSA.recover which handles malleability.',
        references: [
          'https://docs.openzeppelin.com/contracts/4.x/api/utils#ECDSA',
          'https://swcregistry.io/docs/SWC-117'
        ]
      });
    }
  }

  /**
   * Check if function has nonce protection
   */
  hasNonceProtection(code) {
    const codeLower = code.toLowerCase();
    
    // Check for nonce usage
    const noncePatterns = [
      /nonces\s*\[/i,
      /nonce\s*\+\+/i,
      /nonce\s*\+=\s*1/i,
      /_useNonce\s*\(/i,
      /incrementNonce/i,
      /nonce.*require/i
    ];

    return noncePatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check if function has expiration protection
   */
  hasExpirationProtection(code) {
    const codeLower = code.toLowerCase();
    
    const expirationPatterns = [
      /deadline\s*>/i,
      /expires?\s*>/i,
      /expiration\s*>/i,
      /require\s*\(\s*.*deadline/i,
      /require\s*\(\s*.*expir/i,
      /block\.timestamp\s*</i
    ];

    return expirationPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check if function includes chain ID
   */
  hasChainIdProtection(code) {
    const codeLower = code.toLowerCase();
    
    const chainIdPatterns = [
      /chainid/i,
      /chain\.id/i,
      /getChainId/i,
      /DOMAIN_SEPARATOR/i,
      /eip712domain/i,
      /typeHash.*chainId/i
    ];

    return chainIdPatterns.some(pattern => pattern.test(code));
  }

  /**
   * Check if function uses EIP-712
   */
  usesEIP712InFunction(code) {
    const codeLower = code.toLowerCase();
    
    return /eip712|DOMAIN_SEPARATOR|_TYPE_HASH|_HASHED_NAME|_HASHED_VERSION/i.test(codeLower);
  }

  /**
   * Check if contract uses EIP-712 overall
   */
  detectEIP712Usage(sourceCode) {
    const codeLower = sourceCode.toLowerCase();
    return /eip712|DOMAIN_SEPARATOR|_TYPE_HASH/i.test(codeLower);
  }

  /**
   * Check for weak signature validation
   */
  hasWeakSignatureValidation(code) {
    const codeLower = code.toLowerCase();
    
    // Should check for zero address
    const hasZeroCheck = /require\s*\(\s*.*!=\s*address\(0\)|require\s*\(\s*.*!=\s*0x0/i.test(codeLower);
    
    // Should check signature length
    const hasLengthCheck = /length\s*==\s*65|length\s*==\s*64/i.test(codeLower);
    
    // Using ecrecover without proper validation
    const usesEcrecover = /ecrecover\s*\(/i.test(codeLower);
    
    return usesEcrecover && (!hasZeroCheck || !hasLengthCheck);
  }

  /**
   * Post-traversal analysis
   */
  analyzeSignatureFunctions() {
    // Check if contract has nonce mapping but functions don't use it
    const hasNonceMapping = /mapping\s*\(.*\)\s*public\s*nonces/i.test(this.sourceCode);
    
    if (hasNonceMapping) {
      // Check if any signature function doesn't use it
      this.signatureFunctions.forEach(sigInfo => {
        if (!sigInfo.hasNonce) {
          this.addFinding({
            title: 'Nonce Mapping Exists But Not Used',
            description: `Contract has nonce mapping but function '${sigInfo.name}' does not use it. This suggests incomplete implementation of replay protection.`,
            location: `Contract: ${this.currentContract}, Function: ${sigInfo.name}`,
            line: sigInfo.node.loc ? sigInfo.node.loc.start.line : 0,
            column: sigInfo.node.loc ? sigInfo.node.loc.start.column : 0,
            code: this.getCodeSnippet(sigInfo.node.loc),
            severity: 'HIGH',
            confidence: 'HIGH',
            exploitable: true,
            exploitabilityScore: 80,
            attackVector: 'signature-replay',
            recommendation: 'Ensure all signature verification functions increment and check nonces. Use _useNonce(address) pattern from OpenZeppelin.',
            references: [
              'https://docs.openzeppelin.com/contracts/4.x/api/utils#SignatureChecker'
            ]
          });
        }
      });
    }
  }

  /**
   * Generate Foundry PoC for nonce replay attack
   */
  generateNonceReplayPoC(contractName, funcName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Signature Replay Attack
 * Target: ${contractName}.${funcName}()
 * Attack Vector: Reuse same signature multiple times
 */
contract SignatureReplayExploit is Test {
    address constant TARGET = address(0); // ${contractName} address
    address attacker = address(this);
    
    uint256 privateKey = 0x1234...; // Attacker's private key
    address signer = vm.addr(privateKey);

    function testExploit() public {
        // 1. Create signature for legitimate transaction
        // bytes memory sig = signTransaction(...);
        
        // 2. Execute transaction with signature (first time - legitimate)
        // ${contractName}(TARGET).${funcName}(..., sig);
        
        // 3. Replay the same signature (should fail but doesn't)
        // ${contractName}(TARGET).${funcName}(..., sig); // Replay!
        
        // 4. If nonce not checked, this succeeds and attacker benefits twice
        
        // Assert replay succeeded
        // assertGt(attackerBalance, expectedBalance);
    }
    
    // Helper: Sign transaction
    // function signTransaction(...) internal returns (bytes memory) {
    //     bytes32 hash = keccak256(abi.encodePacked(...));
    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
    //     return abi.encodePacked(r, s, v);
    // }
}`;
  }
}

module.exports = SignatureReplayDetector;

