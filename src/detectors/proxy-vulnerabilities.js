const BaseDetector = require('./base-detector');

/**
 * Proxy Contract Vulnerabilities Detector
 * Detects critical issues in upgradeable contracts (UUPS, Transparent Proxies, EIP-1967)
 * 
 * Detects:
 * - Missing initialization protection (uninitialized proxy)
 * - Storage collision in proxy patterns
 * - Unauthorized upgrade functions
 * - Missing implementation contract validation
 * - UUPS-specific vulnerabilities (missing _authorizeUpgrade)
 * - Transparent proxy selector clash
 * - Storage layout incompatibility warnings
 */
class ProxyVulnerabilitiesDetector extends BaseDetector {
  constructor() {
    super(
      'Proxy Contract Vulnerabilities',
      'Detects critical vulnerabilities in upgradeable proxy contracts (UUPS, Transparent, EIP-1967)',
      'CRITICAL'
    );
    this.currentContract = null;
    this.proxyPatterns = {
      uups: false,
      transparent: false,
      beacon: false,
      diamond: false
    };
    this.hasInitializer = false;
    this.hasInitialized = false;
    this.upgradeFunctions = [];
    this.storageSlots = new Set();
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;

    this.traverse(ast);

    // Post-traversal analysis
    this.analyzeProxyPatterns();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    this.proxyPatterns = {
      uups: false,
      transparent: false,
      beacon: false,
      diamond: false
    };
    this.hasInitializer = false;
    this.hasInitialized = false;
    this.upgradeFunctions = [];
    this.storageSlots = new Set();

    // Check if contract is a proxy implementation
    const contractNameLower = (node.name || '').toLowerCase();
    const isProxyContract = contractNameLower.includes('proxy') || 
                           contractNameLower.includes('upgradeable') ||
                           contractNameLower.includes('implementation');
    
    if (node.baseContracts && node.baseContracts.length > 0) {
      node.baseContracts.forEach(base => {
        const baseName = base.baseName.namePath || base.baseName.name;
        if (this.isProxyBaseContract(baseName)) {
          this.detectProxyPattern(baseName);
        }
      });
    }
    
    // Also check contract name for proxy patterns
    if (isProxyContract) {
      // Mark as potential proxy to enable upgrade function detection
      this.proxyPatterns.transparent = true; // Default to transparent if name suggests proxy
    }
  }

  visitFunctionDefinition(node) {
    const funcName = node.name || '';
    const funcCode = this.getCodeSnippet(node.loc);
    const funcCodeLower = funcCode.toLowerCase();

    // Detect initializer functions
    if (funcName.toLowerCase().includes('initializ') || 
        funcCodeLower.includes('initializer') ||
        funcCodeLower.includes('__init')) {
      this.hasInitializer = true;
      
      // Check if initializer is protected
      if (!this.hasInitializerProtection(funcCode, node)) {
        this.addFinding({
          title: 'Unprotected Initializer Function',
          description: `Initializer function '${funcName}' lacks proper protection against multiple initialization. Proxy contracts must prevent re-initialization to avoid storage corruption.`,
          location: `Contract: ${this.currentContract}, Function: ${funcName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 95,
          attackVector: 'proxy-initialization',
          recommendation: 'Use OpenZeppelin\'s Initializable pattern with initializer modifier, or check an initialized storage variable. Never allow re-initialization.',
          references: [
            'https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable',
            'https://swcregistry.io/docs/SWC-118',
            'https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/proxy/utils/Initializable.sol'
          ],
          foundryPoC: this.generateInitializerPoC(this.currentContract, funcName)
        });
      }
    }

    // Detect upgrade functions
    if (this.isUpgradeFunction(funcName, funcCode)) {
      this.upgradeFunctions.push({
        name: funcName,
        node: node,
        code: funcCode
      });

      // Check for unauthorized upgrades
      if (!this.hasUpgradeProtection(funcCode, node)) {
        this.addFinding({
          title: 'Unauthorized Upgrade Function',
          description: `Upgrade function '${funcName}' lacks access control. Anyone can upgrade the proxy implementation, potentially stealing funds or breaking functionality.`,
          location: `Contract: ${this.currentContract}, Function: ${funcName}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 100,
          attackVector: 'unauthorized-upgrade',
          recommendation: 'Add access control (onlyOwner, onlyRole, etc.) to all upgrade functions. Consider using OpenZeppelin\'s UUPSUpgradeable or TransparentUpgradeableProxy.',
          references: [
            'https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable',
            'https://swcregistry.io/docs/SWC-119'
          ],
          foundryPoC: this.generateUpgradePoC(this.currentContract, funcName)
        });
      }
    }

    // UUPS-specific: Check for _authorizeUpgrade
    if (this.proxyPatterns.uups) {
      if (funcName === '_authorizeUpgrade' || funcCodeLower.includes('_authorizeupgrade')) {
        // Good - UUPS pattern requires this
        return;
      }
    }
  }

  visitVariableDeclaration(node) {
    // Track storage slots for collision detection
    if (node.stateVariable && node.name) {
      // Check for EIP-1967 storage slots
      const code = this.getLineContent(node.loc ? node.loc.start.line : 0);
      if (code.includes('bytes32') && code.includes('0x')) {
        // Potential storage slot declaration
        const slotMatch = code.match(/0x[0-9a-fA-F]{64}/);
        if (slotMatch) {
          this.storageSlots.add(slotMatch[0]);
        }
      }
    }
  }

  visitMemberAccess(node) {
    // Detect delegatecall usage (common in proxies)
    if (node.memberName === 'delegatecall') {
      // Get the full function context, not just the member access
      const lineNum = node.loc ? node.loc.start.line : 0;
      // Look for the containing function - get more context
      let funcCode = '';
      
      // Try to get more context - check surrounding lines for fallback/receive
      let foundFallback = false;
      for (let i = Math.max(1, lineNum - 30); i <= Math.min(this.sourceLines.length, lineNum + 10); i++) {
        const line = this.sourceLines[i - 1] || '';
        if (line.includes('fallback') || line.includes('receive')) {
          foundFallback = true;
          // This is in a fallback/receive function - get the full function
          const funcStart = Math.max(1, i - 2);
          const funcEnd = Math.min(this.sourceLines.length, i + 40);
          funcCode = this.sourceLines.slice(funcStart - 1, funcEnd).join('\n');
          break;
        }
      }
      
      // If we didn't find fallback, get context around the delegatecall
      if (!funcCode) {
        const start = Math.max(0, lineNum - 15);
        const end = Math.min(this.sourceLines.length, lineNum + 5);
        funcCode = this.sourceLines.slice(start, end).join('\n');
      }
      
      if (!this.hasDelegatecallProtection(funcCode)) {
        this.addFinding({
          title: 'Unprotected Delegatecall in Proxy',
          description: 'Delegatecall detected without proper validation of target address. Malicious implementation contracts can corrupt proxy storage.',
          location: `Contract: ${this.currentContract}`,
          line: node.loc ? node.loc.start.line : 0,
          column: node.loc ? node.loc.start.column : 0,
          code: this.getCodeSnippet(node.loc),
          severity: 'CRITICAL',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 90,
          attackVector: 'delegatecall-exploit',
          recommendation: 'Validate implementation address before delegatecall. Use OpenZeppelin\'s proxy patterns or ensure implementation is from trusted source.',
          references: [
            'https://swcregistry.io/docs/SWC-112',
            'https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable'
          ]
        });
      }
    }

    // Detect storage slot access (EIP-1967)
    if (node.memberName === 'sload' || node.memberName === 'sstore') {
      // Check for EIP-1967 storage slots
      const code = this.getCodeSnippet(node.loc);
      const eip1967Slots = [
        '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc', // IMPLEMENTATION_SLOT
        '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103', // ADMIN_SLOT
        '0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7'  // BEACON_SLOT
      ];
      
      eip1967Slots.forEach(slot => {
        if (code.includes(slot)) {
          // This is using EIP-1967 - check for proper usage
          if (!this.hasEIP1967Protection(code)) {
            this.addFinding({
              title: 'Unprotected EIP-1967 Storage Access',
              description: `Direct access to EIP-1967 storage slot detected without proper access control. This could allow unauthorized upgrades or storage corruption.`,
              location: `Contract: ${this.currentContract}`,
              line: node.loc ? node.loc.start.line : 0,
              column: node.loc ? node.loc.start.column : 0,
              code: this.getCodeSnippet(node.loc),
              severity: 'HIGH',
              confidence: 'MEDIUM',
              exploitable: true,
              exploitabilityScore: 75,
              attackVector: 'storage-slot-manipulation',
              recommendation: 'Use OpenZeppelin\'s ERC1967Upgrade or similar library for safe storage slot access. Never directly manipulate EIP-1967 slots without access control.',
              references: [
                'https://eips.ethereum.org/EIPS/eip-1967',
                'https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable'
              ]
            });
          }
        }
      });
    }
  }

  /**
   * Analyze proxy patterns after traversal
   */
  analyzeProxyPatterns() {
    // UUPS pattern requires _authorizeUpgrade
    if (this.proxyPatterns.uups) {
      const hasAuthorizeUpgrade = this.sourceCode.toLowerCase().includes('_authorizeupgrade');
      if (!hasAuthorizeUpgrade) {
        this.addFinding({
          title: 'Missing _authorizeUpgrade in UUPS Pattern',
          description: 'Contract appears to use UUPS pattern but lacks _authorizeUpgrade function. This is required for UUPS proxies to prevent unauthorized upgrades.',
          location: `Contract: ${this.currentContract}`,
          line: 1,
          column: 0,
          code: this.sourceCode.substring(0, 200),
          severity: 'CRITICAL',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 95,
          attackVector: 'uups-missing-authorization',
          recommendation: 'Implement _authorizeUpgrade function with proper access control. Use OpenZeppelin\'s UUPSUpgradeable contract.',
          references: [
            'https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable',
            'https://eips.ethereum.org/EIPS/eip-1822'
          ]
        });
      }
    }

    // Check for storage collision risks
    if (this.storageSlots.size > 0) {
      // Warn about potential storage layout issues
      const hasStorageLayout = this.sourceCode.includes('StorageLayout') || 
                               this.sourceCode.includes('storage gap');
      if (!hasStorageLayout && this.proxyPatterns.uups) {
        this.addFinding({
          title: 'Potential Storage Layout Collision',
          description: 'Proxy implementation may have storage layout conflicts. Upgrading to a new implementation with different storage layout can corrupt data.',
          location: `Contract: ${this.currentContract}`,
          line: 1,
          column: 0,
          code: this.sourceCode.substring(0, 200),
          severity: 'HIGH',
          confidence: 'MEDIUM',
          exploitable: false,
          exploitabilityScore: 50,
          attackVector: 'storage-collision',
          recommendation: 'Use storage gaps (e.g., uint256[50] __gap) in base contracts. Document storage layout. Use OpenZeppelin\'s storage layout validation tools.',
          references: [
            'https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#storage-gaps',
            'https://swcregistry.io/docs/SWC-120'
          ]
        });
      }
    }
  }

  /**
   * Check if contract inherits from proxy base contracts
   */
  isProxyBaseContract(baseName) {
    const proxyBases = [
      'UUPSUpgradeable',
      'TransparentUpgradeableProxy',
      'ERC1967Proxy',
      'BeaconProxy',
      'Diamond',
      'DiamondProxy',
      'UpgradeableProxy',
      'Proxy'
    ];
    
    return proxyBases.some(base => 
      baseName.toLowerCase().includes(base.toLowerCase())
    );
  }

  /**
   * Detect which proxy pattern is being used
   */
  detectProxyPattern(baseName) {
    const nameLower = baseName.toLowerCase();
    if (nameLower.includes('uups')) {
      this.proxyPatterns.uups = true;
    } else if (nameLower.includes('transparent')) {
      this.proxyPatterns.transparent = true;
    } else if (nameLower.includes('beacon')) {
      this.proxyPatterns.beacon = true;
    } else if (nameLower.includes('diamond')) {
      this.proxyPatterns.diamond = true;
    }
  }

  /**
   * Check if function is an upgrade function
   */
  isUpgradeFunction(funcName, code) {
    const nameLower = (funcName || '').toLowerCase();
    const codeLower = code.toLowerCase();

    // Skip fallback and receive functions - these are for delegation, not upgrades
    if (nameLower === 'fallback' || nameLower === '' || nameLower === 'receive') {
      return false;
    }

    // Check for explicit upgrade function names
    const upgradeKeywords = ['upgrade', 'upgradeto', 'upgradetoandcall', 'changeimplementation',
                            'setimplementation', 'updateimplementation'];
    const hasUpgradeKeyword = upgradeKeywords.some(keyword =>
      nameLower.includes(keyword)
    );

    // Check for implementation assignment pattern (not just usage)
    // e.g., implementation = newImpl, _setImplementation(newImpl)
    const hasImplementationWrite = /implementation\s*=|_setimplementation\s*\(|_upgrade\s*\(/i.test(code);

    const isUpgrade = hasUpgradeKeyword || hasImplementationWrite;

    // Only consider it an upgrade function if it's in a contract that looks like a proxy
    if (isUpgrade) {
      const contractNameLower = (this.currentContract || '').toLowerCase();
      const isProxyContract = this.proxyPatterns.uups || this.proxyPatterns.transparent ||
                             this.proxyPatterns.beacon || this.proxyPatterns.diamond ||
                             contractNameLower.includes('proxy') ||
                             contractNameLower.includes('upgradeable') ||
                             contractNameLower.includes('implementation');

      if (!isProxyContract) {
        // Not a proxy contract, skip
        return false;
      }
    }

    return isUpgrade;
  }

  /**
   * Check if initializer has protection
   */
  hasInitializerProtection(code, node) {
    const codeLower = code.toLowerCase();
    
    // Check for initializer modifier
    if (node.modifiers && node.modifiers.some(m => 
      m.name && m.name.toLowerCase().includes('initializer')
    )) {
      return true;
    }

    // Check for initialized variable check
    if (codeLower.includes('initialized') && 
        (codeLower.includes('require') || codeLower.includes('revert'))) {
      return true;
    }

    // Check for initializer() modifier usage
    if (codeLower.includes('initializer()') || codeLower.includes('!initialized')) {
      return true;
    }

    return false;
  }

  /**
   * Check if upgrade function has protection
   */
  hasUpgradeProtection(code, node) {
    const codeLower = code.toLowerCase();
    
    // Check for access control modifiers in the function definition
    const accessControlModifiers = ['onlyowner', 'onlyrole', 'onlyadmin', 'onlygovernance', 'onlyauthorized'];
    if (node.modifiers && node.modifiers.length > 0) {
      const hasAccessControl = node.modifiers.some(m => {
        if (!m || !m.name) return false;
        const modName = m.name.toLowerCase();
        return accessControlModifiers.some(ac => modName.includes(ac));
      });
      if (hasAccessControl) {
        return true;
      }
    }

    // Also check the function signature in code for modifiers
    // Pattern: function upgrade(...) public onlyAdmin
    // Modifiers can be on the same line or next line after function declaration
    const modifierPatterns = [
      /\bfunction\s+\w+\s*\([^)]*\)\s+[^{]*(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyAuthorized)/i,
      /\bfunction\s+\w+\s*\([^)]*\)\s+public\s+(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyAuthorized)/i,
      /\bfunction\s+\w+\s*\([^)]*\)\s+external\s+(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyAuthorized)/i
    ];
    
    if (modifierPatterns.some(pattern => pattern.test(code))) {
      return true;
    }
    
    // Check if modifier appears near the function declaration (within first few lines)
    const lines = code.split('\n');
    let foundFunction = false;
    for (let i = 0; i < Math.min(5, lines.length); i++) {
      const line = lines[i];
      if (line.includes('function') && line.includes('upgrade')) {
        foundFunction = true;
      }
      if (foundFunction && /\b(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|onlyAuthorized)\b/i.test(line)) {
        return true;
      }
    }

    // Check for require statements with access control in the function body
    const accessControlPatterns = [
      /require\s*\(\s*msg\.sender\s*==\s*owner/i,
      /require\s*\(\s*msg\.sender\s*==\s*admin/i,
      /require\s*\(\s*hasRole/i,
      /require\s*\(\s*_authorizeUpgrade/i,
      /\bonlyOwner\b/i,
      /\bonlyRole\b/i,
      /\bonlyAdmin\b/i
    ];

    // Also check if the function code contains modifier usage
    if (accessControlPatterns.some(pattern => pattern.test(code))) {
      return true;
    }
    
    // Check if there's a require with approvedImplementations or similar whitelist
    if (codeLower.includes('require') && 
        (codeLower.includes('approvedimplementations') || 
         codeLower.includes('trustedimplementations') ||
         codeLower.includes('whitelist'))) {
      return true;
    }

    return false;
  }

  /**
   * Check if delegatecall has protection
   */
  hasDelegatecallProtection(code) {
    const codeLower = code.toLowerCase();
    
    // Check if it's in a fallback function (standard proxy pattern)
    // Fallback functions with delegatecall are typically secure proxy patterns
    if (codeLower.includes('fallback') || codeLower.includes('receive')) {
      // Check if implementation is validated
      if (codeLower.includes('require') && (codeLower.includes('implementation') || codeLower.includes('impl'))) {
        return true;
      }
      // Assembly delegatecall in fallback is standard proxy pattern
      // Check if there's a require before the delegatecall
      const lines = code.split('\n');
      let foundRequire = false;
      let foundDelegatecall = false;
      for (const line of lines) {
        const lineLower = line.toLowerCase();
        if (lineLower.includes('require') && (lineLower.includes('implementation') || lineLower.includes('impl'))) {
          foundRequire = true;
        }
        if (lineLower.includes('delegatecall')) {
          foundDelegatecall = true;
          // If we found delegatecall and there was a require before, it's protected
          if (foundRequire) {
            return true;
          }
        }
      }
      // Assembly delegatecall in fallback with implementation variable is standard pattern
      if (codeLower.includes('assembly') && codeLower.includes('delegatecall') && 
          (codeLower.includes('implementation') || codeLower.includes('impl'))) {
        return true;
      }
    }
    
    // Should validate implementation address
    const validationPatterns = [
      /require\s*\(\s*.*implementation/i,
      /require\s*\(\s*.*impl\s*!=\s*address\(0\)/i,
      /require\s*\(\s*.*code\.length\s*>\s*0/i,
      /isContract\s*\(/i,
      /address\(.*\)\.code\.length/i,
      /approvedImplementations\[/i,
      /trustedImplementations\[/i
    ];

    return validationPatterns.some(pattern => pattern.test(codeLower));
  }

  /**
   * Check if EIP-1967 storage access has protection
   */
  hasEIP1967Protection(code) {
    const codeLower = code.toLowerCase();
    
    // Should have access control
    return /onlyOwner|onlyRole|_authorizeUpgrade|require.*msg\.sender/i.test(codeLower);
  }

  /**
   * Generate Foundry PoC for initializer exploit
   */
  generateInitializerPoC(contractName, funcName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Unprotected Initializer Exploit
 * Target: ${contractName}.${funcName}()
 * Attack Vector: Re-initialize proxy to corrupt storage
 */
contract InitializerExploit is Test {
    address constant PROXY = address(0); // ${contractName} proxy address
    address attacker = address(this);

    function testExploit() public {
        // 1. Call initializer multiple times to corrupt storage
        // ${contractName}(PROXY).${funcName}(...);
        
        // 2. First call sets owner to legitimate address
        // Second call can overwrite storage if unprotected
        
        // 3. If storage is corrupted, attacker can:
        //    - Change owner to attacker address
        //    - Reset balances
        //    - Corrupt critical state variables
        
        // Assert storage corruption
        // assertEq(owner, attacker);
    }
}`;
  }

  /**
   * Generate Foundry PoC for unauthorized upgrade
   */
  generateUpgradePoC(contractName, funcName) {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Proof of Concept: Unauthorized Upgrade Exploit
 * Target: ${contractName}.${funcName}()
 * Attack Vector: Upgrade to malicious implementation
 */
contract UpgradeExploit is Test {
    address constant PROXY = address(0); // ${contractName} proxy address
    MaliciousImplementation maliciousImpl;

    function setUp() public {
        maliciousImpl = new MaliciousImplementation();
    }

    function testExploit() public {
        // 1. Deploy malicious implementation
        // MaliciousImplementation impl = new MaliciousImplementation();
        
        // 2. Call upgrade function without authorization
        // ${contractName}(PROXY).${funcName}(address(impl));
        
        // 3. Malicious implementation can:
        //    - Steal all funds via selfdestruct
        //    - Change owner
        //    - Break functionality
        
        // Assert exploit succeeded
        // assertEq(address(PROXY).balance, 0);
    }
}

contract MaliciousImplementation {
    function initialize() external {
        // Steal funds
        selfdestruct(payable(msg.sender));
    }
}`;
  }
}

module.exports = ProxyVulnerabilitiesDetector;

