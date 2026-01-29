const BaseDetector = require('./base-detector');

/**
 * Token Standard Compliance Detector
 * Ensures tokens strictly follow ERC standards (ERC20, ERC721, ERC1155)
 * 
 * Detects:
 * - Missing required functions for ERC standards
 * - Incorrect function signatures
 * - Missing events
 * - Non-standard return values
 * - Missing approvals/transfers
 * - Incorrect behavior patterns
 */
class TokenStandardComplianceDetector extends BaseDetector {
  constructor() {
    super(
      'Token Standard Compliance',
      'Detects violations of ERC token standards (ERC20, ERC721, ERC1155)',
      'HIGH'
    );
    this.currentContract = null;
    this.tokenStandard = null; // 'ERC20', 'ERC721', 'ERC1155', or null
    this.requiredFunctions = {
      ERC20: ['totalSupply', 'balanceOf', 'transfer', 'transferFrom', 'approve', 'allowance'],
      ERC721: ['balanceOf', 'ownerOf', 'safeTransferFrom', 'transferFrom', 'approve', 'setApprovalForAll', 'getApproved', 'isApprovedForAll'],
      ERC1155: ['balanceOf', 'balanceOfBatch', 'setApprovalForAll', 'isApprovedForAll', 'safeTransferFrom', 'safeBatchTransferFrom']
    };
    this.requiredEvents = {
      ERC20: ['Transfer', 'Approval'],
      ERC721: ['Transfer', 'Approval', 'ApprovalForAll'],
      ERC1155: ['TransferSingle', 'TransferBatch', 'ApprovalForAll', 'URI']
    };
    this.foundFunctions = new Set();
    this.foundEvents = new Set();
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;

    // Reset per-file state
    this.tokenStandard = null;
    this.foundFunctions.clear();
    this.foundEvents.clear();
    this.currentContract = null;

    // Detect which standard this contract implements
    this.detectTokenStandard(sourceCode);

    if (!this.tokenStandard) {
      // Not a token contract, skip
      return this.findings;
    }

    this.traverse(ast);

    // Post-traversal analysis
    this.analyzeCompliance();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;
    this.foundFunctions.clear();
    this.foundEvents.clear();
  }

  visitFunctionDefinition(node) {
    const funcName = node.name || '';
    
    if (this.tokenStandard) {
      // Check if this is a required function
      const required = this.requiredFunctions[this.tokenStandard] || [];
      if (required.includes(funcName)) {
        this.foundFunctions.add(funcName);
        
        // Validate function signature and behavior
        this.validateFunction(node, funcName);
      }
    }
  }

  visitEventDefinition(node) {
    const eventName = node.name || '';
    
    if (this.tokenStandard) {
      const required = this.requiredEvents[this.tokenStandard] || [];
      if (required.includes(eventName)) {
        this.foundEvents.add(eventName);
        
        // Validate event signature
        this.validateEvent(node, eventName);
      }
    }
  }

  /**
   * Detect which ERC standard this contract implements
   */
  detectTokenStandard(sourceCode) {
    // Strip imports/comments so "ERC20" in import paths doesn't misclassify non-token contracts
    const stripped = sourceCode
      .replace(/^\s*import[^;]*;/gm, '')
      .replace(/\/\/.*$/gm, '')
      .replace(/\/\*[\s\S]*?\*\//g, '');

    const codeLower = stripped.toLowerCase();
    
    // Check for explicit ERC standard inheritance or interface implementation
    const hasERCInterface =
      /contract\s+\w+\s+(?:is|implements)\s+.*\b(IERC|ERC)\d+\b/i.test(stripped) ||
      /contract\s+\w+\s+(?:is|implements)\s+.*\bERC\b/i.test(stripped);
    
    // Check for ERC1155 (most specific)
    if (codeLower.includes('erc1155') || 
        codeLower.includes('multitoken') ||
        (codeLower.includes('balanceofbatch') && codeLower.includes('safebatchtransferfrom'))) {
      this.tokenStandard = 'ERC1155';
      return;
    }

    // Check for ERC721
    if (codeLower.includes('erc721') || 
        (codeLower.includes('nft') && codeLower.includes('ownerof')) ||
        (codeLower.includes('ownerof') && codeLower.includes('tokenuri')) ||
        (codeLower.includes('setapprovalforall') && codeLower.includes('ownerof'))) {
      this.tokenStandard = 'ERC721';
      return;
    }

    // Check for ERC20 - need multiple indicators to avoid false positives
    // Must have both transfer/transferFrom AND approve/allowance patterns
    const hasTransfer = /function\s+transfer/i.test(sourceCode) || /function\s+transferFrom/i.test(sourceCode);
    const hasApprove = /function\s+approve/i.test(sourceCode) || /function\s+allowance/i.test(sourceCode);
    const hasBalanceOf = /function\s+balanceOf/i.test(sourceCode);
    const hasTotalSupply = /function\s+totalSupply/i.test(sourceCode);
    
    // Only treat as ERC20 if it is explicitly implemented/inherited, or declares core ERC20 functions
    if (hasERCInterface) {
      this.tokenStandard = 'ERC20';
      return;
    }
    
    // Only detect ERC20 if it has multiple token functions (not just one)
    if ((hasTransfer && hasApprove && hasBalanceOf) || 
        (hasTransfer && hasTotalSupply && hasBalanceOf)) {
      this.tokenStandard = 'ERC20';
      return;
    }
  }

  /**
   * Validate function implementation
   */
  validateFunction(node, funcName) {
    const funcCode = this.getCodeSnippet(node.loc);
    const funcCodeLower = funcCode.toLowerCase();

    // ERC20 specific validations
    if (this.tokenStandard === 'ERC20') {
      this.validateERC20Function(node, funcName, funcCode);
    }

    // ERC721 specific validations
    if (this.tokenStandard === 'ERC721') {
      this.validateERC721Function(node, funcName, funcCode);
    }

    // ERC1155 specific validations
    if (this.tokenStandard === 'ERC1155') {
      this.validateERC1155Function(node, funcName, funcCode);
    }
  }

  /**
   * Validate ERC20 function
   */
  validateERC20Function(node, funcName, code) {
    const codeLower = code.toLowerCase();

    // transfer/transferFrom must emit Transfer event
    if ((funcName === 'transfer' || funcName === 'transferFrom') && 
        !codeLower.includes('emit transfer')) {
      this.addFinding({
        title: 'ERC20 Transfer Missing Transfer Event',
        description: `ERC20 function '${funcName}' does not emit Transfer event. This violates ERC20 standard and breaks compatibility with wallets, DEXs, and other contracts expecting the event.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 30,
        attackVector: 'standard-compliance',
        recommendation: 'Emit Transfer event: emit Transfer(from, to, amount);',
        references: [
          'https://eips.ethereum.org/EIPS/eip-20',
          'https://swcregistry.io/docs/SWC-140'
        ]
      });
    }

    // approve must emit Approval event
    if (funcName === 'approve' && !codeLower.includes('emit approval')) {
      this.addFinding({
        title: 'ERC20 Approve Missing Approval Event',
        description: `ERC20 function 'approve' does not emit Approval event. This violates ERC20 standard.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 30,
        attackVector: 'standard-compliance',
        recommendation: 'Emit Approval event: emit Approval(owner, spender, amount);',
        references: [
          'https://eips.ethereum.org/EIPS/eip-20'
        ]
      });
    }

    // Check for non-standard return values (should return bool)
    if ((funcName === 'transfer' || funcName === 'transferFrom' || funcName === 'approve') &&
        node.returnParameters && node.returnParameters.length === 0) {
      // Some ERC20 implementations don't return bool, but it's non-standard
      this.addFinding({
        title: 'ERC20 Function Missing Return Value',
        description: `ERC20 function '${funcName}' should return bool according to standard. Missing return value may break compatibility with some contracts.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'MEDIUM',
        confidence: 'MEDIUM',
        exploitable: false,
        exploitabilityScore: 20,
        attackVector: 'standard-compliance',
        recommendation: 'Add return bool to function signature: function transfer(...) public returns (bool)',
        references: [
          'https://eips.ethereum.org/EIPS/eip-20'
        ]
      });
    }
  }

  /**
   * Validate ERC721 function
   */
  validateERC721Function(node, funcName, code) {
    const codeLower = code.toLowerCase();

    // transferFrom/safeTransferFrom must emit Transfer event
    if ((funcName === 'transferFrom' || funcName === 'safeTransferFrom') &&
        !codeLower.includes('emit transfer')) {
      this.addFinding({
        title: 'ERC721 Transfer Missing Transfer Event',
        description: `ERC721 function '${funcName}' does not emit Transfer event. This violates ERC721 standard.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 30,
        attackVector: 'standard-compliance',
        recommendation: 'Emit Transfer event: emit Transfer(from, to, tokenId);',
        references: [
          'https://eips.ethereum.org/EIPS/eip-721'
        ]
      });
    }

    // approve must emit Approval event
    if (funcName === 'approve' && !codeLower.includes('emit approval')) {
      this.addFinding({
        title: 'ERC721 Approve Missing Approval Event',
        description: `ERC721 function 'approve' does not emit Approval event. This violates ERC721 standard.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 30,
        attackVector: 'standard-compliance',
        recommendation: 'Emit Approval event: emit Approval(owner, approved, tokenId);',
        references: [
          'https://eips.ethereum.org/EIPS/eip-721'
        ]
      });
    }

    // setApprovalForAll must emit ApprovalForAll event
    if (funcName === 'setApprovalForAll' && !codeLower.includes('emit approvalforall')) {
      this.addFinding({
        title: 'ERC721 setApprovalForAll Missing ApprovalForAll Event',
        description: `ERC721 function 'setApprovalForAll' does not emit ApprovalForAll event. This violates ERC721 standard.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 30,
        attackVector: 'standard-compliance',
        recommendation: 'Emit ApprovalForAll event: emit ApprovalForAll(owner, operator, approved);',
        references: [
          'https://eips.ethereum.org/EIPS/eip-721'
        ]
      });
    }
  }

  /**
   * Validate ERC1155 function
   */
  validateERC1155Function(node, funcName, code) {
    const codeLower = code.toLowerCase();

    // safeTransferFrom must emit TransferSingle event
    if (funcName === 'safeTransferFrom' && !codeLower.includes('emit transfersingle')) {
      this.addFinding({
        title: 'ERC1155 safeTransferFrom Missing TransferSingle Event',
        description: `ERC1155 function 'safeTransferFrom' does not emit TransferSingle event. This violates ERC1155 standard.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 30,
        attackVector: 'standard-compliance',
        recommendation: 'Emit TransferSingle event: emit TransferSingle(operator, from, to, id, value);',
        references: [
          'https://eips.ethereum.org/EIPS/eip-1155'
        ]
      });
    }

    // safeBatchTransferFrom must emit TransferBatch event
    if (funcName === 'safeBatchTransferFrom' && !codeLower.includes('emit transferbatch')) {
      this.addFinding({
        title: 'ERC1155 safeBatchTransferFrom Missing TransferBatch Event',
        description: `ERC1155 function 'safeBatchTransferFrom' does not emit TransferBatch event. This violates ERC1155 standard.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 30,
        attackVector: 'standard-compliance',
        recommendation: 'Emit TransferBatch event: emit TransferBatch(operator, from, to, ids, values);',
        references: [
          'https://eips.ethereum.org/EIPS/eip-1155'
        ]
      });
    }

    // setApprovalForAll must emit ApprovalForAll event
    if (funcName === 'setApprovalForAll' && !codeLower.includes('emit approvalforall')) {
      this.addFinding({
        title: 'ERC1155 setApprovalForAll Missing ApprovalForAll Event',
        description: `ERC1155 function 'setApprovalForAll' does not emit ApprovalForAll event. This violates ERC1155 standard.`,
        location: `Contract: ${this.currentContract}, Function: ${funcName}`,
        line: node.loc ? node.loc.start.line : 0,
        column: node.loc ? node.loc.start.column : 0,
        code: this.getCodeSnippet(node.loc),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 30,
        attackVector: 'standard-compliance',
        recommendation: 'Emit ApprovalForAll event: emit ApprovalForAll(owner, operator, approved);',
        references: [
          'https://eips.ethereum.org/EIPS/eip-1155'
        ]
      });
    }
  }

  /**
   * Validate event signature
   */
  validateEvent(node, eventName) {
    // Basic validation - events should have correct parameters
    // This is a simplified check; full validation would require parameter matching
  }

  /**
   * Post-traversal compliance analysis
   */
  analyzeCompliance() {
    if (!this.tokenStandard) return;

    const requiredFuncs = this.requiredFunctions[this.tokenStandard] || [];
    const requiredEvents = this.requiredEvents[this.tokenStandard] || [];

    // Check for missing required functions
    const missingFunctions = requiredFuncs.filter(func => !this.foundFunctions.has(func));
    if (missingFunctions.length > 0) {
      this.addFinding({
        title: `Missing Required ${this.tokenStandard} Functions`,
        description: `Contract claims to implement ${this.tokenStandard} but is missing required functions: ${missingFunctions.join(', ')}. This breaks standard compliance and may cause integration issues.`,
        location: `Contract: ${this.currentContract}`,
        line: 1,
        column: 0,
        code: this.sourceCode.substring(0, 200),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 40,
        attackVector: 'standard-compliance',
        recommendation: `Implement all required ${this.tokenStandard} functions. Use OpenZeppelin's standard implementations as reference.`,
        references: [
          this.tokenStandard === 'ERC20' ? 'https://eips.ethereum.org/EIPS/eip-20' :
          this.tokenStandard === 'ERC721' ? 'https://eips.ethereum.org/EIPS/eip-721' :
          'https://eips.ethereum.org/EIPS/eip-1155'
        ]
      });
    }

    // Check for missing required events
    const missingEvents = requiredEvents.filter(event => !this.foundEvents.has(event));
    if (missingEvents.length > 0) {
      this.addFinding({
        title: `Missing Required ${this.tokenStandard} Events`,
        description: `Contract claims to implement ${this.tokenStandard} but is missing required events: ${missingEvents.join(', ')}. This breaks standard compliance.`,
        location: `Contract: ${this.currentContract}`,
        line: 1,
        column: 0,
        code: this.sourceCode.substring(0, 200),
        severity: 'HIGH',
        confidence: 'HIGH',
        exploitable: false,
        exploitabilityScore: 40,
        attackVector: 'standard-compliance',
        recommendation: `Declare all required ${this.tokenStandard} events. Events are essential for off-chain indexing and monitoring.`,
        references: [
          this.tokenStandard === 'ERC20' ? 'https://eips.ethereum.org/EIPS/eip-20' :
          this.tokenStandard === 'ERC721' ? 'https://eips.ethereum.org/EIPS/eip-721' :
          'https://eips.ethereum.org/EIPS/eip-1155'
        ]
      });
    }
  }
}

module.exports = TokenStandardComplianceDetector;

