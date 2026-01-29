const BaseDetector = require('./base-detector');

/**
 * Governance Attack Detector
 * Detects vulnerabilities in governance mechanisms that can lead to:
 * - Governance takeover via flash loan voting
 * - Proposal hijacking
 * - Vote manipulation
 * - Timelock bypass
 *
 * Immunefi Critical: Governance takeover = full protocol control
 */
class GovernanceAttackDetector extends BaseDetector {
  constructor() {
    super(
      'Governance Attack',
      'Detects governance vulnerabilities exploitable for protocol takeover',
      'CRITICAL'
    );
    this.currentContract = null;
    this.currentFunction = null;
    this.governancePatterns = [];
    this.votingMechanisms = [];
    this.timelocks = [];
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.governancePatterns = [];
    this.votingMechanisms = [];
    this.timelocks = [];

    this.traverse(ast);
    this.analyzeGovernancePatterns();

    return this.findings;
  }

  visitContractDefinition(node) {
    this.currentContract = node.name;

    // Check if this is a governance contract
    const baseContracts = (node.baseContracts || []).map(b =>
      b.baseName?.namePath || ''
    ).join(' ');

    if (/Governor|Governance|DAO|Voting|Timelock/i.test(this.currentContract) ||
        /Governor|Governance|DAO|Voting|Timelock/i.test(baseContracts)) {
      this.governancePatterns.push({
        contract: this.currentContract,
        type: 'governance_contract',
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

    // Detect voting functions
    this.detectVotingVulnerabilities(funcCode, node, funcName);

    // Detect proposal functions
    this.detectProposalVulnerabilities(funcCode, node, funcName);

    // Detect timelock issues
    this.detectTimelockVulnerabilities(funcCode, node, funcName);

    // Detect flash loan governance
    this.detectFlashLoanGovernance(funcCode, node, funcName);
  }

  /**
   * Detect voting mechanism vulnerabilities
   */
  detectVotingVulnerabilities(funcCode, node, funcName) {
    // Flash loan voting - voting power from current balance
    if (/vote|castVote/i.test(funcName)) {
      // Check if voting power is from current balance (flash loan vulnerable)
      if (/balanceOf\s*\(|getVotes\s*\(/.test(funcCode)) {
        // Check for snapshot protection
        const hasSnapshot = /getPastVotes|getPastTotalSupply|snapshot|checkpoint/i.test(funcCode);
        const hasBlockDelay = /block\.number\s*-|votingDelay|proposalSnapshot/i.test(funcCode);

        if (!hasSnapshot && !hasBlockDelay) {
          this.addFinding({
            title: 'Flash Loan Governance Attack',
            description: `Function '${this.currentFunction}' uses current balance for voting power without snapshot protection. Attacker can:
1. Take flash loan of governance tokens
2. Vote with borrowed voting power
3. Return tokens in same transaction
4. Pass malicious proposal with temporary supermajority

This enables full governance takeover with zero capital.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: node.loc?.start?.line || 0,
            column: node.loc?.start?.column || 0,
            code: funcCode.substring(0, 300),
            severity: 'CRITICAL',
            confidence: 'HIGH',
            exploitable: true,
            exploitabilityScore: 95,
            attackVector: 'flash-loan-governance',
            recommendation: `Implement snapshot-based voting:
1. Use ERC20Votes with getPastVotes(account, blockNumber)
2. Snapshot voting power at proposal creation time
3. Add voting delay (proposalSnapshot = block.number + votingDelay)
4. Consider vote escrow (veToken) requiring time-locked tokens`,
            references: [
              'https://www.comp.xyz/t/flash-loan-governance-attacks/2289',
              'https://docs.openzeppelin.com/contracts/4.x/api/governance'
            ],
            foundryPoC: this.generateFlashLoanGovernancePoC()
          });
        }
      }

      // Vote delegation manipulation
      if (/delegate|delegatee/i.test(funcCode)) {
        if (!/block\.number|snapshot|checkpoint/i.test(funcCode)) {
          this.addFinding({
            title: 'Delegation Manipulation Risk',
            description: `Vote delegation in '${this.currentFunction}' may allow manipulation. Attackers can delegate/undelegate around snapshot times to double-count votes or avoid dilution.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: node.loc?.start?.line || 0,
            code: funcCode.substring(0, 200),
            severity: 'HIGH',
            confidence: 'MEDIUM',
            exploitable: true,
            exploitabilityScore: 70,
            attackVector: 'delegation-manipulation',
            recommendation: 'Use checkpointed delegation with historical lookups. Ensure delegation changes are reflected in past vote calculations.'
          });
        }
      }
    }
  }

  /**
   * Detect proposal mechanism vulnerabilities
   */
  detectProposalVulnerabilities(funcCode, node, funcName) {
    if (/propose|createProposal|submitProposal/i.test(funcName)) {
      // Check proposal threshold
      const hasThreshold = /proposalThreshold|minProposerBalance|require.*balance/i.test(funcCode);

      if (!hasThreshold) {
        this.addFinding({
          title: 'Missing Proposal Threshold',
          description: `Function '${this.currentFunction}' allows creating proposals without minimum token threshold. Attacker can spam proposals or create malicious proposals with dust amounts.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 200),
          severity: 'MEDIUM',
          confidence: 'HIGH',
          exploitable: true,
          exploitabilityScore: 60,
          attackVector: 'proposal-spam',
          recommendation: 'Require minimum token balance or stake to create proposals: require(getVotes(msg.sender) >= proposalThreshold)'
        });
      }

      // Check for arbitrary execution
      if (/\.call\s*\(|delegatecall|target.*data/i.test(funcCode)) {
        if (!/timelock|delay|queue/i.test(funcCode)) {
          this.addFinding({
            title: 'Proposal Execution Without Timelock',
            description: `Proposals in '${this.currentFunction}' may execute immediately without timelock. Malicious proposals could drain funds before users can react.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: node.loc?.start?.line || 0,
            code: funcCode.substring(0, 200),
            severity: 'HIGH',
            confidence: 'MEDIUM',
            exploitable: true,
            exploitabilityScore: 75,
            attackVector: 'instant-governance',
            recommendation: 'Add mandatory timelock delay between proposal passing and execution: require(block.timestamp >= proposal.eta)'
          });
        }
      }
    }

    // Execute function vulnerabilities
    if (/execute|executeProposal/i.test(funcName)) {
      // Check for reentrancy in execution
      if (/\.call\s*\(|\.transfer\s*\(/.test(funcCode)) {
        if (!/nonReentrant|_status|locked/i.test(funcCode)) {
          this.addFinding({
            title: 'Governance Execution Reentrancy',
            description: `Proposal execution in '${this.currentFunction}' makes external calls without reentrancy protection. Malicious proposal targets could reenter and manipulate governance state.`,
            location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
            line: node.loc?.start?.line || 0,
            code: funcCode.substring(0, 200),
            severity: 'HIGH',
            confidence: 'HIGH',
            exploitable: true,
            exploitabilityScore: 80,
            attackVector: 'governance-reentrancy',
            recommendation: 'Add nonReentrant modifier to proposal execution functions.'
          });
        }
      }
    }
  }

  /**
   * Detect timelock vulnerabilities
   */
  detectTimelockVulnerabilities(funcCode, node, funcName) {
    // Emergency bypass
    if (/emergency|bypass|skip.*delay/i.test(funcName)) {
      this.addFinding({
        title: 'Timelock Emergency Bypass',
        description: `Function '${this.currentFunction}' appears to bypass timelock. If access control is compromised, attacker can execute malicious transactions immediately.`,
        location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
        line: node.loc?.start?.line || 0,
        code: funcCode.substring(0, 200),
        severity: 'HIGH',
        confidence: 'MEDIUM',
        exploitable: true,
        exploitabilityScore: 70,
        attackVector: 'timelock-bypass',
        recommendation: 'Emergency functions should still have minimum delay or require multi-sig. Document and audit all bypass mechanisms.'
      });
    }

    // Zero delay timelock
    if (/setDelay|updateDelay/i.test(funcName)) {
      if (!/require.*delay\s*>=|minDelay|MIN_DELAY/i.test(funcCode)) {
        this.addFinding({
          title: 'Timelock Delay Can Be Set to Zero',
          description: `Function '${this.currentFunction}' may allow setting timelock delay to zero, effectively disabling governance protection.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 200),
          severity: 'CRITICAL',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 85,
          attackVector: 'timelock-disable',
          recommendation: 'Enforce minimum delay: require(newDelay >= MIN_DELAY) where MIN_DELAY is at least 24-48 hours.'
        });
      }
    }
  }

  /**
   * Detect flash loan governance patterns across contract
   */
  detectFlashLoanGovernance(funcCode, node, funcName) {
    // Check for token transfer functions that could enable flash loan attacks
    if (/transfer|transferFrom/i.test(funcCode) && /vote|governance/i.test(this.currentContract.toLowerCase())) {
      // Check if voting checkpoints are updated on transfer
      const updatesCheckpoint = /_writeCheckpoint|_moveVotingPower|_afterTokenTransfer/i.test(funcCode);

      if (!updatesCheckpoint && /balanceOf/.test(funcCode)) {
        this.addFinding({
          title: 'Voting Power Not Checkpointed on Transfer',
          description: `Token transfer in governance contract doesn't checkpoint voting power. This enables flash loan attacks where attacker borrows tokens, votes, and returns in same block.`,
          location: `Contract: ${this.currentContract}, Function: ${this.currentFunction}`,
          line: node.loc?.start?.line || 0,
          code: funcCode.substring(0, 200),
          severity: 'CRITICAL',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 85,
          attackVector: 'flash-loan-governance',
          recommendation: 'Use ERC20Votes or implement checkpointing in _afterTokenTransfer to track historical balances.'
        });
      }
    }
  }

  analyzeGovernancePatterns() {
    // Cross-reference governance patterns for compound vulnerabilities
    if (this.governancePatterns.length > 0) {
      // Check for lack of quorum
      const hasQuorum = this.sourceCode.match(/quorum|minVotes|minimumVotes/i);
      if (!hasQuorum) {
        const govContract = this.governancePatterns[0];
        this.addFinding({
          title: 'Missing Quorum Requirement',
          description: `Governance contract '${govContract.contract}' may lack quorum requirements. Proposals could pass with minimal participation, enabling governance capture with small token holdings.`,
          location: `Contract: ${govContract.contract}`,
          line: govContract.node.loc?.start?.line || 0,
          severity: 'HIGH',
          confidence: 'MEDIUM',
          exploitable: true,
          exploitabilityScore: 70,
          attackVector: 'low-quorum-governance',
          recommendation: 'Implement quorum requirement: require(forVotes + againstVotes >= quorum())'
        });
      }
    }
  }

  generateFlashLoanGovernancePoC() {
    return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

/**
 * Flash Loan Governance Attack PoC
 * Exploits voting based on current balance without snapshot
 */
interface IGovernance {
    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata description) external returns (uint256);
    function castVote(uint256 proposalId, uint8 support) external;
    function execute(uint256 proposalId) external;
}

interface IFlashLoan {
    function flashLoan(address token, uint256 amount, bytes calldata data) external;
}

contract GovernanceExploit is Test {
    IGovernance governance;
    IFlashLoan flashLender;
    address govToken;

    function testFlashLoanGovernanceAttack() public {
        // 1. Create malicious proposal (drain treasury)
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);

        targets[0] = address(governance);
        calldatas[0] = abi.encodeWithSignature("withdrawAll(address)", address(this));

        uint256 proposalId = governance.propose(targets, values, calldatas, "Drain treasury");

        // 2. Flash loan massive amount of governance tokens
        // flashLender.flashLoan(govToken, 10_000_000e18, abi.encode(proposalId));

        // In callback:
        // - Cast vote with flash loaned tokens
        // governance.castVote(proposalId, 1); // Vote yes
        // - Return tokens to flash lender

        // 3. Execute proposal (if no timelock)
        // governance.execute(proposalId);

        // Result: Treasury drained with zero capital
    }
}`;
  }
}

module.exports = GovernanceAttackDetector;
