# WEB3CRIT Scanner

<p align="center">
  <img src="web3crit-scanner_animated.gif" alt="WEB3CRIT Scanner Gif" width="250">
</p>

**Production-grade smart contract vulnerability scanner for $5M+ TVL protocols and Immunefi High/Critical bounties**

Web3CRIT Scanner is an exploit-driven static analysis tool for Solidity smart contracts. **v6.0.0** introduces **Production Mode** - a strict PoC-gating system that only emits HIGH/CRITICAL findings when a Foundry PoC compiles, executes, and proves real impact (fund drain, unauthorized transfer, role takeover, invariant break, or permanent DoS).

## Production Mode (NEW in v6.0.0)

For bug bounty submissions and professional audits, use `--production` to enforce:

```bash
web3crit scan ./contracts --production --foundry-root /path/to/foundry-project
```

**Hard Rules Enforced:**
- HIGH/CRITICAL only emitted if Foundry PoC compiles, executes, and proves impact
- Impact must be: fund drain, unauthorized transfer, role takeover, invariant break, or permanent DoS
- If PoC fails to compile, run, or show impact → discarded silently
- Severity derived from observed PoC results, not heuristics
- No placeholder PoCs, no symbolic-only exploits

## Key Features

- **Production Mode (NEW)** - Strict PoC-gating for HIGH/CRITICAL with proven impact verification
- **Control Flow Graph Analysis** - Tracks execution paths and function call relationships across contracts
- **Data Flow Analysis** - Traces tainted user inputs to dangerous operations (delegatecall, selfdestruct, etc.)
- **Oracle → Value Flow Tracking** - Detects oracle reads flowing into value-moving operations (transfer/mint/burn/refunds)
- **Immunefi Classification** - Maps findings to Immunefi payout categories (Direct Theft, Protocol Insolvency, etc.)
- **Exploit Chain Modeling** - Models attack assumptions (flash loans, MEV, malicious contracts)
- **Foundry PoC Execution** - Compiles and runs PoCs with impact extraction from forge output
- **Fork Testing Support** - `--fork-url` enables on-chain state verification
- **Multi-Contract Scanning** - Scan entire directories of Solidity files at once
- **Enhanced Reentrancy Detection** - Detects classic, cross-function, callback, and cross-contract reentrancy
- **Access Control Validation** - Analyzes what modifiers actually do, not just that they exist
- **npm Installable** - Install globally and use alongside Slither, Mythril, Aderyn, Manticore
- **Multiple Output Formats** - JSON, Markdown, Table, or Plain Text

## Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/critfinds/Web3CRIT-Scanner
cd Web3CRIT-Scanner
./install.sh
```

The install script will:
- Check Node.js and npm versions
- Install all dependencies
- Install web3crit globally
- Verify the installation

### Manual Installation

```bash
git clone https://github.com/critfinds/Web3CRIT-Scanner
cd Web3CRIT-Scanner
npm install
npm install -g .
```

### From npm (when published)

```bash
npm install -g web3crit-scanner
```

### Using npx (no installation)

```bash
npx web3crit-scanner scan contract.sol
```

See [INSTALL.md](INSTALL.md) for detailed installation instructions and troubleshooting.

## Usage

### Single Contract

```bash
# Basic scan
web3crit scan MyContract.sol

# JSON output
web3crit scan MyContract.sol --format json

# Critical issues only
web3crit scan MyContract.sol --severity critical

# Exploit-driven (attach exploit chains + Immunefi classification)
web3crit scan MyContract.sol --exploit-driven

# Strict Immunefi mode (High/Critical payout-eligible only)
web3crit scan MyContract.sol --immunefi-only
```

### Multiple Contracts

```bash
# Scan entire directory
web3crit scan contracts/

# Scan with JSON output and save to file
web3crit scan contracts/ --format json --output results.json

# Show only high and critical issues
web3crit scan contracts/ --severity high
```

### Integration with Other Tools

```bash
# Use alongside Slither
slither contracts/ --json slither-results.json
web3crit scan contracts/ --format json --output web3crit-results.json

# Compare findings
cat web3crit-results.json | jq '.stats'
cat slither-results.json | jq '.results.detectors | length'
```

## Vulnerability Detectors

Web3CRIT v6.0.0 includes enhanced detectors with logic-based analysis, plus specialized detectors for high-value TVL contracts and exploit-driven gating.

### Core Enhanced Detectors

Web3CRIT v4.0.0+ includes 5 enhanced detectors with logic-based analysis:

### 1. Reentrancy (Enhanced) - CRITICAL

Detects reentrancy vulnerabilities using control flow and data flow analysis:
- **Classic Reentrancy** - External calls before state updates
- **Cross-Function Reentrancy** - Reentrancy across multiple functions
- **Read-Only Reentrancy** - State reads after external calls in view functions
- **Reentrancy Guard Validation** - Verifies guards actually work (not just named correctly)
- **Exploitability Check** - Only reports if publicly accessible and no effective protection

**Example Vulnerable Code:**
```solidity
function withdraw() public {
    uint256 amount = balances[msg.sender];
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success);
    balances[msg.sender] = 0;  // State update AFTER external call
}
```

### 2. Access Control (Enhanced) - CRITICAL

Validates access control logic instead of just checking for modifier presence:
- **Missing Access Control** - Sensitive functions without protection
- **Broken Modifiers** - Empty modifiers or always-true conditions
- **Weak Patterns** - Balance-based or timestamp-based access control
- **tx.origin Usage** - Detects vulnerable phishing patterns in modifiers
- **Modifier Logic Analysis** - Analyzes require statements to verify actual protection

**Example Vulnerable Code:**
```solidity
// Missing access control
function setOwner(address newOwner) public {
    owner = newOwner;
}

// Broken modifier
modifier onlyOwner() {
    require(true);  // Always passes!
    _;
}
```

### 3. Unchecked External Calls - HIGH

Detects external calls where return values are not properly checked:
- Low-level `.call()` without checking success
- `.send()` without checking return value
- `.delegatecall()` without error handling

**Example Vulnerable Code:**
```solidity
function unsafeTransfer(address payable recipient, uint256 amount) public {
    recipient.send(amount);  // Return value not checked
}
```

### 4. Dangerous Delegatecall - CRITICAL

Identifies user-controlled delegatecall targets:
- Detects delegatecall with user-controlled addresses
- Warns about storage layout compatibility issues
- Validates if proper access control exists

**Example Vulnerable Code:**
```solidity
function upgrade(address newImpl, bytes memory data) public {
    newImpl.delegatecall(data);  // User-controlled target
}
```

### 5. Unprotected Selfdestruct - CRITICAL

Finds selfdestruct operations without proper access control:
- Detects public selfdestruct without modifiers
- Validates access control effectiveness

**Example Vulnerable Code:**
```solidity
function destroy(address payable recipient) public {
    selfdestruct(recipient);  // Anyone can destroy contract
}
```

### High-Value TVL Contract Detectors (v5.2.0+)

These detectors are specifically designed for high-value contracts (>$1M TVL) and provide deeper coverage:

### 6. Proxy Contract Vulnerabilities - CRITICAL

Detects critical issues in upgradeable contracts (UUPS, Transparent Proxies, EIP-1967):
- **Unprotected Initializers** - Missing initialization protection allowing re-initialization
- **Unauthorized Upgrades** - Upgrade functions without access control
- **Missing _authorizeUpgrade** - UUPS pattern without required authorization
- **Storage Collision** - Potential storage layout conflicts in upgrades
- **Unprotected Delegatecall** - Delegatecall without implementation validation
- **EIP-1967 Storage Access** - Direct storage slot manipulation without protection

**Example Vulnerable Code:**
```solidity
// Unprotected initializer
function initialize(address _owner) public {
    owner = _owner;  // Can be called multiple times!
}

// Unauthorized upgrade
function upgrade(address newImpl) public {
    implementation = newImpl;  // Anyone can upgrade!
}
```

**Testing Strategy:**
- Unit tests with vulnerable proxy patterns
- Integration tests with OpenZeppelin proxy contracts
- Foundry PoCs demonstrating initialization and upgrade exploits

### 7. Signature Replay - HIGH

Detects missing replay protection in contracts using off-chain signatures:
- **Missing Nonce** - Signatures can be reused multiple times
- **Missing Expiration** - Old signatures remain valid indefinitely
- **Missing Chain ID** - Cross-chain replay attacks possible
- **Weak Validation** - Direct ecrecover without EIP-712

**Example Vulnerable Code:**
```solidity
function permitTransfer(address from, address to, uint256 amount, bytes memory sig) public {
    address signer = ecrecover(...);
    require(signer == from);
    // No nonce check - signature can be replayed!
    balances[from] -= amount;
    balances[to] += amount;
}
```

**Testing Strategy:**
- Unit tests with signature verification functions
- Integration tests with EIP-2612 permit patterns
- Foundry PoCs demonstrating signature replay attacks

### 8. Cross-Contract Reentrancy - CRITICAL

Detects complex reentrancy attacks involving multiple contracts:
- **Multi-Contract Reentrancy** - Reentrancy across multiple contracts in same transaction
- **State-Dependent Reentrancy** - State changes in one contract affecting another
- **Delegatecall Reentrancy** - Reentrancy via delegatecall patterns
- **Missing Guards** - Cross-contract interactions without reentrancy protection

**Example Vulnerable Code:**
```solidity
function withdrawFromBoth() public {
    uint256 balanceA = balances[msg.sender];
    contractA.withdraw();  // External call
    balances[msg.sender] = 0;  // State update after call
    contractB.deposit{value: balanceB}();  // Another external call
}
```

**Testing Strategy:**
- Unit tests with multiple contract interactions
- Integration tests with complex DeFi protocols
- Foundry PoCs demonstrating cross-contract reentrancy

### 9. Token Standard Compliance - HIGH

Ensures tokens strictly follow ERC standards (ERC20, ERC721, ERC1155):
- **Missing Required Functions** - Functions required by standard not implemented
- **Missing Events** - Transfer, Approval events not emitted
- **Incorrect Signatures** - Function signatures don't match standard
- **Non-Standard Return Values** - Missing bool return values

**Example Vulnerable Code:**
```solidity
// ERC20 missing Transfer event
function transfer(address to, uint256 amount) public returns (bool) {
    balances[msg.sender] -= amount;
    balances[to] += amount;
    // Missing: emit Transfer(msg.sender, to, amount);
    return true;
}
```

**Testing Strategy:**
- Unit tests against ERC20/721/1155 standard specifications
- Integration tests with DEXs and wallets
- Compliance verification against OpenZeppelin implementations

### 10. TOCTOU (Time-of-Check to Time-of-Use) - HIGH

Detects race conditions where contract state changes between check and use:
- **Balance Check Before Transfer** - Balance checked, then external call, then transfer
- **Allowance Check Before Transfer** - Allowance checked, then external call, then transferFrom
- **State Check Before Use** - State variable checked, then external call, then used

**Example Vulnerable Code:**
```solidity
function withdraw() public {
    uint256 balance = balances[msg.sender];  // Check
    (bool success, ) = msg.sender.call{value: balance}("");  // External call
    balances[msg.sender] = 0;  // Use (state update after call)
}
```

**Testing Strategy:**
- Unit tests with check-use patterns
- Integration tests with callback patterns
- Foundry PoCs demonstrating TOCTOU exploits

## Output Formats

### JSON (for tool integration)

```bash
web3crit scan contracts/ --format json --output results.json
```

```json
{
  "findings": [
    {
      "detector": "Reentrancy Vulnerability (Enhanced)",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "exploitable": true,
      "title": "Classic Reentrancy Vulnerability",
      "description": "Function 'withdraw' performs external call before updating state...",
      "location": "Contract: MyContract, Function: withdraw",
      "fileName": "contracts/MyContract.sol",
      "line": 42,
      "column": 4,
      "code": "function withdraw() public { ... }",
      "recommendation": "Move state updates before external calls...",
      "references": [...]
    }
  ],
  "stats": {
    "filesScanned": 5,
    "totalFindings": 12,
    "critical": 3,
    "high": 5,
    "medium": 2,
    "low": 2,
    "exploitable": 6
  },
  "analysis": {
    "engine": "enhanced",
    "version": "4.0.0",
    "features": [
      "Control Flow Analysis",
      "Data Flow Analysis",
      "Cross-Function Reentrancy Detection",
      "Modifier Logic Validation",
      "Exploitability Verification"
    ]
  }
}
```

### Markdown (for reports)

```bash
web3crit scan contracts/ --format markdown --output audit-report.md
```

### Table (CLI output)

```bash
web3crit scan contracts/
```

## Architecture

```
Web3CRIT-Scanner/
├── src/
│   ├── analyzers/
│   │   ├── control-flow.js       # Control flow graph builder
│   │   └── data-flow.js          # Data flow and taint analysis
│   ├── detectors/
│   │   ├── reentrancy-enhanced.js
│   │   ├── access-control-enhanced.js
│   │   ├── unchecked-call.js
│   │   ├── delegatecall.js
│   │   └── selfdestruct.js
│   ├── scanner-enhanced.js       # Main scanner with CFG/dataflow
│   └── cli.js                    # CLI interface
├── bin/
│   └── web3crit                  # Global executable
├── package.json
├── INSTALL.md
└── README.md
```

## How It Works

### Control Flow Graph (CFG) Analysis

The scanner builds a complete control flow graph of your contracts:
1. Maps all functions, modifiers, and state variables
2. Tracks function call relationships (call graph)
3. Identifies external calls and their locations
4. Maps state variable reads and writes

### Data Flow Analysis

Performs taint tracking to identify exploitable data flows:
1. Identifies taint sources (user inputs, function parameters)
2. Propagates taint through assignments and calls
3. Checks if tainted data reaches dangerous operations
4. Verifies if protections (access control) are in place

### Enhanced Detection

Unlike pattern-matching tools, Web3CRIT validates:
- **Exploitability** - Is the vulnerability actually exploitable?
- **Access Control** - Does the modifier logic actually work?
- **Protection** - Are reentrancy guards effective?
- **Reachability** - Can users actually trigger the vulnerable path?

## Comparison to v3.0.0

| Aspect | v3.0.0 (Pattern Matching) | v4.0.0 (Logic Analysis) |
|--------|---------------------------|-------------------------|
| Detectors | 23 pattern-based | 5 logic-based |
| False Positives | High | Low |
| Reentrancy | Basic pattern only | Classic + cross-function + read-only |
| Access Control | Checks if modifier exists | Validates modifier logic |
| Modifier Analysis | Name only | Analyzes require statements |
| Exploitability | Assumed | Verified |
| Cross-Function | Not detected | Fully detected |
| Multi-Contract | No | Yes |

## Use Cases

### Development Workflow

```bash
# During development
web3crit scan contracts/

# Before committing
web3crit scan contracts/ --severity critical

# Pre-audit cleanup
web3crit scan contracts/ --format json --output pre-audit.json
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    npm install -g web3crit-scanner
    web3crit scan contracts/ --severity high
```

### Audit Preparation

```bash
# Generate comprehensive report
web3crit scan contracts/ --format markdown --output security-audit.md

# Compare with other tools
slither contracts/ --json slither.json
mythril analyze contracts/Token.sol -o mythril.json
web3crit scan contracts/ --format json --output web3crit.json
```

## Limitations

Web3CRIT Scanner provides advanced static analysis but has limitations:

- **No Symbolic Execution** - Cannot prove all execution paths (use Mythril for this)
- **Single-File Analysis** - Limited cross-contract dependency tracking
- **No Formal Verification** - Cannot prove mathematical properties (use Certora for this)
- **Heuristic-Based** - Some edge cases may be missed

### Recommended Multi-Tool Approach

For high-value contracts (>$1M TVL), use multiple tools:

1. **Web3CRIT** - Logic-based analysis with low false positives
2. **Slither** - Comprehensive pattern detection (90+ detectors)
3. **Mythril** - Symbolic execution for exploit proofs
4. **Manticore/Echidna** - Dynamic analysis and fuzzing
5. **Professional Audit** - Human expert review
6. **Formal Verification** - Mathematical proofs (Certora, K Framework)

## Requirements

- Node.js >= 14.0.0
- npm >= 6.0.0

## Command Line Options

```
Usage: web3crit scan <file|directory> [options]

Options:
  -s, --severity <level>   Minimum severity (critical|high|medium|low|info|all) (default: "all")
  -o, --output <file>      Save report to file
  -f, --format <format>    Output format (table|json|markdown|text) (default: "table")
  -v, --verbose            Verbose output
  --exploit-driven         Enable exploit-driven analysis (attach exploit chains + Immunefi classification)
  --immunefi-only          Strict Immunefi mode (only keep High/Critical payout-eligible findings)
  --poc-validate           Validate attached Foundry PoCs (drop findings whose PoCs fail validation)
  --poc-require-pass       Require PoCs to compile+pass under forge (requires foundry.toml + forge installed)
  --poc-mode <mode>        PoC validation mode: test|build (default: test)
  --foundry-root <path>    Path to Foundry project root (directory containing foundry.toml)
  --poc-keep-temp          Keep temporary test files written during PoC validation
  --no-banner              Disable banner
  -h, --help               Display help
```

## Foundry PoC Validation (Important)

The scanner repo is **not** a Foundry project. `--poc-require-pass` is intended to be run **inside the target protocol repo** (or with `--foundry-root`) so PoCs can be compiled and executed via `forge test`.

## Examples

### Example 1: Quick Scan

```bash
web3crit scan MyContract.sol
```

### Example 2: Multi-Contract with JSON

```bash
web3crit scan ./contracts --format json --output scan-results.json
```

### Example 3: Critical Issues Only

```bash
web3crit scan ./contracts --severity critical
```

### Example 4: Integration with Slither

```bash
slither contracts/ && web3crit scan contracts/
```

## Contributing

Contributions are welcome! Please:
1. Add tests for new detectors
2. Follow existing code patterns
3. Update documentation
4. Include references to vulnerability resources

## Security Researchers

If you find vulnerabilities in this tool or have suggestions for new detectors, please open an issue or submit a pull request.

## Testing Strategy

### Unit Tests

Each detector includes comprehensive unit tests:
- **Vulnerable Contracts**: Test contracts demonstrating each vulnerability pattern
- **Secure Contracts**: Test contracts with proper mitigations (should produce minimal findings)
- **Edge Cases**: Boundary conditions and complex scenarios

Run tests:
```bash
npm test
```

### Integration Tests

Integration tests verify detectors work together:
- Multi-contract scanning
- Complex protocol interactions
- Real-world contract patterns

### Foundry PoCs

High-confidence findings (confidence: HIGH, exploitability score ≥ 70) automatically generate Foundry PoC templates:

```bash
web3crit scan contracts/ --format json --output results.json
# PoCs included in findings with foundryPoC field
```

Generate complete Foundry test file:
```javascript
const scanner = new Web3CRITScanner();
await scanner.scanDirectory('contracts/');
const testFile = scanner.generateFoundryTestFile('VulnerabilityExploits');
// Save to test/VulnerabilityExploits.t.sol
```

### Testing Priority for High-Value TVL Contracts

For contracts with >$1M TVL, recommended testing order:

1. **Proxy Vulnerabilities** (CRITICAL) - Test first for upgradeable contracts
2. **Cross-Contract Reentrancy** (CRITICAL) - Test for multi-contract protocols
3. **Signature Replay** (HIGH) - Test for meta-transaction/permit patterns
4. **Token Standard Compliance** (HIGH) - Test for token contracts
5. **TOCTOU** (HIGH) - Test for complex state management

## Version History

### v5.2.0 - High-Value TVL Detectors (Current)

- **NEW**: Proxy Contract Vulnerabilities detector (UUPS, Transparent Proxies)
- **NEW**: Signature Replay detector for meta-transactions
- **NEW**: Cross-Contract Reentrancy detector
- **NEW**: Token Standard Compliance detector (ERC20/721/1155)
- **NEW**: TOCTOU (Time-of-Check to Time-of-Use) detector
- Enhanced Foundry PoC generation for high-confidence findings
- Comprehensive test suite with vulnerable contract examples
- Improved exploitability scoring (0-100)

### v4.0.0 - Enhanced Analysis Engine

- Control flow graph (CFG) builder
- Data flow and taint analysis
- Enhanced reentrancy detector (classic + cross-function + read-only)
- Enhanced access control detector (validates modifier logic)
- Exploitability verification
- Multi-contract directory scanning
- Reduced false positives
- npm installable globally

### v3.0.0 - Production Patterns

- 23 pattern-matching detectors
- Flash loan detection
- Signature replay detection
- High false positive rate

### v1.0.0 - Initial Release

- 10 basic pattern-matching detectors
- AST-based analysis

## License

MIT

## References

- [Smart Contract Weakness Classification (SWC)](https://swcregistry.io/)
- [ConsenSys Smart Contract Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Security](https://docs.openzeppelin.com/contracts/4.x/api/security)
- [Slither Documentation](https://github.com/crytic/slither)
- [Trail of Bits Resources](https://github.com/crytic)
