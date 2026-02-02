# Web3CRIT-Scanner

<p align="center">
  <img src="web3crit-scanner.logo.png" alt="WEB3CRIT Scanner Logo" width="350">
</p>

**Enhanced smart contract vulnerability scanner with control flow and data flow analysis**

Web3CRIT Scanner is a production-grade static analysis tool for Solidity smart contracts. Version 4.0.0 features advanced logic-based detection using control flow graphs and data flow analysis, moving beyond simple pattern matching to provide accurate, exploitable vulnerability detection.

## Key Features

- **Control Flow Graph Analysis** - Tracks execution paths and function call relationships across contracts
- **Data Flow Analysis** - Traces tainted user inputs to dangerous operations (delegatecall, selfdestruct, etc.)
- **Multi-Contract Scanning** - Scan entire directories of Solidity files at once
- **Enhanced Reentrancy Detection** - Detects classic, cross-function, and read-only reentrancy with exploitability verification
- **Access Control Validation** - Analyzes what modifiers actually do, not just that they exist
- **Exploitability Verification** - Only reports issues that are realistically exploitable
- **npm Installable** - Install globally and use alongside Slither, Mythril, Aderyn, Manticore
- **Multiple Output Formats** - JSON, Markdown, Table, or Plain Text

## Installation

### From Source

```bash
git clone https://github.com/critfinds/Web3CRIT-Scanner
cd Web3CRIT-Scanner
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

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

## Usage

### Single Contract

```bash
# Basic scan
web3crit scan MyContract.sol

# JSON output
web3crit scan MyContract.sol --format json

# Critical issues only
web3crit scan MyContract.sol --severity critical
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

Web3CRIT v4.0.0 includes 5 enhanced detectors with logic-based analysis:

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
  --no-banner              Disable banner
  -h, --help               Display help
```

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

## Version History

### v4.0.0 - Enhanced Analysis Engine (Current)

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
