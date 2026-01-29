# Web3CRIT Scanner - Installation & Usage

## Quick Install (Recommended)

### From npm Registry (When Published)

```bash
# Install globally
npm install -g web3crit-scanner

# Or using npx (no installation needed)
npx web3crit-scanner scan contract.sol
```

### From Source (Current Method)

```bash
# Clone or navigate to the directory
cd Web3CRIT-Scanner

# Install globally from current directory
npm install -g .

# Verify installation
web3crit --version
which web3crit
```

### Local Installation (Development)

```bash
# Install dependencies only
npm install

# Run without global installation
node src/cli.js scan contract.sol
```

## Usage

### Single Contract Scanning

```bash
# Scan a single file
web3crit scan MyContract.sol

# Scan with JSON output
web3crit scan MyContract.sol --format json

# Only show critical issues
web3crit scan MyContract.sol --severity critical

# Save results to file
web3crit scan MyContract.sol --output report.json --format json

# Exploit-driven (attach exploit chains + Immunefi classification)
web3crit scan MyContract.sol --exploit-driven

# Strict Immunefi payout-eligible findings only
web3crit scan MyContract.sol --immunefi-only
```

### Multi-Contract Scanning

Web3CRIT can scan entire directories of contracts at once.

```bash
# Scan ALL contracts in a directory
web3crit scan contracts/

# Scan all contracts, JSON output
web3crit scan ./contracts --format json --output results.json

# Scan all contracts, only show high/critical
web3crit scan ./src --severity high

# Scan and create markdown report
web3crit scan ./contracts --format markdown --output audit-report.md

# Strict Immunefi mode (High/Critical payout-eligible only)
web3crit scan ./contracts --immunefi-only
```

## Foundry PoC Validation (Optional but Recommended for High-Value Targets)

To drop High/Critical findings unless their attached Foundry PoCs pass under `forge`, run inside a Foundry project:

```bash
web3crit scan . --immunefi-only --poc-validate --poc-require-pass --foundry-root .
```

Notes:
- Requires Foundry (`forge`) installed and a `foundry.toml` at `--foundry-root`.
- The scanner repo itself is not a Foundry project; this gate is intended for target protocol repos.

**Example with multiple contracts:**
```bash
# Your project structure
contracts/
├── Token.sol
├── DEX.sol
├── Vault.sol
└── Governance.sol

# Scan everything at once
web3crit scan contracts/ --format json

# Output shows findings from ALL 4 contracts
# Stats will show: filesScanned: 4, totalFindings: X
```

### Integration with Other Tools

```bash
# Use alongside Slither
slither contract.sol
web3crit scan contract.sol --format json

# Chain multiple tools
slither contract.sol && mythril analyze contract.sol && web3crit scan contract.sol

# Compare outputs
web3crit scan contract.sol --format json > web3crit-results.json
slither contract.sol --json - > slither-results.json
```

### Output Formats

```bash
# Table (default) - Pretty CLI output
web3crit scan contract.sol

# JSON - For tool integration
web3crit scan contract.sol --format json

# Markdown - For reports
web3crit scan contract.sol --format markdown --output audit-report.md

# Text - Plain text
web3crit scan contract.sol --format text
```

### Advanced Options

```bash
# Verbose mode
web3crit scan contract.sol --verbose

# No banner
web3crit scan contract.sol --no-banner

# Save to file
web3crit scan contracts/ --output full-audit.json --format json

# Filter by severity
web3crit scan contracts/ --severity critical --format json
```

## Scanner Features

### Enhanced Analysis (v4.0.0)

- **Control Flow Analysis**: Tracks execution paths across functions
- **Data Flow Analysis**: Traces tainted data from inputs to dangerous operations
- **Modifier Logic Validation**: Checks what access control actually does, not just that it exists
- **Cross-Function Reentrancy**: Detects reentrancy across multiple functions
- **Exploitability Verification**: Only reports realistically exploitable issues

### Detectors

1. **Reentrancy (Enhanced)** - Classic, cross-function, and read-only reentrancy
2. **Access Control (Enhanced)** - Validates modifier logic, detects broken/weak patterns
3. **Unchecked External Calls** - Missing return value checks
4. **Dangerous Delegatecall** - User-controlled delegatecall targets
5. **Unprotected Selfdestruct** - Contract destruction without access control

## Complete Workflow Example

### Step-by-Step: Auditing a DeFi Project

```bash
# 1. Install Web3CRIT globally
npm install -g .

# 2. Verify installation
web3crit --version
# Output: 4.0.0

# 3. Scan entire project (multiple contracts)
web3crit scan contracts/

# 4. Get JSON output for all contracts
web3crit scan contracts/ --format json --output web3crit-results.json

# 5. Check critical issues only
web3crit scan contracts/ --severity critical

# 6. Use alongside other tools
slither contracts/ --json slither-results.json
web3crit scan contracts/ --format json --output web3crit-results.json
mythril analyze contracts/Token.sol -o mythril-results.json

### Quick Multi-Contract Example

```bash
# Scan 10 contracts at once
web3crit scan ./contracts --format json

# Expected output:
# Scan completed! Found 45 issues (12 CRITICAL) in 8.2s
# {
#   "findings": [...],
#   "stats": {
#     "filesScanned": 10,
#     "totalFindings": 45,
#     "critical": 12,
#     "high": 18,
#     ...
#   }
# }
```

## JSON Output Format

```json
{
  "findings": [
    {
      "detector": "Reentrancy Vulnerability (Enhanced)",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "exploitable": true,
      "title": "Classic Reentrancy Vulnerability",
      "description": "Detailed description...",
      "location": "Contract: MyContract, Function: withdraw",
      "fileName": "contracts/MyContract.sol",
      "line": 42,
      "column": 4,
      "code": "function withdraw() public { ... }",
      "recommendation": "Fix recommendation...",
      "references": [
        "https://consensys.github.io/smart-contract-best-practices/"
      ]
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

## Installation Methods Summary

| Method | Command | Use Case |
|--------|---------|----------|
| **Global (from npm)** | `npm install -g web3crit-scanner` | Production use (when published) |
| **Global (from source)** | `npm install -g .` | Current installation method |
| **npx (no install)** | `npx web3crit-scanner scan file.sol` | One-time usage |
| **Local** | `npm install` then `node src/cli.js scan` | Development |

## Requirements

- **Node.js** >= 14.0.0
- **npm** >= 6.0.0

## Uninstallation

```bash
# If installed globally via npm
npm uninstall -g web3crit-scanner

# If installed from source directory
npm uninstall -g .

# Or manually remove
rm -f $(which web3crit)
```

## Troubleshooting

### "web3crit: command not found"

```bash
# Make sure you installed globally
npm install -g .

# Check npm global bin path
npm bin -g

# Add to PATH if needed
export PATH="$(npm bin -g):$PATH"
```

### "Cannot find module"

```bash
# Reinstall dependencies
npm install
```

### Permission Errors

```bash
# On Linux/Mac, you might need sudo
sudo npm install -g .

# Or fix npm permissions
npm config set prefix ~/.npm-global
export PATH=~/.npm-global/bin:$PATH
```

## License

MIT
