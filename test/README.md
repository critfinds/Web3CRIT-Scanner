# Web3CRIT Scanner Test Contracts

This directory contains test contracts for validating the Web3CRIT Scanner's vulnerability detection capabilities.

## Directory Structure

```
test/
├── contracts/
│   ├── vulnerable/          # Intentionally vulnerable contracts
│   │   ├── ReentrancyVulnerable.sol
│   │   ├── AccessControlVulnerable.sol
│   │   ├── UncheckedCallsVulnerable.sol
│   │   ├── DelegatecallVulnerable.sol
│   │   ├── OracleManipulationVulnerable.sol
│   │   └── SelfdestructVulnerable.sol
│   └── secure/              # Secure reference implementations
│       └── SecurePatterns.sol
└── README.md
```

## Vulnerable Test Contracts

### 1. ReentrancyVulnerable.sol

**Severity:** CRITICAL

**Vulnerabilities Demonstrated:**
- Classic reentrancy (external call before state update)
- Cross-function reentrancy
- Read-only reentrancy in view functions
- Multiple attack vectors (call, send)

**Key Vulnerable Functions:**
- `withdraw()` - Classic reentrancy pattern
- `withdrawViaSend()` - Reentrancy via send()
- `transfer()` - Cross-function reentrancy target

**Expected Detections:**
- Reentrancy Vulnerability (Enhanced)
- External call before state update
- Missing reentrancy guard

**Test Command:**
```bash
web3crit scan test/contracts/vulnerable/ReentrancyVulnerable.sol
```

**Expected Output:** Multiple CRITICAL findings for reentrancy

---

### 2. AccessControlVulnerable.sol

**Severity:** CRITICAL

**Vulnerabilities Demonstrated:**
- Missing access control on sensitive functions
- Broken modifiers (always-true conditions)
- tx.origin usage (phishing vulnerability)
- Weak access control (balance-based, timestamp-based)
- Empty modifiers

**Key Vulnerable Functions:**
- `setOwner()` - No access control
- `withdrawAll()` - Broken modifier
- `dangerousTxOrigin()` - tx.origin vulnerability
- `balanceBasedAccess()` - Weak balance-based control
- `timeBasedAccess()` - Manipulable timestamp check

**Expected Detections:**
- Access Control Vulnerability (Enhanced)
- Missing access control on critical functions
- Broken modifier logic
- tx.origin usage

**Test Command:**
```bash
web3crit scan test/contracts/vulnerable/AccessControlVulnerable.sol
```

**Expected Output:** Multiple CRITICAL findings for access control

---

### 3. UncheckedCallsVulnerable.sol

**Severity:** HIGH

**Vulnerabilities Demonstrated:**
- Unchecked low-level call()
- Unchecked send()
- Unchecked delegatecall()
- Unchecked external contract calls
- Batch operations without validation

**Key Vulnerable Functions:**
- `unsafeTransfer()` - call() without checking return value
- `unsafeSend()` - send() return value ignored
- `unsafeDelegateCall()` - delegatecall without validation
- `batchTransfer()` - Multiple unchecked sends
- `genericCall()` - Arbitrary unchecked call

**Expected Detections:**
- Unchecked External Call
- Return value not validated
- Silent failure possible

**Test Command:**
```bash
web3crit scan test/contracts/vulnerable/UncheckedCallsVulnerable.sol
```

**Expected Output:** Multiple HIGH findings for unchecked calls

---

### OracleManipulationVulnerable.sol

**Severity:** CRITICAL

**Vulnerabilities Demonstrated:**
- Spot-price oracle usage (`getReserves`) flowing into value-moving logic
- Flash-loan manipulable oracle → refund/amount computation

**Expected Detections:**
- Oracle Manipulation
- Flash Loan Vulnerability (depending on heuristics)

**Test Command:**
```bash
web3crit scan test/contracts/vulnerable/OracleManipulationVulnerable.sol
```

### 4. DelegatecallVulnerable.sol

**Severity:** CRITICAL

**Vulnerabilities Demonstrated:**
- User-controlled delegatecall target
- Storage collision attacks
- Arbitrary code execution
- Proxy pattern vulnerabilities

**Key Vulnerable Functions:**
- `execute()` - User controls target address
- `upgrade()` - Owner-controlled but dangerous
- `callLibrary()` - User-supplied library address
- `proxy()` - Unprotected proxy delegatecall
- `batchExecute()` - Multiple delegatecalls

**Attack Contracts Included:**
- `MaliciousImplementation` - Steals ownership via delegatecall
- `StorageCollisionAttack` - Exploits storage layout
- `DelegatecallAttacker` - Full attack demonstration

**Expected Detections:**
- Dangerous Delegatecall
- User-controlled delegatecall target
- Storage collision risk

**Test Command:**
```bash
web3crit scan test/contracts/vulnerable/DelegatecallVulnerable.sol
```

**Expected Output:** Multiple CRITICAL findings for delegatecall

---

### 5. SelfdestructVulnerable.sol

**Severity:** CRITICAL

**Vulnerabilities Demonstrated:**
- Completely unprotected selfdestruct
- Broken access control on selfdestruct
- tx.origin vulnerability
- Weak time-based access control
- Selfdestruct in fallback function
- Indirect selfdestruct via delegatecall

**Key Vulnerable Functions:**
- `destroy()` - No protection at all
- `destroyWithBrokenModifier()` - Broken modifier
- `destroyWithTxOrigin()` - tx.origin vulnerability
- `timedDestroy()` - Weak timestamp check
- `receive()` - Selfdestruct in fallback

**Attack Contracts Included:**
- `SelfdestructAttacker` - Various attack vectors
- `ForceFeedAttack` - Force-feed ETH demonstration

**Expected Detections:**
- Unprotected Selfdestruct
- Anyone can destroy contract
- All funds can be stolen

**Test Command:**
```bash
web3crit scan test/contracts/vulnerable/SelfdestructVulnerable.sol
```

**Expected Output:** Multiple CRITICAL findings for selfdestruct

---

## Secure Reference Contracts

### SecurePatterns.sol

**Purpose:** Demonstrates secure implementations that should NOT trigger warnings

**Secure Patterns Shown:**
- Checks-Effects-Interactions pattern
- Proper reentrancy guards
- Correct access control modifiers
- Return value validation
- Two-step ownership transfer
- Whitelisted delegatecall
- Pull payment pattern
- Emergency pause mechanism

**Key Secure Functions:**
- `withdraw()` - Proper CEI pattern + reentrancy guard
- `safeTransfer()` - Checked external call
- `transferOwnership()` - Two-step transfer
- `safeDelegate()` - Whitelisted delegatecall only
- `withdrawFunds()` - Pull payment pattern

**Test Command:**
```bash
web3crit scan test/contracts/secure/SecurePatterns.sol
```

**Expected Output:** No critical findings (or very few low-severity informational warnings)

---

## Running Tests

### Scan All Vulnerable Contracts

```bash
# Scan all vulnerable contracts
web3crit scan test/contracts/vulnerable/

# JSON output for automated testing
web3crit scan test/contracts/vulnerable/ --format json --output results.json

# Only show critical issues
web3crit scan test/contracts/vulnerable/ --severity critical
```

### Scan Secure Contracts (Should Be Clean)

```bash
# Verify secure contracts have no critical issues
web3crit scan test/contracts/secure/

# Detailed verification
web3crit scan test/contracts/secure/ --format json
```

### Individual Contract Testing

```bash
# Test specific vulnerability detection
web3crit scan test/contracts/vulnerable/ReentrancyVulnerable.sol --severity critical
web3crit scan test/contracts/vulnerable/AccessControlVulnerable.sol --severity critical
web3crit scan test/contracts/vulnerable/DelegatecallVulnerable.sol --severity critical
```

### Comparison Testing

```bash
# Compare with other tools (if installed)
slither test/contracts/vulnerable/ --json slither-results.json
web3crit scan test/contracts/vulnerable/ --format json --output web3crit-results.json

# View findings comparison
cat web3crit-results.json | jq '.stats'
cat slither-results.json | jq '.results.detectors | length'
```

## Expected Results Summary

| Contract | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| ReentrancyVulnerable.sol | 2-3 | 0-1 | 0 | 0 |
| AccessControlVulnerable.sol | 5-7 | 0-2 | 0-1 | 0 |
| UncheckedCallsVulnerable.sol | 0 | 6-8 | 0 | 0 |
| DelegatecallVulnerable.sol | 4-6 | 0 | 0 | 0 |
| SelfdestructVulnerable.sol | 5-7 | 0 | 0 | 0 |
| **Total Vulnerable** | **16-29** | **6-11** | **0-1** | **0** |
| SecurePatterns.sol | 0 | 0 | 0-1 | 0-2 |

## Validation Checklist

Use this checklist to verify scanner accuracy:

### Reentrancy Detection
- [ ] Detects classic reentrancy (withdraw before balance update)
- [ ] Identifies cross-function reentrancy
- [ ] Recognizes read-only reentrancy
- [ ] Validates reentrancy guard effectiveness

### Access Control
- [ ] Flags missing access control
- [ ] Identifies broken modifiers (always-true)
- [ ] Detects tx.origin usage
- [ ] Warns about weak access patterns

### External Calls
- [ ] Finds unchecked call() return values
- [ ] Identifies unchecked send()
- [ ] Detects unchecked delegatecall()
- [ ] Flags batch operations without validation

### Delegatecall
- [ ] Detects user-controlled delegatecall targets
- [ ] Warns about storage collision risks
- [ ] Identifies unwhitelisted delegatecall

### Selfdestruct
- [ ] Finds completely unprotected selfdestruct
- [ ] Identifies broken access control
- [ ] Detects indirect selfdestruct via delegatecall

### Secure Patterns (Should Pass)
- [ ] No false positives on secure withdraw
- [ ] Accepts proper access control modifiers
- [ ] Recognizes valid reentrancy guards
- [ ] Allows whitelisted delegatecall

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install Web3CRIT Scanner
        run: npm install -g web3crit-scanner

      - name: Scan Test Contracts
        run: |
          web3crit scan test/contracts/vulnerable/ --format json --output scan-results.json

      - name: Verify Results
        run: |
          # Ensure critical vulnerabilities are detected in test contracts
          CRITICAL=$(cat scan-results.json | jq '.stats.critical')
          if [ "$CRITICAL" -lt 10 ]; then
            echo "Error: Expected at least 10 critical findings in test contracts"
            exit 1
          fi

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: scan-results.json
```

## Notes for Developers

1. **DO NOT deploy these contracts** - They are intentionally vulnerable
2. All vulnerable contracts are clearly marked with warnings
3. Use these contracts only for testing scanner accuracy
4. Secure patterns demonstrate best practices for production code
5. Each vulnerability includes exploit contracts for educational purposes

## Adding New Test Contracts

When adding new test contracts:

1. Place vulnerable contracts in `test/contracts/vulnerable/`
2. Place secure implementations in `test/contracts/secure/`
3. Add clear comments explaining the vulnerability
4. Include expected scanner output in this README
5. Update the validation checklist
6. Add CI/CD test cases if needed

## License

MIT - For educational and testing purposes only

## References

- [SWC Registry](https://swcregistry.io/)
- [ConsenSys Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [OpenZeppelin Security](https://docs.openzeppelin.com/contracts/4.x/api/security)
- [Trail of Bits Guides](https://github.com/crytic)
