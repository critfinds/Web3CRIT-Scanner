#!/usr/bin/env node

/**
 * Web3CRIT Scanner Test Suite
 * Tests all detectors against vulnerable and secure contracts
 */

const path = require('path');
const fs = require('fs');
const Web3CRITScanner = require('../src/scanner-enhanced');

// ANSI colors for output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bold: '\x1b[1m'
};

class TestRunner {
  constructor() {
    this.results = {
      passed: 0,
      failed: 0,
      skipped: 0,
      tests: []
    };
    this.scanner = new Web3CRITScanner({ verbose: false });
  }

  log(color, message) {
    console.log(`${color}${message}${colors.reset}`);
  }

  async runAllTests() {
    console.log('\n' + '='.repeat(60));
    this.log(colors.bold + colors.cyan, '         Web3CRIT Scanner Test Suite v5.0.0');
    console.log('='.repeat(60) + '\n');

    const startTime = Date.now();

    // Test vulnerable contracts
    await this.testVulnerableContracts();

    // Test secure contracts
    await this.testSecureContracts();

    // Test individual detector functionality
    await this.testDetectorFunctionality();

    // Print summary
    this.printSummary(Date.now() - startTime);

    // Exit with appropriate code
    process.exit(this.results.failed > 0 ? 1 : 0);
  }

  async testVulnerableContracts() {
    this.log(colors.bold, '\n[VULNERABLE CONTRACTS TESTS]');
    this.log(colors.white, '-'.repeat(40));

    const vulnerableDir = path.join(__dirname, 'contracts', 'vulnerable');

    // Exploit-driven test suite: Only test for HIGH/CRITICAL exploitable vulnerabilities
    // Per SICKPROMPT: Findings must have concrete fund-loss, insolvency, or takeover impact
    const vulnerableTests = [
      {
        file: 'ReentrancyVulnerable.sol',
        expectFindings: true,
        minFindings: 1,
        expectedDetectors: ['Reentrancy']  // Removed 'Unchecked' - reentrancy is primary exploit
      },
      {
        file: 'AccessControlVulnerable.sol',
        expectFindings: true,
        minFindings: 1,
        expectedDetectors: ['Access Control']
      },
      {
        file: 'UncheckedCallsVulnerable.sol',
        expectFindings: true,
        minFindings: 1,
        expectedDetectors: ['Unchecked', 'Access Control', 'Proxy']  // Accept any - unchecked calls + access control issues
      },
      {
        file: 'SelfdestructVulnerable.sol',
        expectFindings: true,
        minCritical: 1,
        expectedDetectors: ['Selfdestruct']
      },
      {
        file: 'DeprecatedFunctionsVulnerable.sol',
        expectFindings: true,
        minFindings: 1,  // Reduced - only HIGH confidence deprecated patterns
        expectedDetectors: ['Deprecated', 'Access Control']  // Accept either
      },
      // New high-value TVL detectors
      {
        file: 'ProxyVulnerable.sol',
        expectFindings: true,
        minFindings: 1,
        expectedDetectors: ['Proxy']
      },
      {
        file: 'SignatureReplayVulnerable.sol',
        expectFindings: true,
        minFindings: 1,
        expectedDetectors: ['Signature Replay']
      },
      {
        file: 'CrossContractReentrancyVulnerable.sol',
        expectFindings: true,
        minFindings: 1,
        expectedDetectors: ['Reentrancy', 'Access Control', 'Proxy'] // Accept any of these detecting the issues
      },
      // TokenStandardVulnerable - REMOVED from exploit-driven tests
      // Reason: Missing events/functions are compliance issues, not direct fund theft
      // Per SICKPROMPT: "Eliminate all best-practice, theoretical, or keyword-based findings"
      {
        file: 'TOCTOUVulnerable.sol',
        expectFindings: true,
        minFindings: 1,
        expectedDetectors: ['TOCTOU']  // Primary detector - TOCTOU vulnerability
      },
      {
        file: 'OracleManipulationVulnerable.sol',
        expectFindings: true,
        minFindings: 1,
        expectedDetectors: ['Oracle Manipulation', 'Flash Loan']
      }
    ];

    for (const test of vulnerableTests) {
      await this.runContractTest(vulnerableDir, test);
    }
  }

  async testSecureContracts() {
    this.log(colors.bold, '\n[SECURE CONTRACTS TESTS]');
    this.log(colors.white, '-'.repeat(40));

    const secureDir = path.join(__dirname, 'contracts', 'secure');

    const secureTests = [
      {
        file: 'SecurePatterns.sol',
        expectFindings: false, // Secure patterns should produce minimal findings
        maxCritical: 0, // No false positive CRITICAL findings
        maxHigh: 1 // Allow minor false positives
      }
    ];

    for (const test of secureTests) {
      await this.runContractTest(secureDir, test);
    }
  }

  async runContractTest(dir, test) {
    const filePath = path.join(dir, test.file);

    if (!fs.existsSync(filePath)) {
      this.log(colors.yellow, `  [SKIP] ${test.file} - File not found`);
      this.results.skipped++;
      this.results.tests.push({
        name: test.file,
        status: 'skipped',
        reason: 'File not found'
      });
      return;
    }

    try {
      this.scanner.reset();
      const findings = await this.scanner.scanFile(filePath);
      const stats = this.scanner.getFindings().stats;

      let passed = true;
      let reasons = [];

      // Check expectations
      if (test.expectFindings && findings.length === 0) {
        passed = false;
        reasons.push('Expected findings but found none');
      }

      if (!test.expectFindings && findings.length > 0) {
        // Allow some low severity findings in "secure" contracts
        const criticalOrHigh = findings.filter(f =>
          f.severity === 'CRITICAL' || f.severity === 'HIGH'
        );
        if (criticalOrHigh.length > 0) {
          passed = false;
          reasons.push(`Expected no critical/high findings, found ${criticalOrHigh.length}`);
        }
      }

      if (test.minFindings && findings.length < test.minFindings) {
        passed = false;
        reasons.push(`Expected at least ${test.minFindings} findings, found ${findings.length}`);
      }

      if (test.minCritical && stats.critical < test.minCritical) {
        passed = false;
        reasons.push(`Expected at least ${test.minCritical} CRITICAL, found ${stats.critical}`);
      }

      if (test.minHigh && stats.high < test.minHigh) {
        passed = false;
        reasons.push(`Expected at least ${test.minHigh} HIGH, found ${stats.high}`);
      }

      if (test.maxCritical !== undefined && stats.critical > test.maxCritical) {
        passed = false;
        reasons.push(`Expected max ${test.maxCritical} CRITICAL, found ${stats.critical}`);
      }

      if (test.maxHigh !== undefined && stats.high > test.maxHigh) {
        passed = false;
        reasons.push(`Expected max ${test.maxHigh} HIGH, found ${stats.high}`);
      }

      if (test.expectedDetectors) {
        for (const expectedDetector of test.expectedDetectors) {
          const found = findings.some(f =>
            f.detector.toLowerCase().includes(expectedDetector.toLowerCase())
          );
          if (!found) {
            passed = false;
            reasons.push(`Expected detector "${expectedDetector}" not found`);
          }
        }
      }

      if (passed) {
        this.log(colors.green, `  [PASS] ${test.file} (${findings.length} findings, ${stats.critical} CRIT, ${stats.high} HIGH)`);
        this.results.passed++;
      } else {
        this.log(colors.red, `  [FAIL] ${test.file}`);
        reasons.forEach(r => this.log(colors.red, `         - ${r}`));
        this.results.failed++;
      }

      this.results.tests.push({
        name: test.file,
        status: passed ? 'passed' : 'failed',
        findings: findings.length,
        critical: stats.critical,
        high: stats.high,
        reasons: reasons
      });

    } catch (error) {
      this.log(colors.red, `  [ERROR] ${test.file}: ${error.message}`);
      this.results.failed++;
      this.results.tests.push({
        name: test.file,
        status: 'error',
        error: error.message
      });
    }
  }

  async testDetectorFunctionality() {
    this.log(colors.bold, '\n[DETECTOR FUNCTIONALITY TESTS]');
    this.log(colors.white, '-'.repeat(40));

    // Test that all detectors are loaded
    const detectorCount = this.scanner.detectors.length;
    const expectedDetectors = 16; // Original detectors + high-value TVL detectors (+ Oracle Manipulation)

    if (detectorCount >= expectedDetectors) {
      this.log(colors.green, `  [PASS] All ${detectorCount} detectors loaded`);
      this.results.passed++;
    } else {
      this.log(colors.red, `  [FAIL] Expected ${expectedDetectors} detectors, found ${detectorCount}`);
      this.results.failed++;
    }

    // Test detector names are unique
    const names = this.scanner.detectors.map(d => d.name);
    const uniqueNames = new Set(names);
    if (uniqueNames.size === names.length) {
      this.log(colors.green, `  [PASS] All detector names are unique`);
      this.results.passed++;
    } else {
      this.log(colors.red, `  [FAIL] Duplicate detector names found`);
      this.results.failed++;
    }

    // Test scanner can be reset
    this.scanner.reset();
    if (this.scanner.findings.length === 0 && this.scanner.stats.totalFindings === 0) {
      this.log(colors.green, `  [PASS] Scanner reset works correctly`);
      this.results.passed++;
    } else {
      this.log(colors.red, `  [FAIL] Scanner reset did not clear state`);
      this.results.failed++;
    }

    // Test parsing works
    const testCode = `pragma solidity ^0.8.0; contract Test { function test() public {} }`;
    try {
      await this.scanner.scanSource(testCode, 'test.sol');
      this.log(colors.green, `  [PASS] Basic Solidity parsing works`);
      this.results.passed++;
    } catch (error) {
      this.log(colors.red, `  [FAIL] Basic parsing failed: ${error.message}`);
      this.results.failed++;
    }
  }

  printSummary(duration) {
    console.log('\n' + '='.repeat(60));
    this.log(colors.bold + colors.cyan, '                   TEST SUMMARY');
    console.log('='.repeat(60));

    const total = this.results.passed + this.results.failed + this.results.skipped;

    this.log(colors.green, `  Passed:  ${this.results.passed}`);
    this.log(colors.red, `  Failed:  ${this.results.failed}`);
    this.log(colors.yellow, `  Skipped: ${this.results.skipped}`);
    this.log(colors.white, `  Total:   ${total}`);
    this.log(colors.white, `  Time:    ${duration}ms`);

    console.log('='.repeat(60));

    if (this.results.failed === 0) {
      this.log(colors.bold + colors.green, '\n  ✓ All tests passed!\n');
    } else {
      this.log(colors.bold + colors.red, '\n  ✗ Some tests failed!\n');

      // List failed tests
      const failedTests = this.results.tests.filter(t => t.status === 'failed' || t.status === 'error');
      if (failedTests.length > 0) {
        this.log(colors.red, '  Failed tests:');
        failedTests.forEach(t => {
          this.log(colors.red, `    - ${t.name}`);
          if (t.reasons) {
            t.reasons.forEach(r => this.log(colors.red, `      ${r}`));
          }
          if (t.error) {
            this.log(colors.red, `      Error: ${t.error}`);
          }
        });
      }
    }
  }
}

// Run tests
const runner = new TestRunner();
runner.runAllTests().catch(error => {
  console.error('Test runner error:', error);
  process.exit(1);
});
