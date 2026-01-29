#!/usr/bin/env node

const { Command } = require('commander');
const chalk = require('chalk');
const ora = require('ora');
const boxen = require('boxen');
const Table = require('cli-table3');
const gradient = require('gradient-string');
const figures = require('figures');
const fs = require('fs').promises;
const path = require('path');
const Web3CRITScanner = require('./scanner-enhanced');
const pkg = require('../package.json');

const program = new Command();

// WEB3CRIT Banner
function displayBanner() {
  const banner = `
 ██╗    ██╗███████╗██████╗ ██████╗  ██████╗██████╗ ██╗████████╗
 ██║    ██║██╔════╝██╔══██╗╚════██╗██╔════╝██╔══██╗██║╚══██╔══╝
 ██║ █╗ ██║█████╗  ██████╔╝ █████╔╝██║     ██████╔╝██║   ██║
 ██║███╗██║██╔══╝  ██╔══██╗ ╚═══██╗██║     ██╔══██╗██║   ██║
 ╚███╔███╔╝███████╗██████╔╝██████╔╝╚██████╗██║  ██║██║   ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝
  `;

  console.log(chalk.red.bold(banner));
  console.log(chalk.gray('  Production-Grade Smart Contract Security Scanner'));
  console.log(chalk.gray(`  Version ${pkg.version} - Exploit-Driven | Immunefi-Aligned | High-TVL Ready\n`));
}

// Severity color mapping
function getSeverityColor(severity) {
  const colors = {
    CRITICAL: chalk.red.bold,
    HIGH: chalk.red,
    MEDIUM: chalk.yellow,
    LOW: chalk.blue,
    INFO: chalk.gray
  };
  return colors[severity] || chalk.white;
}

// Display results in table format
function displayTableResults(results) {
  const { findings, stats } = results;

  // Summary box
  const modeIndicator = stats.productionMode
    ? chalk.magenta.bold('\n[PRODUCTION MODE] PoC-verified findings only')
    : '';

  const pocStats = stats.pocValidated !== undefined
    ? `\nPoC Validated:     ${chalk.green(stats.pocValidated)} | Dropped: ${chalk.red(stats.pocDropped || 0)}`
    : '';

  const soloditStats = stats.soloditEnabled
    ? `\n${chalk.cyan('Solodit Correlation:')}
  Confirmed in Wild: ${chalk.red.bold(stats.soloditConfirmedInWild || 0)}
  Confirmed Pattern: ${chalk.yellow(stats.soloditConfirmedPattern || 0)}
  Theoretical:       ${chalk.gray(stats.soloditTheoretical || 0)}`
    : '';

  const summaryContent = `
${chalk.bold('Scan Summary')}${modeIndicator}
${'─'.repeat(40)}
Files Scanned:     ${chalk.cyan(stats.filesScanned)}
Total Findings:    ${chalk.cyan(stats.totalFindings)}${pocStats}

${chalk.red.bold(figures.cross)} Critical:  ${stats.critical}
${chalk.red(figures.warning)} High:      ${stats.high}
${chalk.yellow(figures.warning)} Medium:    ${stats.medium}
${chalk.blue(figures.info)} Low:       ${stats.low}
${chalk.gray(figures.info)} Info:      ${stats.info}
${soloditStats}
  `;

  console.log(boxen(summaryContent, {
    padding: 1,
    margin: 1,
    borderStyle: 'round',
    borderColor: 'cyan'
  }));

  if (findings.length === 0) {
    console.log(chalk.green.bold('\nNo vulnerabilities found!\n'));
    return;
  }

  // Findings table
  console.log(chalk.bold('\nDetailed Findings:\n'));

  findings.forEach((finding, index) => {
    const severityColor = getSeverityColor(finding.severity);

    // Display confidence level for findings
    const confidenceBadge = finding.confidence ?
      (finding.confidence === 'HIGH' ? chalk.green.bold('[HIGH CONFIDENCE]') :
       finding.confidence === 'MEDIUM' ? chalk.yellow('[MEDIUM]') :
       chalk.gray('[LOW]')) : '';

    // Display proven impact badge for production mode findings
    const impactBadge = finding.provenImpact ?
      chalk.red.bold(` [IMPACT: ${finding.provenImpact.impactType}]`) : '';

    console.log(severityColor(`\n[${finding.severity}] ${finding.title} ${confidenceBadge}${impactBadge}`));
    console.log(chalk.gray(`${figures.arrowRight} ${finding.fileName}:${finding.line}:${finding.column}`));
    console.log(chalk.white(`  ${finding.description}`));

    // Show proven impact evidence if available
    if (finding.provenImpact) {
      console.log(chalk.red(`\n  ${figures.warning} Proven Impact: ${finding.provenImpact.evidence}`));
    }

    // Show Solodit correlation if available
    if (finding.soloditMetadata && finding.soloditMetadata.matched) {
      const sm = finding.soloditMetadata;
      const statusColor = sm.validationStatus?.status === 'confirmed_in_wild' ? chalk.red.bold :
                         sm.validationStatus?.status === 'confirmed_pattern' ? chalk.yellow :
                         chalk.gray;
      const statusLabel = sm.validationStatus?.label || 'Unknown';
      const confidence = Math.round((sm.matchConfidence || 0) * 100);

      console.log(statusColor(`\n  ${figures.star} Solodit: [${statusLabel}] (${confidence}% match)`));

      if (sm.topMatch) {
        console.log(chalk.gray(`    Best Match: "${sm.topMatch.title}" (${sm.topMatch.protocol})`));
        if (sm.topMatch.exploited) {
          console.log(chalk.red(`    ${figures.warning} EXPLOITED in production`));
        }
        if (sm.topMatch.bountyAmount) {
          console.log(chalk.green(`    ${figures.tick} Bounty: $${sm.topMatch.bountyAmount.toLocaleString()}`));
        }
      }

      if (sm.realWorldExploits && sm.realWorldExploits.length > 0) {
        console.log(chalk.red(`    Related Exploits:`));
        sm.realWorldExploits.slice(0, 2).forEach(exp => {
          const loss = exp.lossAmount ? ` ($${exp.lossAmount.toLocaleString()} loss)` : '';
          console.log(chalk.red(`      ${figures.pointer} ${exp.protocol}: ${exp.title}${loss}`));
        });
      }
    } else if (finding.soloditMetadata && !finding.soloditMetadata.matched) {
      console.log(chalk.gray(`\n  ${figures.info} Solodit: [Theoretical] No matching real-world exploits found`));
    }

    if (finding.code) {
      console.log(chalk.gray('\n  Code:'));
      console.log(chalk.dim('  ' + finding.code.split('\n').join('\n  ')));
    }

    console.log(chalk.cyan(`\n  ${figures.pointer} Recommendation:`));
    console.log(chalk.white(`  ${finding.recommendation}`));

    if (finding.references && finding.references.length > 0) {
      console.log(chalk.gray(`\n  References:`));
      finding.references.forEach(ref => {
        console.log(chalk.gray(`  ${figures.arrowRight} ${ref}`));
      });
    }

    console.log(chalk.gray('─'.repeat(80)));
  });
}

// Display results in JSON format
function displayJsonResults(results) {
  console.log(JSON.stringify(results, null, 2));
}

// Save results to file
async function saveResults(results, outputPath, format) {
  try {
    let content;

    if (format === 'json') {
      content = JSON.stringify(results, null, 2);
    } else if (format === 'markdown') {
      content = generateMarkdownReport(results);
    } else {
      content = generateTextReport(results);
    }

    await fs.writeFile(outputPath, content, 'utf8');
    console.log(chalk.green(`\nReport saved to: ${outputPath}\n`));
  } catch (error) {
    console.error(chalk.red(`Error saving report: ${error.message}`));
  }
}

// Generate Markdown report
function generateMarkdownReport(results) {
  const { findings, stats } = results;

  let markdown = '# Web3CRIT Security Scan Report\n\n';
  markdown += `**Scan Date:** ${new Date().toISOString()}\n\n`;

  markdown += '## Summary\n\n';
  markdown += `- **Files Scanned:** ${stats.filesScanned}\n`;
  markdown += `- **Total Findings:** ${stats.totalFindings}\n`;
  markdown += `- **Critical:** ${stats.critical}\n`;
  markdown += `- **High:** ${stats.high}\n`;
  markdown += `- **Medium:** ${stats.medium}\n`;
  markdown += `- **Low:** ${stats.low}\n`;
  markdown += `- **Info:** ${stats.info}\n\n`;

  markdown += '## Findings\n\n';

  findings.forEach((finding, index) => {
    markdown += `### ${index + 1}. [${finding.severity}] ${finding.title}\n\n`;
    markdown += `**File:** ${finding.fileName}:${finding.line}:${finding.column}\n\n`;
    markdown += `**Description:** ${finding.description}\n\n`;

    if (finding.code) {
      markdown += '**Code:**\n```solidity\n' + finding.code + '\n```\n\n';
    }

    markdown += `**Recommendation:** ${finding.recommendation}\n\n`;

    // Solodit correlation
    if (finding.soloditMetadata) {
      const sm = finding.soloditMetadata;
      markdown += '**Solodit Correlation:**\n';
      markdown += `- Status: ${sm.validationStatus?.label || 'Unknown'}\n`;
      markdown += `- Match Confidence: ${Math.round((sm.matchConfidence || 0) * 100)}%\n`;

      if (sm.topMatch) {
        markdown += `- Best Match: "${sm.topMatch.title}" (${sm.topMatch.protocol})\n`;
        if (sm.topMatch.exploited) {
          markdown += `- **EXPLOITED in production**\n`;
        }
        if (sm.topMatch.bountyAmount) {
          markdown += `- Bounty Amount: $${sm.topMatch.bountyAmount.toLocaleString()}\n`;
        }
      }

      if (sm.realWorldExploits && sm.realWorldExploits.length > 0) {
        markdown += '\n**Related Real-World Exploits:**\n';
        sm.realWorldExploits.forEach(exp => {
          const loss = exp.lossAmount ? ` ($${exp.lossAmount.toLocaleString()} loss)` : '';
          markdown += `- ${exp.protocol}: ${exp.title}${loss}\n`;
        });
      }
      markdown += '\n';
    }

    if (finding.references && finding.references.length > 0) {
      markdown += '**References:**\n';
      finding.references.forEach(ref => {
        markdown += `- ${ref}\n`;
      });
      markdown += '\n';
    }

    markdown += '---\n\n';
  });

  return markdown;
}

// Generate text report
function generateTextReport(results) {
  const { findings, stats } = results;

  let text = 'WEB3CRIT SECURITY SCAN REPORT\n';
  text += '='.repeat(80) + '\n\n';
  text += `Scan Date: ${new Date().toISOString()}\n\n`;

  text += 'SUMMARY\n';
  text += '-'.repeat(80) + '\n';
  text += `Files Scanned:  ${stats.filesScanned}\n`;
  text += `Total Findings: ${stats.totalFindings}\n`;
  text += `  Critical: ${stats.critical}\n`;
  text += `  High:     ${stats.high}\n`;
  text += `  Medium:   ${stats.medium}\n`;
  text += `  Low:      ${stats.low}\n`;
  text += `  Info:     ${stats.info}\n\n`;

  text += 'FINDINGS\n';
  text += '='.repeat(80) + '\n\n';

  findings.forEach((finding, index) => {
    text += `${index + 1}. [${finding.severity}] ${finding.title}\n`;
    text += `   File: ${finding.fileName}:${finding.line}:${finding.column}\n\n`;
    text += `   Description:\n   ${finding.description}\n\n`;

    if (finding.code) {
      text += '   Code:\n';
      finding.code.split('\n').forEach(line => {
        text += `   ${line}\n`;
      });
      text += '\n';
    }

    text += `   Recommendation:\n   ${finding.recommendation}\n\n`;

    if (finding.references && finding.references.length > 0) {
      text += '   References:\n';
      finding.references.forEach(ref => {
        text += `   - ${ref}\n`;
      });
      text += '\n';
    }

    text += '-'.repeat(80) + '\n\n';
  });

  return text;
}

// Main scan command
program
  .name('web3crit')
  .description('Production-grade smart contract vulnerability scanner for high-value DeFi protocols')
  .version(pkg.version);

program
  .command('scan')
  .description('Scan Solidity files for vulnerabilities')
  .argument('<path>', 'File or directory to scan')
  .option('-s, --severity <level>', 'Minimum severity level (critical, high, medium, low, info, all)', 'all')
  .option('-o, --output <file>', 'Save report to file')
  .option('-f, --format <format>', 'Output format (table, json, markdown, text)', 'table')
  .option('-v, --verbose', 'Verbose output')
  .option('--exploit-driven', 'Enable exploit-driven analysis (attach exploit chains + Immunefi classification)')
  .option('--immunefi-only', 'Strict Immunefi mode (only keep High/Critical payout-eligible findings)')
  .option('--production', 'PRODUCTION MODE: Gate HIGH/CRITICAL behind PoC execution with proven impact (for $5M+ TVL, Immunefi bounties)')
  .option('--poc-validate', 'Validate attached Foundry PoCs (drop findings whose PoCs fail validation)')
  .option('--poc-require-pass', 'Require PoCs to compile+pass under forge (requires foundry.toml + forge installed)')
  .option('--poc-mode <mode>', 'PoC validation mode: test|build (default: test)', 'test')
  .option('--foundry-root <path>', 'Path to Foundry project root (directory containing foundry.toml)')
  .option('--fork-url <url>', 'RPC URL for fork testing (enables on-chain state verification)')
  .option('--poc-keep-temp', 'Keep temporary test files written during PoC validation')
  .option('--solodit-enrich', 'Enrich findings with Solodit vulnerability database (correlate with real-world exploits)')
  .option('--solodit-api-key <key>', 'Solodit API key (or set SOLODIT_API_KEY env var)')
  .option('--solodit-min-confidence <threshold>', 'Minimum Solodit match confidence (0-1, default: 0.3)', parseFloat)
  .option('--no-banner', 'Disable banner')
  .action(async (targetPath, options) => {
    if (options.banner !== false) {
      displayBanner();
    }

    const spinner = ora({
      text: 'Initializing scanner...',
      spinner: 'dots12'
    }).start();

    const startTime = Date.now();

    try {
      // Progress callback to update spinner
      let detectorCount = 0;

      const onProgress = (progress) => {
        switch (progress.stage) {
          case 'discovery':
            spinner.color = 'cyan';
            spinner.text = chalk.cyan.bold(`${figures.info} ${progress.message}`);
            break;
          case 'file-scan':
            spinner.color = 'cyan';
            spinner.text = chalk.cyan(`${figures.arrowRight} ${progress.message}: ${chalk.white.bold(path.basename(progress.fileName))}`);
            break;
          case 'parsing':
            spinner.color = 'blue';
            spinner.text = chalk.blue(`${figures.play} Parsing Solidity AST... ${chalk.gray('[Building syntax tree]')}`);
            break;
          case 'detecting':
            detectorCount++;
            const progress_percent = Math.round((progress.current / progress.total) * 100);
            const progressBar = '█'.repeat(Math.floor(progress_percent / 5)) + '░'.repeat(20 - Math.floor(progress_percent / 5));

            // Color code by detector type
            let color = chalk.yellow;
            if (progress.detector.includes('Taint') || progress.detector.includes('Reentrancy')) {
              color = chalk.red;
            } else if (progress.detector.includes('Access') || progress.detector.includes('Uninitialized')) {
              color = chalk.magenta;
            }

            spinner.color = 'yellow';
            spinner.text = color(`${figures.pointer} [${progress.current}/${progress.total}] ${progress.detector} ${chalk.gray(progressBar)} ${chalk.white(progress_percent + '%')}`);
            break;
          case 'analyzing':
            spinner.color = 'green';
            spinner.text = chalk.green(`${figures.tick} ${progress.message} ${chalk.gray('[Compiling results]')}`);
            break;
          case 'solodit-enrichment':
            spinner.color = 'cyan';
            spinner.text = chalk.cyan(`${figures.info} ${progress.message} ${chalk.gray('[Solodit API]')}`);
            break;
          default:
            spinner.text = progress.message;
        }
      };

      // Initialize scanner with progress callback
      const scanner = new Web3CRITScanner({
        verbose: options.verbose,
        severity: options.severity,
        outputFormat: options.format,
        exploitDriven: options.exploitDriven || options.immunefiOnly || options.production,
        immunefiOnly: options.immunefiOnly || options.production || false,
        productionMode: options.production || false,
        pocValidate: options.pocValidate || options.production || false,
        pocRequirePass: options.pocRequirePass || options.production || false,
        pocMode: options.pocMode || 'test',
        foundryRoot: options.foundryRoot || null,
        forkUrl: options.forkUrl || null,
        pocKeepTemp: options.pocKeepTemp || false,
        // Solodit integration options
        soloditEnrich: options.soloditEnrich || false,
        soloditApiKey: options.soloditApiKey || null,
        soloditMinConfidence: options.soloditMinConfidence || 0.3,
        onProgress: onProgress
      });

      spinner.text = chalk.cyan('Analyzing target...');

      // Determine if path is file or directory
      const stats = await fs.stat(targetPath);
      let results;

      if (stats.isDirectory()) {
        spinner.text = chalk.cyan(`${figures.info} Scanning directory: ${targetPath}`);
        results = await scanner.scanDirectory(targetPath);
      } else if (stats.isFile()) {
        spinner.text = chalk.cyan(`${figures.info} Scanning file: ${targetPath}`);
        results = await scanner.scanFile(targetPath);
      } else {
        throw new Error('Invalid path: must be a file or directory');
      }

      const scanResults = scanner.getFindings();
      const duration = ((Date.now() - startTime) / 1000).toFixed(2);

      // Success message with summary
      const criticalCount = scanResults.stats.critical;
      const highCount = scanResults.stats.high;
      const totalCount = scanResults.stats.totalFindings;

      let successMsg = chalk.green.bold('Scan completed! ');
      const modeLabel = options.production ? chalk.magenta('[PRODUCTION] ') : '';

      if (criticalCount > 0) {
        successMsg += modeLabel + chalk.red.bold(`Found ${totalCount} issues (${criticalCount} CRITICAL) `) + chalk.gray(`in ${duration}s`);
      } else if (highCount > 0) {
        successMsg += modeLabel + chalk.yellow.bold(`Found ${totalCount} issues (${highCount} HIGH) `) + chalk.gray(`in ${duration}s`);
      } else if (totalCount > 0) {
        successMsg += modeLabel + chalk.blue(`Found ${totalCount} issues `) + chalk.gray(`in ${duration}s`);
      } else {
        successMsg += modeLabel + chalk.green('No vulnerabilities detected! ') + chalk.gray(`in ${duration}s`);
      }

      // In production mode, add PoC validation stats
      if (options.production && scanResults.stats.pocValidated !== undefined) {
        console.log(chalk.gray(`\n  PoC Validation: ${scanResults.stats.pocValidated} validated, ${scanResults.stats.pocDropped || 0} dropped (no proven impact)`));
      }

      spinner.succeed(successMsg);

      // Display results
      if (options.format === 'json') {
        displayJsonResults(scanResults);
      } else {
        displayTableResults(scanResults);
      }

      // Save to file if requested
      if (options.output) {
        const outputFormat = options.format === 'table' ? 'markdown' : options.format;
        await saveResults(scanResults, options.output, outputFormat);
      }

      // Exit with error code if critical/high vulnerabilities found
      if (scanResults.stats.critical > 0 || scanResults.stats.high > 0) {
        process.exit(1);
      }

    } catch (error) {
      spinner.fail('Scan failed!');
      console.error(chalk.red(`\nError: ${error.message}`));
      if (options.verbose) {
        console.error(error.stack);
      }
      process.exit(1);
    }
  });

// Info command
program
  .command('info')
  .description('Display information about available detectors')
  .action(() => {
    displayBanner();

    // Solodit integration info
    console.log(chalk.bold.cyan('Solodit Integration:\n'));
    console.log(chalk.white('  Correlate findings with real-world exploits from the Solodit database.'));
    console.log(chalk.gray('  - Tags findings as "Confirmed in Wild", "Confirmed Pattern", or "Theoretical"'));
    console.log(chalk.gray('  - Shows matching exploits with loss amounts and references'));
    console.log(chalk.gray('  - Works offline with built-in knowledge base of 15+ major exploits'));
    console.log(chalk.gray('  - Online mode with API key for full Solodit database access\n'));
    console.log(chalk.white('  Usage: web3crit scan <path> --solodit-enrich [--solodit-api-key <key>]\n'));

    console.log(chalk.bold('Available Vulnerability Detectors:\n'));

    const detectors = [
      // Critical - Production-grade for multi-million dollar contracts
      { name: 'Flash Loan Attacks', severity: 'CRITICAL', description: 'Detects balance-based logic and price manipulation vulnerabilities' },
      { name: 'Signature Replay Attacks', severity: 'CRITICAL', description: 'Finds missing nonce/chainId in signature verification' },
      { name: 'Reentrancy Vulnerability', severity: 'CRITICAL', description: 'Detects reentrancy attack patterns' },
      { name: 'Taint Analysis', severity: 'CRITICAL', description: 'Tracks user-controlled data flow to dangerous operations' },
      { name: 'Uninitialized Storage Pointers', severity: 'CRITICAL', description: 'Finds uninitialized local storage variables' },
      { name: 'Access Control', severity: 'CRITICAL', description: 'Finds missing access control modifiers' },
      { name: 'Delegatecall Vulnerabilities', severity: 'CRITICAL', description: 'Detects unsafe delegatecall usage' },
      { name: 'Unprotected Selfdestruct', severity: 'CRITICAL', description: 'Finds unprotected contract destruction' },
      { name: 'Price Feed Manipulation', severity: 'CRITICAL', description: 'Detects oracle manipulation risks' },
      // High - Advanced vulnerability detection
      { name: 'Precision Loss', severity: 'HIGH', description: 'Finds division before multiplication and rounding errors' },
      { name: 'Gas Griefing & DoS', severity: 'HIGH', description: 'Detects unbounded loops and denial of service vectors' },
      { name: 'Integer Overflow/Underflow', severity: 'HIGH', description: 'Finds unchecked arithmetic operations' },
      { name: 'Unchecked External Calls', severity: 'HIGH', description: 'Detects unchecked call return values' },
      { name: 'Front-Running', severity: 'HIGH', description: 'Identifies transaction ordering vulnerabilities' },
      { name: 'tx.origin Authentication', severity: 'HIGH', description: 'Detects dangerous use of tx.origin' },
      { name: 'Shadowing', severity: 'HIGH', description: 'Finds shadowed variables and functions in inheritance' },
      { name: 'Logic Bugs', severity: 'HIGH', description: 'Detects common logic errors' },
      // Medium - Code quality and best practices
      { name: 'Timestamp Dependence', severity: 'MEDIUM', description: 'Finds risky timestamp usage' },
      { name: 'Assembly Usage', severity: 'MEDIUM', description: 'Detects inline assembly that bypasses safety checks' },
      { name: 'Inheritance Order', severity: 'MEDIUM', description: 'Checks for incorrect inheritance patterns' },
      // Low/Info - Optimization and maintainability
      { name: 'Missing Events', severity: 'LOW', description: 'Finds state changes without event emissions' },
      { name: 'Dead Code', severity: 'INFO', description: 'Detects unused functions and variables' },
      { name: 'State Mutability', severity: 'INFO', description: 'Finds functions that should be view/pure' }
    ];

    detectors.forEach(detector => {
      const color = getSeverityColor(detector.severity);
      console.log(color(`${figures.pointer} ${detector.name} [${detector.severity}]`));
      console.log(chalk.gray(`  ${detector.description}\n`));
    });
  });

program.parse();
