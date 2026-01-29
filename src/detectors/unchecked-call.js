const BaseDetector = require('./base-detector');

class UncheckedCallDetector extends BaseDetector {
  constructor() {
    super(
      'Unchecked External Call',
      'Detects external calls whose return values are not checked',
      'HIGH'
    );
    this.potentialIssues = [];
    this.checkedVariables = new Set();
  }

  async detect(ast, sourceCode, fileName, cfg, dataFlow) {
    this.findings = [];
    this.ast = ast;
    this.sourceCode = sourceCode;
    this.fileName = fileName;
    this.sourceLines = sourceCode.split('\n');
    this.cfg = cfg;
    this.dataFlow = dataFlow;
    this.potentialIssues = [];
    this.checkedVariables = new Set();

    // First pass: collect potential issues and checked variables
    this.traverse(ast);

    // Second pass: filter out false positives
    this.potentialIssues = this.potentialIssues.filter(issue => {
      return !this.checkedVariables.has(issue.variableName);
    });

    // Add remaining issues as findings
    this.potentialIssues.forEach(issue => {
      this.addFinding(issue.finding);
    });

    return this.findings;
  }

  visitFunctionDefinition(node) {
    // Scan entire function for all require/assert/if statements
    if (node.body) {
      this.scanForChecks(node.body);
    }
  }

  scanForChecks(node) {
    if (!node) return;

    // Check for require(success) or assert(success)
    if (node.type === 'ExpressionStatement' && node.expression) {
      const expr = node.expression;
      if (expr.type === 'FunctionCall' && expr.expression) {
        const funcName = expr.expression.name;
        if (funcName === 'require' || funcName === 'assert') {
          // Check first argument
          if (expr.arguments && expr.arguments.length > 0) {
            const arg = expr.arguments[0];
            if (arg.type === 'Identifier') {
              this.checkedVariables.add(arg.name);
            }
            // Handle !variable pattern
            if (arg.type === 'UnaryOperation' && arg.operator === '!' && arg.subExpression && arg.subExpression.type === 'Identifier') {
              this.checkedVariables.add(arg.subExpression.name);
            }
          }
        }
      }
    }

    // Check for if (success) or if (!success)
    if (node.type === 'IfStatement' && node.condition) {
      if (node.condition.type === 'Identifier') {
        this.checkedVariables.add(node.condition.name);
      }
      if (node.condition.type === 'UnaryOperation' && node.condition.operator === '!' && node.condition.subExpression && node.condition.subExpression.type === 'Identifier') {
        this.checkedVariables.add(node.condition.subExpression.name);
      }
      // Recursively check inside if body
      if (node.trueBody) this.scanForChecks(node.trueBody);
      if (node.falseBody) this.scanForChecks(node.falseBody);
    }

    // Recursively check Block statements
    if (node.type === 'Block' && node.statements) {
      node.statements.forEach(stmt => this.scanForChecks(stmt));
    }

    // Check other nested structures
    if (node.statements) {
      node.statements.forEach(stmt => this.scanForChecks(stmt));
    }
  }

  visitExpressionStatement(node) {
    if (!node.expression) return;

    const expr = node.expression;

    // Check for call expressions
    if (expr.type === 'FunctionCall') {
      this.checkFunctionCall(expr, node);
    }
  }

  checkFunctionCall(expr, parentNode) {
    const code = this.getCodeSnippet(expr.loc);

    // Check for low-level calls that should be checked
    if (this.isLowLevelCall(code)) {
      // If this is a standalone statement (not assigned or checked in if)
      // it means the return value is ignored
      if (parentNode.type === 'ExpressionStatement') {
        // Determine severity based on call type
        const isDelegatecall = code.includes('.delegatecall');
        const hasValue = code.includes('{value:') || code.includes('{value :');

        this.addFinding({
          title: 'Unchecked Low-Level Call',
          description: `Low-level call (${isDelegatecall ? 'delegatecall' : hasValue ? 'call with value' : 'call'}) return value is not checked. Failed calls will be silently ignored, potentially causing:\n` +
            `- Fund loss (if sending ETH)\n` +
            `- State inconsistency (balance decremented but transfer failed)\n` +
            `- Silent failures in critical operations`,
          location: this.getLocationString(expr.loc),
          line: expr.loc ? expr.loc.start.line : 0,
          column: expr.loc ? expr.loc.start.column : 0,
          code: code,
          severity: isDelegatecall ? 'CRITICAL' : 'HIGH',
          confidence: 'HIGH',  // Definite unchecked call
          exploitable: true,
          attackVector: 'unchecked-call',
          recommendation: 'Always check the return value of low-level calls. Use require(success, "error message") or implement proper error handling.',
          references: [
            'https://swcregistry.io/docs/SWC-104',
            'https://consensys.github.io/smart-contract-best-practices/development-recommendations/general/external-calls/'
          ]
        });
      }
    }

    // Check for .send() calls
    if (code.includes('.send(')) {
      if (parentNode.type === 'ExpressionStatement') {
        this.addFinding({
          title: 'Unchecked Send Return Value',
          description: 'The .send() function returns false on failure, but the return value is not checked. This causes fund loss - user balance is decremented but ETH transfer fails silently.',
          location: this.getLocationString(expr.loc),
          line: expr.loc ? expr.loc.start.line : 0,
          column: expr.loc ? expr.loc.start.column : 0,
          code: code,
          severity: 'HIGH',
          confidence: 'HIGH',  // Definite unchecked send
          exploitable: true,
          attackVector: 'unchecked-call',
          recommendation: 'Check the return value: require(recipient.send(amount), "Send failed"). Consider using .transfer() which reverts on failure, or .call{value: amount}() with proper checks.',
          references: [
            'https://swcregistry.io/docs/SWC-104'
          ]
        });
      }
    }
  }

  visitVariableDeclarationStatement(node) {
    // Check if a call's return value is assigned but never used
    if (node.variables && node.variables.length > 0) {
      const variable = node.variables[0];

      // Handle null variables (from tuple destruction like "(bool success, ) = ...")
      if (variable && variable.name && node.initialValue) {
        const code = this.getCodeSnippet(node.initialValue.loc);

        if (this.isLowLevelCall(code)) {
          // Check if variable name suggests it should be checked (like 'success')
          if (variable.name.toLowerCase().includes('success')) {
            // Store as potential issue - will be filtered later
            this.potentialIssues.push({
              variableName: variable.name,
              finding: {
                title: 'Low-Level Call Return Value Not Checked',
                description: `Low-level call result assigned to '${variable.name}' but never validated. Failed calls will be silently ignored.`,
                location: this.getLocationString(node.loc),
                line: node.loc ? node.loc.start.line : 0,
                column: node.loc ? node.loc.start.column : 0,
                code: this.getCodeSnippet(node.loc),
                recommendation: 'Add validation: require(success, "Call failed") or if (!success) revert("Call failed")',
                references: [
                  'https://swcregistry.io/docs/SWC-104'
                ]
              }
            });
          }
        }
      }
    }
  }

  isLowLevelCall(code) {
    return code.includes('.call(') ||
           code.includes('.call{') ||
           code.includes('.delegatecall(') ||
           code.includes('.delegatecall{') ||
           code.includes('.staticcall(') ||
           code.includes('.staticcall{');
  }

  getLocationString(loc) {
    if (!loc || !loc.start) return 'Unknown';
    return `Line ${loc.start.line}, Column ${loc.start.column}`;
  }
}

module.exports = UncheckedCallDetector;
