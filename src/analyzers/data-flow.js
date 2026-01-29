const parser = require('@solidity-parser/parser');

/**
 * Advanced Data Flow Analyzer
 * Implements real taint propagation with source-sink analysis
 * Tracks user-controlled data through complex expressions and assignments
 */
class DataFlowAnalyzer {
  constructor(controlFlowGraph) {
    this.cfg = controlFlowGraph;
    this.taintedVariables = new Map(); // variable -> taint info
    this.taintedExpressions = new Map(); // expression hash -> taint info
    this.dataFlows = [];
    this.stateVariableTaints = new Map(); // state var -> taint info
    this.arithmeticOperations = []; // Track arithmetic for precision loss
    this.valueFlows = []; // Track ETH/token value flows
    this.oracleValueFlows = []; // Track oracle-derived values flowing into value-moving operations
  }

  /**
   * Perform comprehensive taint analysis
   */
  analyze() {
    this.taintedVariables.clear();
    this.taintedExpressions.clear();
    this.dataFlows = [];
    this.stateVariableTaints.clear();
    this.arithmeticOperations = [];
    this.valueFlows = [];
    this.oracleValueFlows = [];

    // Phase 1: Identify all taint sources
    this.identifyTaintSources();

    // Phase 2: Propagate taint through assignments (fixed-point)
    this.propagateTaint();

    // Phase 3: Track arithmetic operations for precision loss
    this.analyzeArithmeticOperations();

    // Phase 4: Track value flows (ETH, tokens)
    this.analyzeValueFlows();

    // Phase 5: Check dangerous sinks
    this.checkDangerousSinks();

    return {
      taintedVariables: this.taintedVariables,
      stateVariableTaints: this.stateVariableTaints,
      dataFlows: this.dataFlows,
      arithmeticOperations: this.arithmeticOperations,
      valueFlows: this.valueFlows,
      oracleValueFlows: this.oracleValueFlows
    };
  }

  /**
   * Identify all sources of tainted (user-controlled) data
   */
  identifyTaintSources() {
    for (const [funcKey, funcInfo] of this.cfg.functions) {
      // Skip internal/private functions for external taint sources
      const isExternallyCallable = funcInfo.visibility === 'public' ||
                                    funcInfo.visibility === 'external' ||
                                    funcInfo.isConstructor;

      if (!isExternallyCallable && !funcInfo.isFallback && !funcInfo.isReceive) {
        continue;
      }

      // Function parameters are tainted (user-controlled)
      funcInfo.parameters.forEach((param, index) => {
        if (param.name) {
          const varKey = `${funcKey}.${param.name}`;
          this.taintedVariables.set(varKey, {
            type: 'parameter',
            source: 'user_input',
            function: funcKey,
            name: param.name,
            paramIndex: index,
            paramType: param.type,
            confidence: 'HIGH',
            exploitability: this.assessParameterExploitability(param.type)
          });
        }
      });

      // Analyze function body for msg.*, tx.*, block.* usage
      if (funcInfo.node && funcInfo.node.body) {
        this.findImplicitTaintSources(funcInfo.node.body, funcKey);
      }
    }
  }

  /**
   * Find implicit taint sources in function body (msg.sender, msg.value, etc.)
   */
  findImplicitTaintSources(node, funcKey) {
    if (!node) return;

    const self = this;

    parser.visit(node, {
      MemberAccess(memberNode) {
        const expr = self.nodeToString(memberNode);

        // msg.* sources
        if (expr.startsWith('msg.')) {
          self.taintedExpressions.set(expr, {
            type: 'msg_property',
            source: expr,
            function: funcKey,
            confidence: 'HIGH',
            exploitability: expr === 'msg.value' ? 'HIGH' : 'MEDIUM'
          });
        }

        // tx.* sources
        if (expr.startsWith('tx.')) {
          self.taintedExpressions.set(expr, {
            type: 'tx_property',
            source: expr,
            function: funcKey,
            confidence: 'HIGH',
            exploitability: expr === 'tx.origin' ? 'HIGH' : 'MEDIUM'
          });
        }

        // block.* sources (manipulable by miners)
        if (expr.startsWith('block.')) {
          const manipulable = ['block.timestamp', 'block.number', 'block.coinbase'];
          if (manipulable.some(m => expr.includes(m))) {
            self.taintedExpressions.set(expr, {
              type: 'block_property',
              source: expr,
              function: funcKey,
              confidence: 'MEDIUM',
              exploitability: 'MEDIUM',
              note: 'Manipulable by miners/validators'
            });
          }
        }
      }
    });
  }

  /**
   * Detect whether a function call expression looks like an oracle read.
   * This is intentionally conservative and used to taint *oracle-derived values*,
   * which can enable oracle->profit/dataflow checks.
   */
  isOracleRead(node) {
    if (!node) return false;
    // Covers common Chainlink, Uniswap, and "median price" style oracles
    const expr = this.nodeToString(node);
    const oraclePatterns = [
      /latestRoundData\s*\(/i,
      /latestAnswer\s*\(/i,
      /\.getReserves\s*\(\s*\)/i,
      /\.slot0\s*\(\s*\)/i,
      /\.observe\s*\(/i,
      /getMedianPrice\s*\(/i,
      /consult\s*\(/i,
      /priceCumulative/i,
      /cumulativePrice/i
    ];
    return oraclePatterns.some(p => p.test(expr));
  }

  /**
   * Propagate taint through assignments using fixed-point iteration
   */
  propagateTaint() {
    let changed = true;
    let iterations = 0;
    const maxIterations = 50;

    while (changed && iterations < maxIterations) {
      changed = false;
      iterations++;

      for (const [funcKey, funcInfo] of this.cfg.functions) {
        if (!funcInfo.node || !funcInfo.node.body) continue;

        // Analyze all assignments in function
        const newTaints = this.analyzeAssignments(funcInfo.node.body, funcKey);

        for (const [varKey, taintInfo] of newTaints) {
          if (!this.taintedVariables.has(varKey)) {
            this.taintedVariables.set(varKey, taintInfo);
            changed = true;
          }
        }

        // Propagate to state variables
        funcInfo.stateWrites.forEach(write => {
          const localTaint = this.findTaintForWrite(write, funcKey);
          if (localTaint) {
            const stateKey = `${funcInfo.contract}.${write.variable}`;
            if (!this.stateVariableTaints.has(stateKey)) {
              this.stateVariableTaints.set(stateKey, {
                ...localTaint,
                stateVariable: write.variable,
                writtenBy: funcKey,
                loc: write.loc
              });
              changed = true;
            }
          }
        });
      }
    }
  }

  /**
   * Analyze assignments to propagate taint
   */
  analyzeAssignments(node, funcKey) {
    const newTaints = new Map();
    const self = this;

    parser.visit(node, {
      BinaryOperation(binNode) {
        if (!['=', '+=', '-=', '*=', '/='].includes(binNode.operator)) return;

        const leftName = self.getAssignmentTarget(binNode.left);
        if (!leftName) return;

        const rightExpr = self.nodeToString(binNode.right);
        const rightTaint = self.isExpressionTainted(binNode.right, funcKey);

        if (rightTaint) {
          const varKey = `${funcKey}.${leftName}`;
          newTaints.set(varKey, {
            type: 'derived',
            source: rightTaint.source,
            derivedFrom: rightExpr,
            function: funcKey,
            name: leftName,
            confidence: rightTaint.confidence,
            exploitability: rightTaint.exploitability
          });
        }
      },

      VariableDeclarationStatement(declNode) {
        if (!declNode.initialValue) return;

        declNode.variables.forEach(variable => {
          if (!variable || !variable.name) return;

          const rightTaint = self.isExpressionTainted(declNode.initialValue, funcKey);
          if (rightTaint) {
            const varKey = `${funcKey}.${variable.name}`;
            newTaints.set(varKey, {
              type: 'derived',
              source: rightTaint.source,
              derivedFrom: self.nodeToString(declNode.initialValue),
              function: funcKey,
              name: variable.name,
              confidence: rightTaint.confidence,
              exploitability: rightTaint.exploitability
            });
          }
        });
      }
    });

    return newTaints;
  }

  /**
   * Check if an expression is tainted
   */
  isExpressionTainted(node, funcKey) {
    if (!node) return null;

    const exprStr = this.nodeToString(node);

    // Oracle read is a taint source (even if no user input involved)
    if (node.type === 'FunctionCall' && this.isOracleRead(node)) {
      return {
        type: 'oracle_read',
        source: exprStr,
        confidence: 'HIGH',
        exploitability: 'HIGH'
      };
    }

    // Direct taint source
    if (this.taintedExpressions.has(exprStr)) {
      return this.taintedExpressions.get(exprStr);
    }

    // Check if it's a tainted variable
    if (node.type === 'Identifier') {
      const varKey = `${funcKey}.${node.name}`;
      if (this.taintedVariables.has(varKey)) {
        return this.taintedVariables.get(varKey);
      }
    }

    // Check for msg.*, tx.*, block.* in expression
    if (exprStr.includes('msg.') || exprStr.includes('tx.') || exprStr.includes('block.timestamp')) {
      return {
        type: 'implicit',
        source: exprStr,
        confidence: 'MEDIUM',
        exploitability: 'MEDIUM'
      };
    }

    // Recursively check sub-expressions
    if (node.type === 'BinaryOperation') {
      const leftTaint = this.isExpressionTainted(node.left, funcKey);
      const rightTaint = this.isExpressionTainted(node.right, funcKey);
      return leftTaint || rightTaint;
    }

    if (node.type === 'FunctionCall' && node.arguments) {
      // Also consider oracle reads on the callee expression (e.g., oracle.latestRoundData())
      if (this.isOracleRead(node)) {
        return {
          type: 'oracle_read',
          source: exprStr,
          confidence: 'HIGH',
          exploitability: 'HIGH'
        };
      }
      for (const arg of node.arguments) {
        const argTaint = this.isExpressionTainted(arg, funcKey);
        if (argTaint) return argTaint;
      }
    }

    if (node.type === 'IndexAccess') {
      const baseTaint = this.isExpressionTainted(node.base, funcKey);
      const indexTaint = this.isExpressionTainted(node.index, funcKey);
      return baseTaint || indexTaint;
    }

    if (node.type === 'MemberAccess') {
      return this.isExpressionTainted(node.expression, funcKey);
    }

    return null;
  }

  /**
   * Analyze arithmetic operations for precision loss vulnerabilities
   */
  analyzeArithmeticOperations() {
    for (const [funcKey, funcInfo] of this.cfg.functions) {
      if (!funcInfo.node || !funcInfo.node.body) continue;

      const self = this;

      parser.visit(funcInfo.node.body, {
        BinaryOperation(node) {
          if (!['+', '-', '*', '/', '%'].includes(node.operator)) return;

          const operation = {
            function: funcKey,
            operator: node.operator,
            left: self.nodeToString(node.left),
            right: self.nodeToString(node.right),
            loc: node.loc,
            issues: []
          };

          // Check for division before multiplication (precision loss)
          if (node.operator === '*') {
            if (self.containsDivision(node.left) || self.containsDivision(node.right)) {
              operation.issues.push({
                type: 'division_before_multiplication',
                severity: 'MEDIUM',
                description: 'Division before multiplication can cause precision loss'
              });
            }
          }

          // Check for division that could truncate to zero
          if (node.operator === '/') {
            const rightVal = self.tryGetConstantValue(node.right);
            if (rightVal && rightVal > 1e18) {
              operation.issues.push({
                type: 'large_divisor',
                severity: 'MEDIUM',
                description: 'Division by large number may truncate to zero'
              });
            }
          }

          // Check for unchecked arithmetic with tainted values
          const leftTaint = self.isExpressionTainted(node.left, funcKey);
          const rightTaint = self.isExpressionTainted(node.right, funcKey);

          if (leftTaint || rightTaint) {
            operation.tainted = true;
            operation.taintSource = (leftTaint || rightTaint).source;
          }

          if (operation.issues.length > 0 || operation.tainted) {
            self.arithmeticOperations.push(operation);
          }
        }
      });
    }
  }

  /**
   * Analyze value flows (ETH and token transfers)
   */
  analyzeValueFlows() {
    for (const [funcKey, funcInfo] of this.cfg.functions) {
      // Check external calls for value transfers
      funcInfo.externalCalls.forEach(call => {
        if (['call', 'transfer', 'send'].includes(call.type)) {
          const flow = {
            function: funcKey,
            type: call.type,
            target: call.target,
            loc: call.loc,
            issues: []
          };

          // Check if target is tainted (user-controlled recipient)
          const targetTaint = this.isExpressionTainted({ type: 'Identifier', name: call.target }, funcKey);
          if (targetTaint || call.target.includes('msg.sender')) {
            flow.targetTainted = true;
            flow.targetTaintSource = targetTaint?.source || 'msg.sender';
          }

          // Check if this is in a loop (gas griefing potential)
          // (would need loop context tracking)

          this.valueFlows.push(flow);
        }
      });

      // Additionally: detect oracle-derived values used as amounts in value-moving calls.
      // This enables oracle manipulation detectors to reduce pure-regex false positives.
      if (!funcInfo.node || !funcInfo.node.body) continue;
      const self = this;

      parser.visit(funcInfo.node.body, {
        FunctionCall(node) {
          // Identify value-moving calls: transfer(to, amount), transferFrom(from,to,amount), mint(to,amount), burn(amount)
          const callee = self.nodeToString(node.expression).toLowerCase();
          if (!callee) return;

          const isValueMoving =
            /transferfrom\s*\(/.test(callee) ||
            /transfer\s*\(/.test(callee) ||
            /mint\s*\(/.test(callee) ||
            /_mint\s*\(/.test(callee) ||
            /burn\s*\(/.test(callee) ||
            /_burn\s*\(/.test(callee);

          if (!isValueMoving) return;

          // Heuristic: last argument is commonly the amount
          const args = node.arguments || [];
          if (args.length === 0) return;
          const amountNode = args[args.length - 1];
          const amountExpr = self.nodeToString(amountNode);
          const amountTaint = self.isExpressionTainted(amountNode, funcKey);

          if (amountTaint && amountTaint.type === 'oracle_read') {
            self.oracleValueFlows.push({
              function: funcKey,
              contract: funcInfo.contract,
              operation: callee,
              amountExpr,
              oracleSource: amountTaint.source,
              loc: node.loc
            });
          }
        }
      });
    }
  }

  /**
   * Check if tainted data reaches dangerous sinks
   */
  checkDangerousSinks() {
    const dangerousSinks = {
      'delegatecall': { severity: 'CRITICAL', description: 'Arbitrary code execution' },
      'selfdestruct': { severity: 'CRITICAL', description: 'Contract destruction' },
      'suicide': { severity: 'CRITICAL', description: 'Contract destruction (deprecated)' },
      'call': { severity: 'HIGH', description: 'External call with potential reentrancy' },
      'staticcall': { severity: 'MEDIUM', description: 'External read call' },
      'send': { severity: 'HIGH', description: 'ETH transfer' }
    };

    for (const [funcKey, funcInfo] of this.cfg.functions) {
      funcInfo.externalCalls.forEach(call => {
        const sinkInfo = dangerousSinks[call.type];
        if (!sinkInfo) return;

        // Check if call target is tainted
        const targetTaint = this.checkCallTargetTaint(call, funcKey);

        if (targetTaint) {
          const exploitable = this.isExploitable(funcKey, call);

          this.dataFlows.push({
            source: targetTaint.source,
            sourceType: targetTaint.type,
            sink: call.type,
            sinkDescription: sinkInfo.description,
            function: funcKey,
            contract: funcInfo.contract,
            location: call.loc,
            severity: sinkInfo.severity,
            confidence: targetTaint.confidence,
            exploitable: exploitable,
            exploitabilityReason: exploitable ?
              'Function is externally callable without effective access control' :
              'Protected by access control or not externally callable',
            taintPath: this.reconstructTaintPath(targetTaint, call, funcKey)
          });
        }
      });
    }
  }

  /**
   * Check if call target is tainted
   */
  checkCallTargetTaint(call, funcKey) {
    // Check if target address is tainted
    if (call.target) {
      // Direct parameter taint
      const varKey = `${funcKey}.${call.target}`;
      if (this.taintedVariables.has(varKey)) {
        return this.taintedVariables.get(varKey);
      }

      // Check for msg.sender (always tainted)
      if (call.target.includes('msg.sender')) {
        return {
          type: 'msg_property',
          source: 'msg.sender',
          confidence: 'HIGH'
        };
      }

      // Check state variable taint
      for (const [stateKey, taint] of this.stateVariableTaints) {
        if (call.target.includes(stateKey.split('.')[1])) {
          return taint;
        }
      }
    }

    return null;
  }

  /**
   * Reconstruct the taint propagation path
   */
  reconstructTaintPath(taint, call, funcKey) {
    const path = [];

    path.push({
      step: 'source',
      description: `Taint originates from ${taint.source}`,
      type: taint.type
    });

    if (taint.derivedFrom) {
      path.push({
        step: 'propagation',
        description: `Derived through: ${taint.derivedFrom}`,
        type: 'assignment'
      });
    }

    path.push({
      step: 'sink',
      description: `Reaches dangerous operation: ${call.type}`,
      location: call.loc
    });

    return path;
  }

  /**
   * Determine if a taint flow is exploitable
   */
  isExploitable(funcKey, call) {
    const funcInfo = this.cfg.functions.get(funcKey);
    if (!funcInfo) return false;

    // Private/internal functions not directly exploitable
    if (funcInfo.visibility === 'private' || funcInfo.visibility === 'internal') {
      return false;
    }

    // Check for effective access control
    if (funcInfo.modifiers.length > 0) {
      for (const modName of funcInfo.modifiers) {
        const modKey = `${funcInfo.contract}.${modName}`;
        const modInfo = this.cfg.modifiers.get(modKey);

        if (modInfo && (modInfo.checksAccess || modInfo.checksOwnership || modInfo.checksRole)) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Assess exploitability based on parameter type
   */
  assessParameterExploitability(paramType) {
    if (!paramType) return 'MEDIUM';

    // Address parameters - high exploitability for target manipulation
    if (paramType.includes('address')) return 'HIGH';

    // Bytes parameters - can contain arbitrary data
    if (paramType.includes('bytes')) return 'HIGH';

    // Integer parameters - potential for overflow/manipulation
    if (paramType.includes('uint') || paramType.includes('int')) return 'MEDIUM';

    return 'MEDIUM';
  }

  // Helper methods

  nodeToString(node) {
    if (!node) return '';

    switch (node.type) {
      case 'Identifier':
        return node.name;
      case 'MemberAccess':
        return `${this.nodeToString(node.expression)}.${node.memberName}`;
      case 'IndexAccess':
        return `${this.nodeToString(node.base)}[${this.nodeToString(node.index)}]`;
      case 'NumberLiteral':
        return node.number;
      case 'BinaryOperation':
        return `${this.nodeToString(node.left)} ${node.operator} ${this.nodeToString(node.right)}`;
      case 'FunctionCall':
        const funcName = this.nodeToString(node.expression);
        const args = (node.arguments || []).map(a => this.nodeToString(a)).join(', ');
        return `${funcName}(${args})`;
      default:
        return `[${node.type}]`;
    }
  }

  getAssignmentTarget(node) {
    if (!node) return null;
    if (node.type === 'Identifier') return node.name;
    if (node.type === 'IndexAccess') return this.nodeToString(node.base);
    if (node.type === 'MemberAccess') return this.nodeToString(node);
    return null;
  }

  findTaintForWrite(write, funcKey) {
    // Check if any tainted variable could flow to this write
    for (const [varKey, taint] of this.taintedVariables) {
      if (varKey.startsWith(funcKey)) {
        return taint;
      }
    }
    return null;
  }

  containsDivision(node) {
    if (!node) return false;
    if (node.type === 'BinaryOperation' && node.operator === '/') return true;
    if (node.type === 'BinaryOperation') {
      return this.containsDivision(node.left) || this.containsDivision(node.right);
    }
    return false;
  }

  tryGetConstantValue(node) {
    if (!node) return null;
    if (node.type === 'NumberLiteral') {
      return parseFloat(node.number);
    }
    return null;
  }

  // Public API methods

  isTainted(varName, funcKey) {
    const varKey = `${funcKey}.${varName}`;
    return this.taintedVariables.has(varKey);
  }

  getTaintInfo(varName, funcKey) {
    const varKey = `${funcKey}.${varName}`;
    return this.taintedVariables.get(varKey);
  }

  getDangerousFlows(funcKey) {
    return this.dataFlows.filter(flow => flow.function === funcKey);
  }

  getExploitableFlows() {
    return this.dataFlows.filter(flow => flow.exploitable);
  }

  getPrecisionLossRisks() {
    return this.arithmeticOperations.filter(op => op.issues.length > 0);
  }
}

module.exports = DataFlowAnalyzer;
