// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AccessControlVulnerable
 * @notice This contract demonstrates CRITICAL access control vulnerabilities
 * @dev INTENTIONALLY VULNERABLE - For testing Web3CRIT Scanner
 */
contract AccessControlVulnerable {
    address public owner;
    uint256 public contractBalance;
    mapping(address => bool) public admins;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABILITY: Missing access control
     * @dev Anyone can change the owner!
     */
    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    /**
     * @notice VULNERABILITY: Broken modifier (always true)
     * @dev The modifier exists but doesn't actually protect anything
     */
    modifier onlyOwner() {
        require(true);  // Always passes!
        _;
    }

    function withdrawAll() public onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }

    /**
     * @notice VULNERABILITY: tx.origin instead of msg.sender
     * @dev Vulnerable to phishing attacks
     */
    modifier onlyOwnerTxOrigin() {
        require(tx.origin == owner, "Not owner");
        _;
    }

    function dangerousTxOrigin() public onlyOwnerTxOrigin {
        payable(msg.sender).transfer(address(this).balance);
    }

    /**
     * @notice VULNERABILITY: Weak access control (balance-based)
     * @dev Anyone with enough ETH can call this
     */
    modifier hasBalance() {
        require(msg.sender.balance > 1 ether, "Need balance");
        _;
    }

    function balanceBasedAccess() public hasBalance {
        admins[msg.sender] = true;
    }

    /**
     * @notice VULNERABILITY: Timestamp-based access control
     * @dev Miners can manipulate block.timestamp
     */
    modifier afterDeadline() {
        require(block.timestamp > 1700000000, "Too early");
        _;
    }

    function timeBasedAccess() public afterDeadline {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABILITY: Empty modifier
     * @dev Modifier doesn't do anything
     */
    modifier checkSomething() {
        // Empty modifier body
        _;
    }

    function protectedByNothing() public checkSomething {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABILITY: Missing access control on critical function
     * @dev Anyone can add themselves as admin
     */
    function addAdmin(address admin) public {
        admins[admin] = true;
    }

    /**
     * @notice VULNERABILITY: Public function that should be internal/private
     * @dev Allows anyone to reset critical state
     */
    function resetState() public {
        contractBalance = 0;
        owner = address(0);
    }

    receive() external payable {
        contractBalance += msg.value;
    }
}

/**
 * @title PhishingAttacker
 * @notice Demonstrates tx.origin attack
 */
contract PhishingAttacker {
    AccessControlVulnerable public victim;

    constructor(address _victim) {
        victim = AccessControlVulnerable(payable(_victim));
    }

    function attack() public {
        // If the owner calls this, tx.origin will be the owner
        // but msg.sender will be this contract
        victim.dangerousTxOrigin();
    }

    receive() external payable {}
}
