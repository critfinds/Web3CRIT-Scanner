// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title UncheckedCallsVulnerable
 * @notice This contract demonstrates HIGH severity unchecked external call vulnerabilities
 * @dev INTENTIONALLY VULNERABLE - For testing Web3CRIT Scanner
 */
contract UncheckedCallsVulnerable {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice VULNERABILITY: Unchecked low-level call
     * @dev .call() return value not checked - failure is silently ignored
     */
    function unsafeTransfer(address payable recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;

        // VULNERABILITY: call() return value ignored
        recipient.call{value: amount}("");
    }

    /**
     * @notice VULNERABILITY: Unchecked send()
     * @dev send() can fail silently, return value not checked
     */
    function unsafeSend(address payable recipient, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;

        // VULNERABILITY: send() return value not checked
        recipient.send(amount);
    }

    /**
     * @notice VULNERABILITY: Unchecked delegatecall
     * @dev delegatecall can fail, return value not verified
     */
    function unsafeDelegateCall(address target, bytes memory data) public {
        require(msg.sender == owner, "Only owner");

        // VULNERABILITY: delegatecall return value ignored
        target.delegatecall(data);
    }

    /**
     * @notice VULNERABILITY: Unchecked external contract call
     * @dev Token transfer return value not checked (ERC20)
     */
    function unsafeTokenTransfer(address token, address to, uint256 amount) public {
        // VULNERABILITY: External call without checking success
        // Some tokens return false on failure instead of reverting
        (bool success, ) = token.call(
            abi.encodeWithSignature("transfer(address,uint256)", to, amount)
        );
        // success is declared but never used
    }

    /**
     * @notice VULNERABILITY: Multiple unchecked calls
     * @dev Several external calls without proper error handling
     */
    function batchTransfer(address payable[] memory recipients, uint256[] memory amounts) public {
        require(recipients.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < recipients.length; i++) {
            // VULNERABILITY: Multiple unchecked sends
            recipients[i].send(amounts[i]);
        }
    }

    /**
     * @notice VULNERABILITY: Call with value not checked
     * @dev External call with ETH transfer, return value ignored
     */
    function forwardFunds(address payable target) public payable {
        // VULNERABILITY: Forward call without checking return
        target.call{value: msg.value}("");
    }

    /**
     * @notice VULNERABILITY: Staticcall return value ignored
     * @dev Even read-only calls should verify success
     */
    function uncheckedStaticCall(address target, bytes memory data) public view returns (bytes memory) {
        // VULNERABILITY: staticcall success not checked
        (, bytes memory result) = target.staticcall(data);
        return result;
    }

    /**
     * @notice VULNERABILITY: Call with arbitrary data unchecked
     * @dev Generic call wrapper without return value validation
     */
    function genericCall(address target, bytes memory data) public payable {
        // VULNERABILITY: No check if call succeeded
        target.call{value: msg.value}(data);
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {
        deposit();
    }
}

/**
 * @title MaliciousReceiver
 * @notice Contract that fails to receive funds (for testing)
 */
contract MaliciousReceiver {
    // Rejects all incoming transfers
    receive() external payable {
        revert("I don't accept funds");
    }
}

/**
 * @title FallbackAttacker
 * @notice Contract that exploits unchecked calls
 */
contract FallbackAttacker {
    UncheckedCallsVulnerable public victim;

    constructor(address _victim) {
        victim = UncheckedCallsVulnerable(payable(_victim));
    }

    function exploit() public {
        // Call will fail but victim won't know
        victim.unsafeTransfer(payable(address(this)), 1 ether);
    }

    // No receive function - transfers will fail
}
