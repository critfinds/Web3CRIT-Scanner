// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SecurePatterns
 * @notice This contract demonstrates SECURE patterns that should NOT trigger warnings
 * @dev Reference implementation showing best practices
 */
contract SecurePatterns {
    address public owner;
    mapping(address => uint256) public balances;
    bool private locked;

    event Withdrawal(address indexed user, uint256 amount);
    event Deposit(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice SECURE: Reentrancy guard using mutex
     * @dev State updated before external call + reentrancy guard
     */
    modifier nonReentrant() {
        require(!locked, "Reentrancy detected");
        locked = true;
        _;
        locked = false;
    }

    /**
     * @notice SECURE: Proper access control
     * @dev Uses msg.sender and actually checks ownership
     */
    modifier onlyOwner() {
        require(msg.sender == owner, "Not the owner");
        _;
    }

    /**
     * @notice SECURE: Checks-Effects-Interactions pattern
     * @dev State updated BEFORE external call
     */
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Effects: Update state BEFORE interaction
        balances[msg.sender] -= amount;

        // Interaction: External call happens AFTER state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice SECURE: Proper external call with error handling
     * @dev Return value is checked
     */
    function safeTransfer(address payable recipient, uint256 amount) public onlyOwner {
        require(address(this).balance >= amount, "Insufficient contract balance");

        // SECURE: Check return value
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    /**
     * @notice SECURE: Using transfer() which reverts on failure
     * @dev Automatic error handling
     */
    function safeTransferBuiltin(address payable recipient, uint256 amount) public onlyOwner {
        require(address(this).balance >= amount, "Insufficient contract balance");
        recipient.transfer(amount);  // Reverts on failure
    }

    /**
     * @notice SECURE: Protected ownership transfer
     * @dev Proper access control with two-step transfer
     */
    address public pendingOwner;

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Invalid address");
        pendingOwner = newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == pendingOwner, "Not pending owner");
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    /**
     * @notice SECURE: Delegatecall to whitelisted addresses only
     * @dev Controlled delegatecall with whitelist
     */
    mapping(address => bool) public trustedImplementations;

    function setTrustedImplementation(address impl, bool trusted) public onlyOwner {
        trustedImplementations[impl] = trusted;
    }

    function safeDelegate(address target, bytes memory data) public onlyOwner returns (bytes memory) {
        require(trustedImplementations[target], "Untrusted implementation");

        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");

        return result;
    }

    /**
     * @notice SECURE: Pull payment pattern
     * @dev Users withdraw their own funds instead of push payments
     */
    mapping(address => uint256) public pendingWithdrawals;

    function allowWithdrawal(address user, uint256 amount) public onlyOwner {
        pendingWithdrawals[user] += amount;
    }

    function withdrawFunds() public nonReentrant {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "No funds available");

        pendingWithdrawals[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Withdrawal failed");
    }

    /**
     * @notice SECURE: Batch operations with proper error handling
     * @dev Each operation is validated
     */
    function batchTransfer(address payable[] memory recipients, uint256[] memory amounts)
        public
        onlyOwner
        nonReentrant
    {
        require(recipients.length == amounts.length, "Length mismatch");

        uint256 totalAmount = 0;
        for (uint256 i = 0; i < amounts.length; i++) {
            totalAmount += amounts[i];
        }
        require(address(this).balance >= totalAmount, "Insufficient balance");

        for (uint256 i = 0; i < recipients.length; i++) {
            (bool success, ) = recipients[i].call{value: amounts[i]}("");
            require(success, "Transfer failed");
        }
    }

    /**
     * @notice SECURE: Emergency stop mechanism
     * @dev Can pause contract without destroying it
     */
    bool public paused;

    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }

    function pause() public onlyOwner {
        paused = true;
    }

    function unpause() public onlyOwner {
        paused = false;
    }

    /**
     * @notice SECURE: Safe deposit function
     */
    function deposit() public payable whenNotPaused {
        require(msg.value > 0, "Must send ETH");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice SECURE: View function for balance (no external calls)
     */
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }

    receive() external payable {
        deposit();
    }
}

/**
 * @title SecureUpgradeable
 * @notice Example of secure upgradeable proxy pattern
 */
contract SecureUpgradeable {
    address public admin;
    address public implementation;
    mapping(address => bool) public approvedImplementations;

    constructor(address _implementation) {
        admin = msg.sender;
        implementation = _implementation;
        approvedImplementations[_implementation] = true;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    /**
     * @notice SECURE: Upgrade with whitelist validation
     */
    function upgrade(address newImplementation) public onlyAdmin {
        require(approvedImplementations[newImplementation], "Implementation not approved");
        implementation = newImplementation;
    }

    function approveImplementation(address impl) public onlyAdmin {
        require(impl != address(0), "Invalid implementation");
        approvedImplementations[impl] = true;
    }

    receive() external payable {
        // Accept ETH transfers
    }

    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "No implementation set");

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
 * @title ReentrancyGuard
 * @notice Reusable reentrancy protection
 */
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;

    constructor() {
        _status = _NOT_ENTERED;
    }

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}
